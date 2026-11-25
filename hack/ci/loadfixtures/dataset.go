/*
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/unikorn-cloud/identity/hack/ci/internal/fixturelib"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// userClass is a group of users who each belong to the same number of
// organizations.
type userClass struct {
	memberships int
	count       int
}

// shape sizes a dataset. Users are split by how many organizations each
// belongs to, so a cost that grows with membership shows up.
type shape struct {
	orgs           int
	groupsPerOrg   int
	projectsPerOrg int
	users          []userClass
	// tokens is the number of distinct Auth0 tokens minted.
	tokens int
}

// shapeFor returns the named dataset. Medium and web have about three
// projects, two groups and one service account per organization, and as many
// users as organizations: most in one to three organizations, a few in 20. The
// tokens are one per user, so every user and every membership is exercised.
// Medium and web are meant for direct mode (see direct.go).
func shapeFor(name string) (shape, bool) {
	switch name {
	case "small":
		return shape{
			orgs: 20, groupsPerOrg: 4, projectsPerOrg: 3, tokens: 600,
			users: []userClass{{1, 10}, {5, 6}, {20, 3}},
		}, true
	case "medium":
		return shape{
			orgs: 2000, groupsPerOrg: 2, projectsPerOrg: 3, tokens: 2000,
			users: []userClass{{1, 900}, {2, 600}, {3, 400}, {20, 100}},
		}, true
	case "web":
		return shape{
			orgs: 20000, groupsPerOrg: 2, projectsPerOrg: 3, tokens: 20000,
			users: []userClass{{1, 9000}, {2, 6000}, {3, 4000}, {20, 1000}},
		}, true
	}

	return shape{}, false
}

const (
	// concurrency bounds the parallel API calls this program issues.
	concurrency = 16
	// userGroups is how many of an organization's groups each user joins.
	userGroups = 3
	// minGroups keeps the administrator group and the user group.
	minGroups = 2
)

type org struct {
	id       string
	groupIDs []string
	saToken  string
}

type user struct {
	email string
	// orgs indexes into the created organizations.
	orgs []int
}

// builder creates a dataset through the identity API.
type builder struct {
	ac        *openapi.ClientWithResponses
	k8s       client.Client
	namespace string
}

// createOrgs creates the organizations with bounded concurrency.
func (b *builder) createOrgs(ctx context.Context, s shape) []org {
	orgs := make([]org, s.orgs)

	var group errgroup.Group

	group.SetLimit(concurrency)

	for i := range s.orgs {
		group.Go(func() error {
			orgs[i] = b.createOrg(ctx, i, s)

			return nil
		})
	}

	// The fixture helpers exit the process on failure, so nothing is returned.
	if err := group.Wait(); err != nil {
		fixturelib.Fatalf("failed to create organizations: %v", err)
	}

	return orgs
}

func (b *builder) createOrg(ctx context.Context, i int, s shape) org {
	id := fixturelib.CreateOrganization(ctx, b.ac, b.k8s, b.namespace, fmt.Sprintf("load-org-%03d", i))

	adminRoleID, userRoleID, _ := fixturelib.ResolveRoles(ctx, b.ac, id)

	groupIDs := make([]string, 0, s.groupsPerOrg)

	for g := range max(s.groupsPerOrg, minGroups) {
		roleID := userRoleID
		if g == 0 {
			roleID = adminRoleID
		}

		groupIDs = append(groupIDs, fixturelib.CreateGroup(ctx, b.ac, id, fmt.Sprintf("load-group-%03d", g), []string{roleID}))
	}

	for p := range s.projectsPerOrg {
		members := []string{groupIDs[p%len(groupIDs)], groupIDs[(p+1)%len(groupIDs)]}
		fixturelib.CreateProject(ctx, b.ac, id, fmt.Sprintf("load-project-%03d", p), members)
	}

	_, token := fixturelib.CreateServiceAccount(ctx, b.ac, id, "load-sa", []string{groupIDs[0]})

	return org{id: id, groupIDs: groupIDs, saToken: token}
}

// plan spreads users across organizations: user k of a class with n
// memberships belongs to n consecutive organizations from a rotating start.
func plan(s shape) []user {
	var users []user

	for _, class := range s.users {
		for k := range class.count {
			u := user{email: fmt.Sprintf("load-user-%d-%03d@example.invalid", class.memberships, k)}

			for j := range class.memberships {
				u.orgs = append(u.orgs, (k*class.memberships+j)%s.orgs)
			}

			users = append(users, u)
		}
	}

	return users
}

// createUser adds the user to each of its organizations, in the user group and
// a few more. One user's memberships are created in turn: they share a
// global user record.
func (b *builder) createUser(ctx context.Context, orgs []org, u user) {
	for _, index := range u.orgs {
		groups := orgs[index].groupIDs[1:]
		fixturelib.CreateUser(ctx, b.ac, orgs[index].id, u.email, groups[:min(userGroups, len(groups))])
	}
}
