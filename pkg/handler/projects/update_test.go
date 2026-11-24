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

package projects_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	groupA        = "6ba7b810-9dad-11d1-80b4-00c04fd430a1"
	groupB        = "6ba7b810-9dad-11d1-80b4-00c04fd430a2"
	unlinkedGroup = "6ba7b810-9dad-11d1-80b4-00c04fd430a3"

	foreignGroup      = "6ba7b810-9dad-11d1-80b4-00c04fd430b1"
	missingGroup      = "6ba7b810-9dad-11d1-80b4-00c04fd430ff"
	otherMissingGroup = "6ba7b810-9dad-11d1-80b4-00c04fd430fe"

	otherOrganizationID        = "6ba7b810-9dad-4372-a567-0e02b2c3d499"
	otherOrganizationNamespace = "baz"

	projectsEndpoint = "identity:projects"
)

func setupUpdateFixtures(t *testing.T, stored []string) client.Client {
	t.Helper()

	cli := setupFixtures(t)

	groups := []struct {
		namespace string
		name      string
	}{
		{organizationNamespace, groupA},
		{organizationNamespace, groupB},
		{organizationNamespace, unlinkedGroup},
		{otherOrganizationNamespace, foreignGroup},
	}

	for _, group := range groups {
		require.NoError(t, cli.Create(t.Context(), &identityv1.Group{
			ObjectMeta: metav1.ObjectMeta{Namespace: group.namespace, Name: group.name},
		}))
	}

	project := getProject(t, cli)
	project.Labels = map[string]string{constants.NameLabel: "before"}
	project.Annotations = map[string]string{constants.DescriptionAnnotation: "before"}
	project.Spec.GroupIDs = stored

	require.NoError(t, cli.Update(t.Context(), project))

	return cli
}

func projectEndpoints(operations ...openapi.AclOperation) openapi.AclEndpoints {
	return openapi.AclEndpoints{{Name: projectsEndpoint, Operations: operations}}
}

func projectOnlyACL() *openapi.Acl {
	return &openapi.Acl{
		Organizations: &openapi.AclOrganizationList{{
			Id: organizationID,
			Projects: &openapi.AclProjectList{{
				Id:        projectID,
				Endpoints: projectEndpoints(openapi.Update),
			}},
		}},
	}
}

func organizationACL(operations ...openapi.AclOperation) *openapi.Acl {
	acl := projectOnlyACL()
	endpoints := projectEndpoints(operations...)
	(*acl.Organizations)[0].Endpoints = &endpoints

	return acl
}

func otherOrganizationACL() *openapi.Acl {
	acl := projectOnlyACL()
	endpoints := projectEndpoints(openapi.Update)
	*acl.Organizations = append(*acl.Organizations, openapi.AclOrganization{Id: otherOrganizationID, Endpoints: &endpoints})

	return acl
}

func globalACL() *openapi.Acl {
	endpoints := projectEndpoints(openapi.Update)

	return &openapi.Acl{Global: &endpoints}
}

func callerContext(t *testing.T, acl *openapi.Acl) context.Context {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: "test-subject"},
	})

	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "test-principal"})

	return rbac.NewContext(ctx, acl)
}

func updateRequest(groups []string) *openapi.ProjectWrite {
	return &openapi.ProjectWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name:        "after",
			Description: ptr.To("after description"),
			Tags:        &coreopenapi.TagList{{Name: "owner", Value: "after"}},
		},
		Spec: openapi.ProjectSpec{GroupIDs: groups},
	}
}

func readProject(t *testing.T, cli client.Client, id string) *openapi.ProjectRead {
	t.Helper()

	read, err := projects.New(cli, namespace).Get(t.Context(), ids.MustParseOrganizationID(organizationID), id)
	require.NoError(t, err)

	return read
}

func requireMetadataUpdated(t *testing.T, read *openapi.ProjectRead) {
	t.Helper()

	require.Equal(t, "after", read.Metadata.Name)
	require.Equal(t, ptr.To("after description"), read.Metadata.Description)
	require.Equal(t, &coreopenapi.TagList{{Name: "owner", Value: "after"}}, read.Metadata.Tags)
}

type outcome int

const (
	succeeds outcome = iota
	forbidden
	invalid
)

func TestUpdateGroupLinks(t *testing.T) {
	t.Parallel()

	projectOnly := projectOnlyACL()

	tests := []struct {
		name      string
		acl       *openapi.Acl
		stored    []string
		requested []string
		want      outcome
	}{
		{"project-only, same links", projectOnly, []string{groupA, groupB}, []string{groupA, groupB}, succeeds},
		{"project-only, reordered links", projectOnly, []string{groupA, groupB}, []string{groupB, groupA}, succeeds},
		{"project-only, stored duplicates collapsed", projectOnly, []string{groupA, groupA, groupB}, []string{groupB, groupA}, succeeds},
		{"project-only, no links stored, nil list", projectOnly, nil, nil, succeeds},
		{"project-only, no links stored, empty list", projectOnly, nil, []string{}, succeeds},
		{"project-only, empty links stored, nil list", projectOnly, []string{}, nil, succeeds},

		{"project-only, add a link", projectOnly, []string{groupA, groupB}, []string{groupA, groupB, unlinkedGroup}, forbidden},
		{"project-only, add the first link", projectOnly, nil, []string{groupA}, forbidden},
		{"project-only, remove a link", projectOnly, []string{groupA, groupB}, []string{groupA}, forbidden},
		{"project-only, replace a link", projectOnly, []string{groupA, groupB}, []string{groupA, unlinkedGroup}, forbidden},
		{"project-only, clear with an empty list", projectOnly, []string{groupA, groupB}, []string{}, forbidden},
		{"project-only, clear with a nil list", projectOnly, []string{groupA, groupB}, nil, forbidden},

		{"project-only, add an unknown group", projectOnly, []string{groupA}, []string{groupA, missingGroup}, forbidden},
		{"project-only, add a group of another organization", projectOnly, []string{groupA}, []string{groupA, foreignGroup}, forbidden},

		{"organization, add a link", organizationACL(openapi.Update), []string{groupA}, []string{groupA, groupB}, succeeds},
		{"organization, remove a link", organizationACL(openapi.Update), []string{groupA, groupB}, []string{groupA}, succeeds},
		{"organization, clear all links", organizationACL(openapi.Update), []string{groupA, groupB}, nil, succeeds},
		{"organization, add an unknown group", organizationACL(openapi.Update), []string{groupA}, []string{groupA, missingGroup}, invalid},
		{"organization, add a group of another organization", organizationACL(openapi.Update), []string{groupA}, []string{groupA, foreignGroup}, invalid},
		{"global, add a link", globalACL(), []string{groupA}, []string{groupA, groupB}, succeeds},
		{"global, remove a link", globalACL(), []string{groupA, groupB}, []string{groupA}, succeeds},
		{"global, clear all links", globalACL(), []string{groupA, groupB}, nil, succeeds},
		{"global, add an unknown group", globalACL(), []string{groupA}, []string{groupA, missingGroup}, invalid},
		{"global, add a group of another organization", globalACL(), []string{groupA}, []string{groupA, foreignGroup}, invalid},

		{"organization read only, add a link", organizationACL(openapi.Read), []string{groupA}, []string{groupA, groupB}, forbidden},
		{"update in another organization, add a link", otherOrganizationACL(), []string{groupA}, []string{groupA, groupB}, forbidden},

		{"project-only, unchanged dangling link", projectOnly, []string{groupA, missingGroup}, []string{groupA, missingGroup}, invalid},
		{"project-only, drop a dangling link", projectOnly, []string{groupA, missingGroup}, []string{groupA}, succeeds},
		{"project-only, drop the only dangling link", projectOnly, []string{missingGroup}, []string{}, succeeds},
		{"project-only, drop a dangling and a live link", projectOnly, []string{groupA, groupB, missingGroup}, []string{groupA}, forbidden},
		{"project-only, replace a dangling link with an unknown group", projectOnly, []string{groupA, missingGroup}, []string{groupA, otherMissingGroup}, forbidden},
		{"organization, drop a dangling link", organizationACL(openapi.Update), []string{groupA, missingGroup}, []string{groupA}, succeeds},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cli := setupUpdateFixtures(t, test.stored)
			before := getProject(t, cli)

			err := projects.New(cli, namespace).Update(callerContext(t, test.acl), ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID), updateRequest(test.requested))
			after := getProject(t, cli)

			switch test.want {
			case succeeds:
				require.NoError(t, err)

				read := readProject(t, cli, projectID)
				require.ElementsMatch(t, test.requested, read.Spec.GroupIDs)
				require.NotNil(t, read.Spec.GroupIDs, "an empty link list must read back as [], not null")
				requireMetadataUpdated(t, read)
			case forbidden:
				require.True(t, errors.IsForbidden(err), "want 403, got %v", err)
				require.Equal(t, before, after)

				for _, id := range test.requested {
					require.NotContains(t, err.Error(), id, "the refusal must not repeat the requested group IDs")
				}
			case invalid:
				require.True(t, errors.IsBadRequest(err), "want 400, got %v", err)
				require.Equal(t, before, after)
			}
		})
	}
}

func TestUpdateRecordsGuardOnlyWhenLinksChange(t *testing.T) {
	t.Parallel()

	update := func(t *testing.T, stored, requested []string) []authz.Decision {
		t.Helper()

		recorder := &authz.Recorder{}
		ctx := authz.NewContext(callerContext(t, organizationACL(openapi.Update)), recorder)
		cli := setupUpdateFixtures(t, stored)

		require.NoError(t, projects.New(cli, namespace).Update(ctx, ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID), updateRequest(requested)))

		return recorder.Decisions()
	}

	require.Empty(t, update(t, []string{groupA, groupB}, []string{groupB, groupA}))
	require.Empty(t, update(t, []string{groupA, groupB, missingGroup}, []string{groupA, groupB}), "dropping only a dangling link needs no guard decision")

	decisions := update(t, []string{groupA, groupB}, []string{groupA})
	require.Len(t, decisions, 1)

	decision := decisions[0]
	require.Equal(t, projectsEndpoint, decision.Endpoint)
	require.Equal(t, openapi.Update, decision.Operation.Access)
	require.Equal(t, "link-groups", decision.Operation.Action)
	require.Equal(t, authz.Subordinate, decision.Kind)
	require.Equal(t, uuid.MustParse(projectID), decision.ObjectID)
	require.Equal(t, ids.MustParseOrganizationID(organizationID), decision.Scope.OrganizationID)
	require.True(t, decision.Allowed)
}

func TestUpdateRefusalLeavesNoDecision(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	ctx := authz.NewContext(callerContext(t, projectOnlyACL()), recorder)
	cli := setupUpdateFixtures(t, []string{groupA})

	err := projects.New(cli, namespace).Update(ctx, ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID), updateRequest(nil))
	require.True(t, errors.IsForbidden(err))
	require.Empty(t, recorder.Decisions())
}

// Only a NotFound answer marks a removed link as dangling. Any other lookup error must stop the
// update, because the group can still exist.
func TestUpdateFailsWhenRemovedGroupLookupFails(t *testing.T) {
	t.Parallel()

	cli := setupUpdateFixtures(t, []string{groupA, missingGroup})
	before := getProject(t, cli)

	watcher, ok := cli.(client.WithWatch)
	require.True(t, ok)

	failing := interceptor.NewClient(watcher, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, isGroup := obj.(*identityv1.Group); isGroup && key.Name == missingGroup {
				return kerrors.NewServiceUnavailable("group lookup failed")
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})

	err := projects.New(failing, namespace).Update(callerContext(t, projectOnlyACL()), ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID), updateRequest([]string{groupA}))
	require.Error(t, err)
	require.False(t, errors.IsForbidden(err), "a failed lookup is not a refusal, got %v", err)
	require.False(t, errors.IsBadRequest(err), "a failed lookup is not a bad request, got %v", err)
	require.Equal(t, before, getProject(t, cli))
}

func TestUpdateKeepsPause(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		acl       *openapi.Acl
		requested []string
	}{
		{"project-only, same links", projectOnlyACL(), []string{groupA}},
		{"organization, add a link", organizationACL(openapi.Update), []string{groupA, groupB}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cli := setupUpdateFixtures(t, []string{groupA})

			paused := getProject(t, cli)
			paused.Spec.Pause = true
			require.NoError(t, cli.Update(t.Context(), paused))

			require.NoError(t, projects.New(cli, namespace).Update(callerContext(t, test.acl), ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID), updateRequest(test.requested)))

			after := getProject(t, cli)
			require.True(t, after.Spec.Pause, "an update must keep the pause flag")
			require.Equal(t, test.requested, after.Spec.GroupIDs)
			requireMetadataUpdated(t, readProject(t, cli, projectID))
		})
	}
}

// The guard judges the links it read. A caller without link permission passes the guard when the
// set is unchanged. Only the optimistic lock then stops that write from replacing a link that
// another caller added in between.
func TestUpdateConflictKeepsConcurrentChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		acl       *openapi.Acl
		stored    []string
		requested []string
	}{
		{"organization, replace a link", organizationACL(openapi.Update), []string{groupA}, []string{groupB}},
		{"project-only, same links reordered", projectOnlyACL(), []string{groupA, groupB}, []string{groupB, groupA}},
		{"project-only, same links stored in another order", projectOnlyACL(), []string{groupB, groupA}, []string{groupA, groupB}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cli := setupUpdateFixtures(t, test.stored)
			concurrentLinks := slices.Concat(test.stored, []string{unlinkedGroup})

			watcher, ok := cli.(client.WithWatch)
			require.True(t, ok)

			racing := interceptor.NewClient(watcher, interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					concurrent := &identityv1.Project{}
					require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: organizationNamespace, Name: projectID}, concurrent))

					concurrent.Spec.GroupIDs = concurrentLinks
					require.NoError(t, cli.Update(ctx, concurrent))

					return c.Patch(ctx, obj, patch, opts...)
				},
			})

			err := projects.New(racing, namespace).Update(callerContext(t, test.acl), ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID), updateRequest(test.requested))
			require.True(t, errors.IsConflict(err), "want 409, got %v", err)
			require.ElementsMatch(t, concurrentLinks, getProject(t, cli).Spec.GroupIDs)
		})
	}
}

func TestUpdateStoresGroupLinksOnceAndSorted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		acl       *openapi.Acl
		stored    []string
		requested []string
	}{
		{"organization, repeated and unordered links", organizationACL(openapi.Update), []string{groupA}, []string{groupB, groupA, groupB, groupA}},
		{"project-only, same links repeated", projectOnlyACL(), []string{groupA, groupB}, []string{groupA, groupA, groupB, groupB}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cli := setupUpdateFixtures(t, test.stored)

			require.NoError(t, projects.New(cli, namespace).Update(callerContext(t, test.acl), ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID), updateRequest(test.requested)))
			require.Equal(t, []string{groupA, groupB}, getProject(t, cli).Spec.GroupIDs)
		})
	}
}

func TestCreateStoresGroupLinksOnceAndSorted(t *testing.T) {
	t.Parallel()

	cli := setupUpdateFixtures(t, nil)

	created, err := projects.New(cli, namespace).Create(callerContext(t, organizationACL(openapi.Create)), ids.MustParseOrganizationID(organizationID), updateRequest([]string{groupB, groupA, groupB}))
	require.NoError(t, err)

	require.Equal(t, []string{groupA, groupB}, created.Spec.GroupIDs)
	require.Equal(t, []string{groupA, groupB}, readProject(t, cli, created.Metadata.Id).Spec.GroupIDs)
}
