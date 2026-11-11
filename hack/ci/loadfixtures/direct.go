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
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/identity/hack/ci/internal/fixturelib"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Direct mode writes the identity records straight to the Kubernetes API
// server, so a dataset of thousands of organizations builds in minutes. It
// bypasses identity's controllers and handlers: the status the organization
// controller would set is written here, and the handlers' validation does not
// run (the cluster's admission policies still do). Identity's controllers must
// be scaled to 0 first, or they race these writes. See test/load/README.md.

const (
	// directConcurrency bounds the parallel writes in direct mode.
	directConcurrency = 64
	// directQPS and directBurst raise the client's rate limit, which would
	// otherwise make a dataset of this size take hours.
	directQPS   = 400
	directBurst = 800

	// loadCreator is recorded as the creator of every record.
	loadCreator = "load-fixtures"

	// serviceAccountLifetime is how long the minted service account tokens
	// live, longer than any run.
	serviceAccountLifetime = 24 * time.Hour
)

// loadIDNamespace derives the names of the records direct mode writes, so a
// rerun of the same dataset converges on the same records. Users and
// organization users take the names the handlers give them (#604).
//
//nolint:gochecknoglobals // a constant derived once
var loadIDNamespace = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("loadfixtures.identity.unikorn-cloud.org"))

// directParams are what the records depend on besides the dataset's shape.
type directParams struct {
	// namespace is identity's namespace: organizations and global users live
	// in it.
	namespace string
	// issuer is recorded as the issuer of every group subject, as the users
	// handler records its own issuer.
	issuer string
	// adminRoleID and userRoleID are the roles of the first group and of the
	// others.
	adminRoleID, userRoleID string
}

// records is a whole dataset as Kubernetes objects, in memory.
type records struct {
	groupsPerOrg      int
	namespaces        []corev1.Namespace
	organizations     []unikornv1.Organization
	groups            []unikornv1.Group
	projects          []unikornv1.Project
	serviceAccounts   []unikornv1.ServiceAccount
	users             []unikornv1.User
	organizationUsers []unikornv1.OrganizationUser
}

func recordName(format string, args ...any) string {
	return util.GenerateDeterministicResourceID(loadIDNamespace, fmt.Sprintf(format, args...))
}

// meta builds object metadata with the labels and annotations the handlers
// set. organization is empty for records that live outside an organization.
func meta(namespace, name, display, organization string) metav1.ObjectMeta {
	builder := conversion.NewObjectMetadata(&coreopenapi.ResourceWriteMetadata{Name: display}, namespace)

	if organization != "" {
		builder = builder.WithOrganization(organization)
	}

	out := builder.Get()
	out.Name = name
	out.Annotations[constants.CreatorAnnotation] = loadCreator
	out.Annotations[constants.CreatorPrincipalAnnotation] = loadCreator

	return out
}

// member is a user's membership of one organization.
type member struct {
	subject         string
	organizationUID string
}

// buildRecords turns a dataset into objects. Service account tokens are left
// empty; mintTokens fills them in.
func buildRecords(s shape, us []user, p directParams) (records, error) {
	r := records{groupsPerOrg: max(s.groupsPerOrg, minGroups)}

	orgNames := make([]string, s.orgs)
	orgNamespaces := make([]string, s.orgs)

	for i := range s.orgs {
		orgNames[i] = recordName("organization/%d", i)
		orgNamespaces[i] = "organization-" + orgNames[i]
	}

	// Membership is settled up front, so each group is written once.
	members := make([][]member, s.orgs)

	for _, u := range us {
		userName := unikornv1.GlobalUserName(u.email)

		r.users = append(r.users, newGlobalUser(p, u.email, userName))

		for _, index := range u.orgs {
			orgUserName := users.OrganizationUserName(ids.OrganizationID(uuid.MustParse(orgNames[index])), userName)

			r.organizationUsers = append(r.organizationUsers, unikornv1.OrganizationUser{
				ObjectMeta: withLabel(meta(orgNamespaces[index], orgUserName, constants.UndefinedName, orgNames[index]), constants.UserLabel, userName),
				Spec:       unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
			})

			members[index] = append(members[index], member{subject: u.email, organizationUID: orgUserName})
		}
	}

	for i := range s.orgs {
		if err := r.organization(p, i, orgNames[i], orgNamespaces[i]); err != nil {
			return records{}, err
		}

		r.groupsAndRest(s, p, i, orgNames[i], orgNamespaces[i], members[i])
	}

	return r, nil
}

func withLabel(m metav1.ObjectMeta, key, value string) metav1.ObjectMeta {
	m.Labels[key] = value

	return m
}

func newGlobalUser(p directParams, email, name string) unikornv1.User {
	return unikornv1.User{
		ObjectMeta: withLabel(meta(p.namespace, name, constants.UndefinedName, ""), unikornv1.UserSubjectIDLabel, name),
		Spec: unikornv1.UserSpec{
			Subject: email,
			State:   unikornv1.UserStateActive,
		},
	}
}

// organization adds an organization as the organization controller leaves it:
// finalizer, namespace and conditions. Its namespace is added with it.
func (r *records) organization(p directParams, index int, name, namespace string) error {
	org := unikornv1.Organization{
		ObjectMeta: meta(p.namespace, name, fmt.Sprintf("load-org-%03d", index), ""),
	}

	controllerutil.AddFinalizer(&org, constants.Finalizer)

	org.Status.Namespace = namespace
	org.SetProvisioningCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonProvisioned, "provisioned")
	org.SetHealthCondition(corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "Healthy")

	labels, err := org.ResourceLabels()
	if err != nil {
		return err
	}

	r.organizations = append(r.organizations, org)
	r.namespaces = append(r.namespaces, corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: labels},
	})

	return nil
}

// groupsAndRest adds an organization's groups, projects and service account.
// The first group holds the administrator role and the service account; the
// others hold the user role and the members.
func (r *records) groupsAndRest(s shape, p directParams, index int, orgName, namespace string, members []member) {
	groupNames := make([]string, r.groupsPerOrg)
	for g := range groupNames {
		groupNames[g] = recordName("group/%d/%d", index, g)
	}

	saName := recordName("serviceaccount/%d", index)

	for g, name := range groupNames {
		group := unikornv1.Group{
			ObjectMeta: meta(namespace, name, fmt.Sprintf("load-group-%03d", g), orgName),
			Spec:       unikornv1.GroupSpec{RoleIDs: []string{p.userRoleID}},
		}

		switch {
		case g == 0:
			group.Spec.RoleIDs = []string{p.adminRoleID}
			group.Spec.ServiceAccountIDs = []string{saName}
		case g <= userGroups:
			for _, m := range members {
				group.Spec.UserIDs = append(group.Spec.UserIDs, m.organizationUID)
				group.Spec.Subjects = append(group.Spec.Subjects, unikornv1.GroupSubject{ID: m.subject, Email: m.subject, Issuer: p.issuer})
			}
		}

		r.groups = append(r.groups, group)
	}

	for proj := range s.projectsPerOrg {
		r.projects = append(r.projects, unikornv1.Project{
			ObjectMeta: meta(namespace, recordName("project/%d/%d", index, proj), fmt.Sprintf("load-project-%03d", proj), orgName),
			Spec: unikornv1.ProjectSpec{
				GroupIDs: []string{groupNames[proj%len(groupNames)], groupNames[(proj+1)%len(groupNames)]},
			},
		})
	}

	r.serviceAccounts = append(r.serviceAccounts, unikornv1.ServiceAccount{
		ObjectMeta: meta(namespace, saName, "load-sa", orgName),
	})
}

// orgs summarizes the records for the token step: one service account per
// organization, in organization order.
func (r *records) orgs() []org {
	out := make([]org, len(r.organizations))

	for i := range r.organizations {
		out[i] = org{id: r.organizations[i].Name, saToken: r.serviceAccounts[i].Spec.AccessToken}

		for _, group := range r.groups[i*r.groupsPerOrg : (i+1)*r.groupsPerOrg] {
			out[i].groupIDs = append(out[i].groupIDs, group.Name)
		}
	}

	return out
}

// tokenMinter issues a service account's access token.
type tokenMinter func(ctx context.Context, serviceAccountName, organizationID string) (string, time.Time, error)

// newTokenMinter issues tokens the way the service accounts handler does: with
// identity's own signing key, read from the cluster.
func newTokenMinter(k8s client.Client, namespace, baseURL string) (tokenMinter, error) {
	issuer := handlercommon.IssuerValue{}
	if err := issuer.Set(baseURL); err != nil {
		return nil, fmt.Errorf("invalid issuer %q: %w", baseURL, err)
	}

	authenticator, err := oauth2.New(&oauth2.Options{
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
		TokenCacheSize:       1,
	}, namespace, issuer, k8s, k8s, jose.NewJWTIssuer(k8s, k8s, namespace, &jose.Options{}), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	duration := serviceAccountLifetime

	return func(ctx context.Context, serviceAccountName, organizationID string) (string, time.Time, error) {
		tokens, err := authenticator.Issue(ctx, &oauth2.IssueInfo{
			Issuer:         issuer.URL,
			Audience:       issuer.Hostname,
			Subject:        serviceAccountName,
			Type:           oauth2.TokenTypeServiceAccount,
			ServiceAccount: &oauth2.ServiceAccountClaims{OrganizationID: organizationID},
			Duration:       &duration,
		})
		if err != nil {
			return "", time.Time{}, err
		}

		return tokens.AccessToken, tokens.Expiry, nil
	}, nil
}

// forEach runs fn for 0..n-1 with bounded concurrency and returns the first
// error.
func forEach(ctx context.Context, n int, fn func(ctx context.Context, i int) error) error {
	group, ctx := errgroup.WithContext(ctx)

	group.SetLimit(directConcurrency)

	for i := range n {
		group.Go(func() error { return fn(ctx, i) })
	}

	return group.Wait()
}

// mintTokens sets every service account's access token and expiry.
func mintTokens(ctx context.Context, r *records, mint tokenMinter) error {
	return forEach(ctx, len(r.serviceAccounts), func(ctx context.Context, i int) error {
		sa := &r.serviceAccounts[i]

		token, expiry, err := mint(ctx, sa.Name, sa.Labels[constants.OrganizationLabel])
		if err != nil {
			return fmt.Errorf("failed to mint a token for service account %s: %w", sa.Name, err)
		}

		sa.Spec.AccessToken = token
		sa.Spec.Expiry = &metav1.Time{Time: expiry}

		return nil
	})
}

// createAll creates every item. A record that already exists is left alone, so
// a rerun of the same dataset converges. Create fills in the items' versions, so
// records are written once.
func createAll[T any, PT interface {
	*T
	client.Object
}](ctx context.Context, k8s client.Client, what string, items []T) error {
	fixturelib.Logf("Writing %d %s", len(items), what)

	return forEach(ctx, len(items), func(ctx context.Context, i int) error {
		if err := k8s.Create(ctx, PT(&items[i])); client.IgnoreAlreadyExists(err) != nil {
			return fmt.Errorf("failed to create %s: %w", client.ObjectKeyFromObject(PT(&items[i])), err)
		}

		return nil
	})
}

// setOrganizationStatus writes the status the organization controller would,
// re-reading the organization when something else has written it since.
func setOrganizationStatus(ctx context.Context, k8s client.Client, want *unikornv1.Organization) error {
	key := types.NamespacedName{Namespace: want.Namespace, Name: want.Name}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &unikornv1.Organization{}

		if err := k8s.Get(ctx, key, current); err != nil {
			return err
		}

		current.Status = want.Status

		return k8s.Status().Update(ctx, current)
	})
}

// upsertServiceAccount creates a service account, or on a rerun replaces the
// token of the one that exists: tokens.json must hold the token the cluster
// holds. Another writer's conflicting update is retried.
func upsertServiceAccount(ctx context.Context, k8s client.Client, want *unikornv1.ServiceAccount) error {
	err := k8s.Create(ctx, want)
	if !kerrors.IsAlreadyExists(err) {
		return err
	}

	key := client.ObjectKeyFromObject(want)

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &unikornv1.ServiceAccount{}

		if err := k8s.Get(ctx, key, current); err != nil {
			return err
		}

		current.Spec.AccessToken = want.Spec.AccessToken
		current.Spec.Expiry = want.Spec.Expiry

		return k8s.Update(ctx, current)
	})
}

// apply writes the records. Organizations come after their namespaces and
// before everything inside them.
func apply(ctx context.Context, k8s client.Client, r *records) error {
	if err := createAll(ctx, k8s, "namespaces", r.namespaces); err != nil {
		return err
	}

	// Create overwrites each item with the server's copy, which has no status.
	statuses := make([]unikornv1.OrganizationStatus, len(r.organizations))
	for i := range r.organizations {
		statuses[i] = r.organizations[i].Status
	}

	if err := createAll(ctx, k8s, "organizations", r.organizations); err != nil {
		return err
	}

	err := forEach(ctx, len(r.organizations), func(ctx context.Context, i int) error {
		r.organizations[i].Status = statuses[i]

		return setOrganizationStatus(ctx, k8s, &r.organizations[i])
	})
	if err != nil {
		return err
	}

	for _, write := range []func() error{
		func() error { return createAll(ctx, k8s, "groups", r.groups) },
		func() error { return createAll(ctx, k8s, "projects", r.projects) },
		func() error {
			fixturelib.Logf("Writing %d service accounts", len(r.serviceAccounts))

			return forEach(ctx, len(r.serviceAccounts), func(ctx context.Context, i int) error {
				return upsertServiceAccount(ctx, k8s, &r.serviceAccounts[i])
			})
		},
		func() error { return createAll(ctx, k8s, "users", r.users) },
		func() error { return createAll(ctx, k8s, "organization users", r.organizationUsers) },
	} {
		if err := write(); err != nil {
			return err
		}
	}

	return nil
}
