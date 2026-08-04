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

package users_test

import (
	"context"
	goerrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	testNamespace = "test-namespace"
	testOrgID     = "00000000-0000-4000-8000-000000000001"
	testOrgNS     = "test-org-ns"

	testIssuerURL  = "https://identity.unikorn-cloud.org"
	testIssuerHost = "identity.unikorn-cloud.org"

	userAliceSubject = "alice@example.com"
	userAliceID      = "user-alice"
	orgUserAliceID   = "orguser-alice"
	orgUserAliceID2  = "orguser-alice-2"
	groupAlphaID     = "group-alpha"
	groupBetaID      = "group-beta"

	userBobSubject = "bob@example.com"
	userBobID      = "user-bob"
	orgUserBobID   = "orguser-bob"

	radarRoleID   = "radar-id"
	radarRoleName = "radar"
)

type userTestFixture struct {
	client      client.Client
	usersClient *users.Client
}

var (
	errListOrganizationUsers  = goerrors.New("list organization users")
	errCreateOrganizationUser = goerrors.New("create organization user")
	errUnexpectedGroupReload  = goerrors.New("unexpected group reload")
)

func newContext(t *testing.T) context.Context {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: "test-subject",
		},
	})

	ctx = principal.NewContext(ctx, &principal.Principal{
		Actor:          "test-principal",
		OrganizationID: testOrgID,
	})

	return ctx
}

func newUserTestFixture(t *testing.T) *userTestFixture {
	t.Helper()

	return newUserTestFixtureWithObjects(t, nil, interceptor.Funcs{})
}

func newUserTestFixtureWithObjects(t *testing.T, objects []client.Object, interceptors interceptor.Funcs) *userTestFixture {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testOrgID,
		},
		Status: unikornv1.OrganizationStatus{
			Namespace: testOrgNS,
		},
	}

	objects = append([]client.Object{organization}, objects...)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(interceptors).Build()
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}

	return &userTestFixture{
		client:      c,
		usersClient: users.New(c, testNamespace, issuer),
	}
}

func newGlobalUser(name, subject string) *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      name,
		},
		Spec: unikornv1.UserSpec{
			Subject: subject,
			State:   unikornv1.UserStateActive,
		},
	}
}

func newOrganizationUser(name, userID string) *unikornv1.OrganizationUser {
	return &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      name,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
				constants.UserLabel:         userID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}
}

func createGroup(ctx context.Context, t *testing.T, cli client.Client, name string) {
	t.Helper()

	group := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      name,
		},
	}

	require.NoError(t, cli.Create(ctx, group))
}

func getGroup(ctx context.Context, t *testing.T, cli client.Client, name string) *unikornv1.Group {
	t.Helper()

	group := &unikornv1.Group{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: name}, group))

	return group
}

func assertCreateUserError(t *testing.T, fixture *userTestFixture, target error) {
	t.Helper()

	ctx := newContext(t)

	request := &openapi.UserWrite{
		Spec: openapi.UserSpec{
			Subject: userAliceSubject,
			State:   openapi.Active,
		},
	}

	_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)

	require.Error(t, err)
	require.ErrorIs(t, err, target)
	assert.Contains(t, err.Error(), "failed to create organization user")
}

func TestClient_Create(t *testing.T) {
	t.Parallel()

	t.Run("reuses existing organization user for same subject", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixture(t)
		ctx := newContext(t)

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject: userAliceSubject,
				State:   openapi.Active,
			},
		}

		first, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
		require.NoError(t, err)

		second, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
		require.NoError(t, err)

		assert.Equal(t, first.Metadata.Id, second.Metadata.Id)
		assert.Equal(t, first.Metadata.Name, second.Metadata.Name)
		assert.Equal(t, testOrgID, second.Metadata.OrganizationId)
		assert.Equal(t, userAliceSubject, second.Spec.Subject)
		assert.Equal(t, first.Spec.State, second.Spec.State)

		globalUsers := &unikornv1.UserList{}
		require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
		require.Len(t, globalUsers.Items, 1)

		organizationUsers := &unikornv1.OrganizationUserList{}
		require.NoError(t, fixture.client.List(ctx, organizationUsers, &client.ListOptions{Namespace: testOrgNS}))
		require.Len(t, organizationUsers.Items, 1)

		assert.Equal(t, first.Metadata.Id, organizationUsers.Items[0].Name)
		assert.Equal(t, testOrgID, organizationUsers.Items[0].Labels[constants.OrganizationLabel])
		assert.Equal(t, globalUsers.Items[0].Name, organizationUsers.Items[0].Labels[constants.UserLabel])
	})

	t.Run("reconciles groups when reusing existing organization user", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixture(t)
		ctx := newContext(t)

		createGroup(ctx, t, fixture.client, groupAlphaID)
		createGroup(ctx, t, fixture.client, groupBetaID)

		firstRequest := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Suspended,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		first, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), firstRequest)
		require.NoError(t, err)

		secondRequest := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupBetaID},
			},
		}

		second, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), secondRequest)
		require.NoError(t, err)

		assert.Equal(t, first.Metadata.Id, second.Metadata.Id)
		assert.Equal(t, testOrgID, second.Metadata.OrganizationId)
		assert.Equal(t, userAliceSubject, second.Spec.Subject)
		assert.Equal(t, openapi.Suspended, second.Spec.State)

		globalUsers := &unikornv1.UserList{}
		require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
		require.Len(t, globalUsers.Items, 1)

		organizationUsers := &unikornv1.OrganizationUserList{}
		require.NoError(t, fixture.client.List(ctx, organizationUsers, &client.ListOptions{Namespace: testOrgNS}))
		require.Len(t, organizationUsers.Items, 1)
		assert.Equal(t, first.Metadata.Id, organizationUsers.Items[0].Name)
		assert.Equal(t, testOrgID, organizationUsers.Items[0].Labels[constants.OrganizationLabel])
		assert.Equal(t, globalUsers.Items[0].Name, organizationUsers.Items[0].Labels[constants.UserLabel])

		subject := unikornv1.GroupSubject{
			ID:     userAliceSubject,
			Email:  userAliceSubject,
			Issuer: testIssuerURL,
		}

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.NotContains(t, alphaGroup.Spec.UserIDs, first.Metadata.Id)
		assert.NotContains(t, alphaGroup.Spec.Subjects, subject)

		betaGroup := getGroup(ctx, t, fixture.client, groupBetaID)
		assert.Contains(t, betaGroup.Spec.UserIDs, first.Metadata.Id)
		assert.Contains(t, betaGroup.Spec.Subjects, subject)
	})

	t.Run("returns consistency error for duplicate organization users", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			newOrganizationUser(orgUserAliceID2, userAliceID),
		}, interceptor.Funcs{})
		ctx := newContext(t)

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject: userAliceSubject,
				State:   openapi.Active,
			},
		}

		_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)

		require.Error(t, err)
		require.ErrorIs(t, err, coreerrors.ErrConsistency)
		assert.Contains(t, err.Error(), "multiple organization users reference global user")
	})

	t.Run("returns list error when organization user lookup fails", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
		}, interceptor.Funcs{
			List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*unikornv1.OrganizationUserList); ok {
					return errListOrganizationUsers
				}

				return inner.List(ctx, list, opts...)
			},
		})

		assertCreateUserError(t, fixture, errListOrganizationUsers)
	})

	t.Run("returns create error when organization user create fails", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
		}, interceptor.Funcs{
			Create: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*unikornv1.OrganizationUser); ok {
					return errCreateOrganizationUser
				}

				return inner.Create(ctx, obj, opts...)
			},
		})

		assertCreateUserError(t, fixture, errCreateOrganizationUser)
	})

	t.Run("creates user when the new global user is not yet visible to cached reads", func(t *testing.T) {
		t.Parallel()

		// Simulate informer cache lag: the global user is written to the API server
		// during creation, but a subsequent cached Get does not observe it yet.
		// Creating a user must not depend on reading back a user it just created,
		// otherwise first-time sign-ups fail intermittently with NotFound.
		fixture := newUserTestFixtureWithObjects(t, nil, interceptor.Funcs{
			Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*unikornv1.User); ok {
					return kerrors.NewNotFound(unikornv1.Resource("users"), key.Name)
				}

				return inner.Get(ctx, key, obj, opts...)
			},
		})
		ctx := newContext(t)

		createGroup(ctx, t, fixture.client, groupAlphaID)

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		result, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
		require.NoError(t, err)
		require.NotNil(t, result)

		globalUsers := &unikornv1.UserList{}
		require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
		require.Len(t, globalUsers.Items, 1)

		organizationUsers := &unikornv1.OrganizationUserList{}
		require.NoError(t, fixture.client.List(ctx, organizationUsers, &client.ListOptions{Namespace: testOrgNS}))
		require.Len(t, organizationUsers.Items, 1)

		// the requested group membership was still applied
		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Contains(t, alphaGroup.Spec.UserIDs, result.Metadata.Id)
	})
}

func TestClient_Update(t *testing.T) {
	t.Parallel()

	t.Run("reports group membership without a post-write cache reload", func(t *testing.T) {
		t.Parallel()

		// After patching group membership, the response must be built from the
		// in-memory group state, not re-listed through the cached client: a cached
		// reload can lag the writes just made and return stale GroupIDs. Enforce it
		// by failing any second group List — the update must still succeed and
		// report the membership it just applied.
		var groupListCalls int

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
		}, interceptor.Funcs{
			List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*unikornv1.GroupList); ok {
					groupListCalls++

					if groupListCalls > 1 {
						return errUnexpectedGroupReload
					}
				}

				return inner.List(ctx, list, opts...)
			},
		})
		ctx := newContext(t)

		createGroup(ctx, t, fixture.client, groupAlphaID)

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		result, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, openapi.GroupIDs{groupAlphaID}, result.Spec.GroupIDs)
	})
}

// radarRole builds a role scoped to an endpoint no built-in role holds, so only a caller
// whose ACL is extended to cover it can grant the role.
func radarRole() *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      radarRoleID,
			Labels:    map[string]string{constants.NameLabel: radarRoleName},
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}
}

// newRadarGroup builds a group already carrying the ungrantable role, standing in for one
// seeded by a third-party service or a more privileged admin.
func newRadarGroup(name string, userIDs []string, subjects []unikornv1.GroupSubject) *unikornv1.Group {
	return &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      name,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs:  []string{radarRoleID},
			UserIDs:  userIDs,
			Subjects: subjects,
		},
	}
}

// newPlainGroup builds a group carrying no roles, so joining it is never a grant.
func newPlainGroup(name string) *unikornv1.Group {
	return &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      name,
		},
	}
}

// aclContext layers an ACL granting only the given organization-scoped endpoints on top of
// newContext's authorization and principal info.
func aclContext(t *testing.T, endpoints openapi.AclEndpoints) context.Context {
	t.Helper()

	organizations := openapi.AclOrganizationList{{Id: testOrgID, Endpoints: &endpoints}}

	return rbac.NewContext(newContext(t), &openapi.Acl{Organizations: &organizations})
}

func aliceSubject() unikornv1.GroupSubject {
	return unikornv1.GroupSubject{
		ID:     userAliceSubject,
		Email:  userAliceSubject,
		Issuer: testIssuerURL,
	}
}

// TestClient_GroupMembershipGrantGate covers the grant hidden inside a user write: adding a
// user to a group hands them every role the group carries, so it is refused unless the
// caller could grant those roles.  Removals confer nothing and stay open.
func TestClient_GroupMembershipGrantGate(t *testing.T) {
	t.Parallel()

	t.Run("refuses adding a user to a group whose role the caller cannot grant", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, nil, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.Error(t, err)
		require.True(t, errors.IsForbidden(err))
		assert.Contains(t, err.Error(), radarRoleName)

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Empty(t, alphaGroup.Spec.UserIDs)
		assert.Empty(t, alphaGroup.Spec.Subjects)
	})

	t.Run("allows adding a user when the caller holds the group's role", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, nil, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
			{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		result, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.NoError(t, err)
		assert.Equal(t, openapi.GroupIDs{groupAlphaID}, result.Spec.GroupIDs)

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Contains(t, alphaGroup.Spec.UserIDs, orgUserAliceID)
	})

	t.Run("leaves every group untouched when one addition in the write is refused", func(t *testing.T) {
		t.Parallel()

		// group-alpha carries no roles and would be allowed on its own, and
		// it sorts first so the reconciliation reaches it before the refusal.
		// A membership write is one request: if any addition in it is a grant
		// the caller cannot make, none of them may land.
		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newPlainGroup(groupAlphaID),
			newRadarGroup(groupBetaID, nil, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID, groupBetaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.Error(t, err)
		require.True(t, errors.IsForbidden(err))
		assert.Contains(t, err.Error(), radarRoleName)

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Empty(t, alphaGroup.Spec.UserIDs,
			"the permitted addition must not land when another in the same write is refused")
		assert.Empty(t, alphaGroup.Spec.Subjects)

		betaGroup := getGroup(ctx, t, fixture.client, groupBetaID)
		assert.Empty(t, betaGroup.Spec.UserIDs)
		assert.Empty(t, betaGroup.Spec.Subjects)
	})

	t.Run("allows removing a user from a group whose role the caller cannot grant", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, []string{orgUserAliceID}, []unikornv1.GroupSubject{aliceSubject()}),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{},
			},
		}

		result, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.NoError(t, err)
		assert.Empty(t, result.Spec.GroupIDs)

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.NotContains(t, alphaGroup.Spec.UserIDs, orgUserAliceID)
		assert.NotContains(t, alphaGroup.Spec.Subjects, aliceSubject())
		assert.Equal(t, []string{radarRoleID}, alphaGroup.Spec.RoleIDs)
	})

	t.Run("refuses a create joining an ungrantable group without persisting any record", func(t *testing.T) {
		t.Parallel()

		// Create writes a global user and an organization membership before it
		// reconciles groups.  Discovering the refusal after that would leave
		// both records behind for an account the caller was told it could not
		// create.
		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			radarRole(),
			newRadarGroup(groupAlphaID, nil, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Create}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
		require.Error(t, err)
		require.True(t, errors.IsForbidden(err))
		assert.Contains(t, err.Error(), radarRoleName)

		globalUsers := &unikornv1.UserList{}
		require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
		assert.Empty(t, globalUsers.Items, "a refused create must not leave a global user behind")

		organizationUsers := &unikornv1.OrganizationUserList{}
		require.NoError(t, fixture.client.List(ctx, organizationUsers, &client.ListOptions{Namespace: testOrgNS}))
		assert.Empty(t, organizationUsers.Items, "a refused create must not leave an organization membership behind")

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Empty(t, alphaGroup.Spec.UserIDs)
		assert.Empty(t, alphaGroup.Spec.Subjects)
	})

	t.Run("creates the user when the caller holds the requested group's role", func(t *testing.T) {
		t.Parallel()

		// The counterpart: validating up front must not block a create the
		// caller is entitled to make, and the whole flow still has to run.
		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			radarRole(),
			newRadarGroup(groupAlphaID, nil, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Create}},
			{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		result, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
		require.NoError(t, err)
		assert.Equal(t, userAliceSubject, result.Spec.Subject)
		assert.Equal(t, openapi.GroupIDs{groupAlphaID}, result.Spec.GroupIDs)

		globalUsers := &unikornv1.UserList{}
		require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
		require.Len(t, globalUsers.Items, 1)
		assert.Equal(t, userAliceSubject, globalUsers.Items[0].Spec.Subject)

		organizationUsers := &unikornv1.OrganizationUserList{}
		require.NoError(t, fixture.client.List(ctx, organizationUsers, &client.ListOptions{Namespace: testOrgNS}))
		require.Len(t, organizationUsers.Items, 1)
		assert.Equal(t, result.Metadata.Id, organizationUsers.Items[0].Name)

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Contains(t, alphaGroup.Spec.UserIDs, result.Metadata.Id)
		assert.Contains(t, alphaGroup.Spec.Subjects, aliceSubject())
	})

	t.Run("allows deleting a user held by a group whose role the caller cannot grant", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, []string{orgUserAliceID}, []unikornv1.GroupSubject{aliceSubject()}),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Delete}},
		})

		// Deletion strips memberships as cleanup.  It confers nothing, so it
		// must not be blocked by the group's ungrantable role.
		require.NoError(t, fixture.usersClient.Delete(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID))

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Empty(t, alphaGroup.Spec.UserIDs)
		assert.Empty(t, alphaGroup.Spec.Subjects)
	})
}

// TestClient_GroupMembershipDanglingRole covers a group referencing a role that no longer
// resolves.  The reference cannot be grant-checked, and role IDs are derived from the role
// name, so the role rebinds to the group if it is ever re-applied.
func TestClient_GroupMembershipDanglingRole(t *testing.T) {
	t.Parallel()

	t.Run("refuses adding a user to a group whose role reference does not resolve", func(t *testing.T) {
		t.Parallel()

		// The role is absent, so nothing can grant-check it.  Waving the
		// addition through would also break the victim's whole organization
		// ACL, which fails closed on a dangling reference — a denial primitive
		// for anyone holding users update.
		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			newRadarGroup(groupAlphaID, nil, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
			{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.Error(t, err)
		require.True(t, errors.IsForbidden(err))
		assert.Contains(t, err.Error(), radarRoleID, "the error must name the role that cannot be resolved")

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Empty(t, alphaGroup.Spec.UserIDs)
		assert.Empty(t, alphaGroup.Spec.Subjects)
	})
}

// TestClient_GroupMembershipUnknownGroup covers a requested group the organization does
// not have.  Reconciliation walks the groups that exist and matches the request against
// them, so an ID that matches nothing used to fall through every branch: the caller got a
// 200 whose body simply did not mention the group it asked for.
func TestClient_GroupMembershipUnknownGroup(t *testing.T) {
	t.Parallel()

	t.Run("refuses an update naming a group that does not exist", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			newPlainGroup(groupAlphaID),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID, "group-that-does-not-exist"},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.Error(t, err)
		require.True(t, errors.IsBadRequest(err))
		assert.Contains(t, err.Error(), "group-that-does-not-exist")

		// The check runs in the pre-pass, so the membership the request would
		// also have applied has not landed either.
		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Empty(t, alphaGroup.Spec.UserIDs)
	})

	t.Run("refuses a create naming a group that does not exist", func(t *testing.T) {
		t.Parallel()

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newPlainGroup(groupAlphaID),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Create}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{"group-that-does-not-exist"},
			},
		}

		_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
		require.Error(t, err)
		require.True(t, errors.IsBadRequest(err))
		assert.Contains(t, err.Error(), "group-that-does-not-exist")

		globalUsers := &unikornv1.UserList{}
		require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
		assert.Empty(t, globalUsers.Items, "a refused create must not leave a global user behind")
	})
}

// TestClient_GroupMembershipRepresentations covers the two ways a group stores a member.
// RBAC resolves a principal into a group through either the deprecated organization user
// ID list or the subject list, so a member present in one already holds the group's roles
// and writing the other half grants nothing.
func TestClient_GroupMembershipRepresentations(t *testing.T) {
	t.Parallel()

	t.Run("allows completing the subject half for a member already in the legacy user ID list", func(t *testing.T) {
		t.Parallel()

		// A group written before Subjects existed lists its members in UserIDs
		// only.  RBAC resolves membership through either list, so the user
		// already holds the group's roles and writing the missing half confers
		// nothing — it must not be gated on a role the caller cannot grant.
		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, []string{orgUserAliceID}, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.NoError(t, err)

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Equal(t, []string{orgUserAliceID}, alphaGroup.Spec.UserIDs)
		require.Len(t, alphaGroup.Spec.Subjects, 1)
		assert.Equal(t, userAliceSubject, alphaGroup.Spec.Subjects[0].ID)
	})

	t.Run("does not duplicate a stored subject whose email differs from the derived one", func(t *testing.T) {
		t.Parallel()

		// Email is display data and three writers populate it differently, so a
		// whole-struct comparison sees the stored subject and the derived one as
		// different principals and appends a second copy on every write.
		stored := unikornv1.GroupSubject{
			ID:     userAliceSubject,
			Email:  "stale-display@example.com",
			Issuer: testIssuerURL,
		}

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, []string{orgUserAliceID}, []unikornv1.GroupSubject{stored}),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.NoError(t, err)

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Len(t, alphaGroup.Spec.Subjects, 1, "the same principal must not be stored twice")
		assert.Equal(t, []string{orgUserAliceID}, alphaGroup.Spec.UserIDs)
	})

	t.Run("allows re-stating a membership stored as a legacy empty-issuer subject", func(t *testing.T) {
		t.Parallel()

		// Subject records written before issuers were recorded carry an empty
		// one, and RBAC resolves them by ID alone, so the user already holds
		// the group's roles.  The gate must match the way RBAC matches: an
		// issuer-qualified comparison would read this no-op re-send as an
		// addition and refuse it on the ungrantable role.
		stored := unikornv1.GroupSubject{
			ID:    userAliceSubject,
			Email: userAliceSubject,
		}

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, nil, []unikornv1.GroupSubject{stored}),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.NoError(t, err)

		// The write completes the canonical representation alongside the
		// legacy record rather than being refused.
		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Equal(t, []string{orgUserAliceID}, alphaGroup.Spec.UserIDs)
	})

	t.Run("still refuses a genuine addition to a group holding only legacy records", func(t *testing.T) {
		t.Parallel()

		// The ID-only matching above must not blanket-allow: a legacy record
		// for someone else confers nothing on this user, so joining the group
		// is still a grant of the ungrantable role and is refused.
		stored := unikornv1.GroupSubject{
			ID:    userBobSubject,
			Email: userBobSubject,
		}

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, nil, []unikornv1.GroupSubject{stored}),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.Error(t, err)
		require.True(t, errors.IsForbidden(err))
		require.Contains(t, err.Error(), "radar")

		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.Empty(t, alphaGroup.Spec.UserIDs, "a refused addition must not be applied")
	})
}

func TestClient_Delete(t *testing.T) {
	t.Parallel()

	t.Run("removes the user from its groups and deletes the membership", func(t *testing.T) {
		t.Parallel()

		subject := unikornv1.GroupSubject{
			ID:     userBobSubject,
			Email:  userBobSubject,
			Issuer: testIssuerURL,
		}

		group := &unikornv1.Group{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testOrgNS,
				Name:      groupAlphaID,
			},
			Spec: unikornv1.GroupSpec{
				UserIDs:  []string{orgUserBobID},
				Subjects: []unikornv1.GroupSubject{subject},
			},
		}

		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userBobID, userBobSubject),
			newOrganizationUser(orgUserBobID, userBobID),
			group,
		}, interceptor.Funcs{})
		ctx := newContext(t)

		err := fixture.usersClient.Delete(ctx, ids.MustParseOrganizationID(testOrgID), orgUserBobID)
		require.NoError(t, err)

		organizationUsers := &unikornv1.OrganizationUserList{}
		require.NoError(t, fixture.client.List(ctx, organizationUsers, &client.ListOptions{Namespace: testOrgNS}))
		require.Empty(t, organizationUsers.Items)

		// the user is scrubbed from the group in both membership representations
		alphaGroup := getGroup(ctx, t, fixture.client, groupAlphaID)
		assert.NotContains(t, alphaGroup.Spec.UserIDs, orgUserBobID)
		assert.NotContains(t, alphaGroup.Spec.Subjects, subject)
	})
}

// TestClient_GroupMembershipWriteOrdering covers what a refusal must leave behind.  An
// update rewrites the organization user record as well as reconciling group membership,
// so the grants have to be settled before any of it lands.
func TestClient_GroupMembershipWriteOrdering(t *testing.T) {
	t.Parallel()

	t.Run("refuses an update joining an ungrantable group without persisting the state change", func(t *testing.T) {
		t.Parallel()

		// Update rewrites the organization user record — state, tags, labels,
		// annotations — as well as reconciling groups.  A membership refusal
		// discovered after that would leave the state change applied for a
		// request the caller was told it could not make.
		fixture := newUserTestFixtureWithObjects(t, []client.Object{
			newGlobalUser(userAliceID, userAliceSubject),
			newOrganizationUser(orgUserAliceID, userAliceID),
			radarRole(),
			newRadarGroup(groupAlphaID, nil, nil),
		}, interceptor.Funcs{})

		ctx := aclContext(t, openapi.AclEndpoints{
			{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
		})

		request := &openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Suspended,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		}

		_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID, request)
		require.Error(t, err)
		require.True(t, errors.IsForbidden(err))

		organizationUser := &unikornv1.OrganizationUser{}
		require.NoError(t, fixture.client.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: orgUserAliceID}, organizationUser))
		assert.Equal(t, unikornv1.UserStateActive, organizationUser.Spec.State,
			"a refused update must not persist the state change")
	})
}
