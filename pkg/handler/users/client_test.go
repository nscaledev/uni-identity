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
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	corev1 "k8s.io/api/core/v1"
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
)

type userTestFixture struct {
	client      client.Client
	usersClient *users.Client
}

var (
	errListOrganizationUsers  = goerrors.New("list organization users")
	errCreateOrganizationUser = goerrors.New("create organization user")
)

func newContext(t *testing.T) context.Context {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Principal: &principal.Principal{
			Subject: "test-subject",
		},
	})

	ctx = principal.NewContext(ctx, &principal.Principal{
		Subject:        "test-principal",
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
}
