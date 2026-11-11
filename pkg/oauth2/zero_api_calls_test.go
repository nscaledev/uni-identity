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

package oauth2_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var errLiveCall = errors.New("live API server call on the per-request path")

// liveGuard stands in for the API server. Once armed, it refuses and records
// every call made through the live client.
type liveGuard struct {
	armed atomic.Bool
	lock  sync.Mutex
	calls []string
}

func (g *liveGuard) refuse(verb string, object any) error {
	if !g.armed.Load() {
		return nil
	}

	g.lock.Lock()
	defer g.lock.Unlock()

	g.calls = append(g.calls, fmt.Sprintf("%s %T", verb, object))

	return errLiveCall
}

func (g *liveGuard) recorded() []string {
	g.lock.Lock()
	defer g.lock.Unlock()

	return append([]string(nil), g.calls...)
}

//nolint:cyclop // one pass-through per client verb
func (g *liveGuard) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := g.refuse("get", obj); err != nil {
				return err
			}

			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := g.refuse("list", list); err != nil {
				return err
			}

			return c.List(ctx, list, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if err := g.refuse("create", obj); err != nil {
				return err
			}

			return c.Create(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := g.refuse("delete", obj); err != nil {
				return err
			}

			return c.Delete(ctx, obj, opts...)
		},
		DeleteAllOf: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
			if err := g.refuse("deleteallof", obj); err != nil {
				return err
			}

			return c.DeleteAllOf(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if err := g.refuse("update", obj); err != nil {
				return err
			}

			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := g.refuse("patch", obj); err != nil {
				return err
			}

			return c.Patch(ctx, obj, patch, opts...)
		},
		Watch: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
			if err := g.refuse("watch", list); err != nil {
				return nil, err
			}

			return c.Watch(ctx, list, opts...)
		},
		SubResourceGet: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, subResource client.Object, opts ...client.SubResourceGetOption) error {
			if err := g.refuse("get/"+subResourceName, obj); err != nil {
				return err
			}

			return c.SubResource(subResourceName).Get(ctx, obj, subResource, opts...)
		},
		SubResourceCreate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
			if err := g.refuse("create/"+subResourceName, obj); err != nil {
				return err
			}

			return c.SubResource(subResourceName).Create(ctx, obj, subResource, opts...)
		},
		SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if err := g.refuse("update/"+subResourceName, obj); err != nil {
				return err
			}

			return c.SubResource(subResourceName).Update(ctx, obj, opts...)
		},
		SubResourcePatch: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if err := g.refuse("patch/"+subResourceName, obj); err != nil {
				return err
			}

			return c.SubResource(subResourceName).Patch(ctx, obj, patch, opts...)
		},
	}
}

const (
	guardOrganization = "org1"
	guardOrgNamespace = josetesting.Namespace + "-org1"
	guardProject      = "project1"
	guardUser         = "test-user"
	guardSubject      = "user@example.com"
	guardAccount      = "test-sa"
)

// guardObjects is an organization with a project, a group that grants a role
// on it to a user and a service account, and the records that make both
// principals active. The user is a legacy record, unlabelled and
// random-named, so its lookup takes the subject index.
func guardObjects(signingKey []byte) []client.Object {
	return []client.Object{
		&unikornv1.SigningKey{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: jose.SigningKeyName},
			Spec:       unikornv1.SigningKeySpec{PrivateKeys: []unikornv1.PrivateKey{{PEM: signingKey}}},
		},
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: guardOrganization},
			Status:     unikornv1.OrganizationStatus{Namespace: guardOrgNamespace},
		},
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: guardUser},
			Spec:       unikornv1.UserSpec{Subject: guardSubject, State: unikornv1.UserStateActive},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: guardOrgNamespace,
				Name:      "org1-user",
				Labels:    map[string]string{constants.UserLabel: guardUser, constants.OrganizationLabel: guardOrganization},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		},
		&unikornv1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: guardOrgNamespace,
				Name:      guardAccount,
				Labels:    map[string]string{constants.OrganizationLabel: guardOrganization},
			},
		},
		&unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: "test-role"},
			Spec: unikornv1.RoleSpec{
				Scopes: unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{{Name: "identity:projects", Operations: []unikornv1.Operation{unikornv1.Read}}},
					Project:      []unikornv1.RoleScope{{Name: "compute", Operations: []unikornv1.Operation{unikornv1.Read}}},
				},
			},
		},
		&unikornv1.Group{
			ObjectMeta: metav1.ObjectMeta{Namespace: guardOrgNamespace, Name: "test-group"},
			Spec: unikornv1.GroupSpec{
				Subjects:          []unikornv1.GroupSubject{{ID: guardSubject}},
				ServiceAccountIDs: []string{guardAccount},
				RoleIDs:           []string{"test-role"},
			},
		},
		&unikornv1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: guardOrgNamespace,
				Name:      guardProject,
				Labels:    map[string]string{constants.OrganizationLabel: guardOrganization},
			},
			Spec: unikornv1.ProjectSpec{GroupIDs: []string{"test-group"}},
		},
	}
}

type guardEnv struct {
	guard *liveGuard
	store client.Client
	// issuer writes sessions as sign-in does; it is only used before the guard is armed.
	issuer *oauth2.Authenticator
	// replica serves requests, from a cold token cache.
	replica *oauth2.Authenticator
	rbac    *rbac.RBAC
}

// newGuardEnv wires the server as production does: the live client writes,
// and the reader, here the fake store the informer cache would mirror, serves
// every other read.
func newGuardEnv(t *testing.T) *guardEnv {
	t.Helper()

	keySource := fake.NewClientBuilder().WithScheme(getScheme(t)).Build()
	signingKey := josetesting.RotateCertificate(t, keySource)

	store := fake.NewClientBuilder().WithScheme(getScheme(t)).
		WithIndex(&unikornv1.User{}, userdb.SubjectIndexField, userdb.SubjectIndexValue).
		WithObjects(guardObjects(signingKey)...).
		Build()

	guard := &liveGuard{}
	live := interceptor.NewClient(store, guard.funcs())

	// The keys are already in the store, so the leader election that writes
	// them is not run.
	jwtIssuer := jose.NewJWTIssuer(live, store, josetesting.Namespace, &jose.Options{})
	rbacInst := rbac.New(store, josetesting.Namespace, &rbac.Options{})
	issuerValue := handlercommon.IssuerValue{URL: "https://test.com", Hostname: "test.com"}

	newAuthenticator := func() *oauth2.Authenticator {
		authenticator, err := oauth2.New(&oauth2.Options{
			AccessTokenDuration:  time.Hour,
			RefreshTokenDuration: time.Hour,
			TokenLeewayDuration:  time.Hour,
			TokenCacheSize:       16,
		}, josetesting.Namespace, issuerValue, live, store, jwtIssuer, rbacInst)
		require.NoError(t, err)

		return authenticator
	}

	return &guardEnv{guard: guard, store: store, issuer: newAuthenticator(), replica: newAuthenticator(), rbac: rbacInst}
}

func (e *guardEnv) issueUserToken(t *testing.T) string {
	t.Helper()

	tokens, err := e.issuer.Issue(t.Context(), &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  guardSubject,
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID:   guardUser,
			ClientID: "client",
			Scope:    oauth2.NewScope("openid email"),
		},
	})
	require.NoError(t, err)

	return tokens.AccessToken
}

func (e *guardEnv) issueServiceAccountToken(t *testing.T) string {
	t.Helper()

	tokens, err := e.issuer.Issue(t.Context(), &oauth2.IssueInfo{
		Issuer:         "https://test.com",
		Audience:       "test.com",
		Subject:        guardAccount,
		Type:           oauth2.TokenTypeServiceAccount,
		ServiceAccount: &oauth2.ServiceAccountClaims{OrganizationID: guardOrganization},
	})
	require.NoError(t, err)

	account := &unikornv1.ServiceAccount{}
	require.NoError(t, e.store.Get(t.Context(), types.NamespacedName{Namespace: guardOrgNamespace, Name: guardAccount}, account))
	account.Spec.AccessToken = tokens.AccessToken
	require.NoError(t, e.store.Update(t.Context(), account))

	return tokens.AccessToken
}

// arm starts refusing live calls, and checks at the end of the test that the
// per-request path made none.
func (e *guardEnv) arm(t *testing.T) {
	t.Helper()

	e.guard.armed.Store(true)

	t.Cleanup(func() {
		require.Empty(t, e.guard.recorded(), "the per-request path called the API server")
	})
}

func userinfoRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://test.com/oauth2/v2/userinfo", nil)
}

// TestPerRequestPathMakesNoAPIServerCalls drives the per-request authn and
// authz path with every live client call refused. Each subtest builds its own
// world, so a cached read in one cannot hide a live read in another.
func TestPerRequestPathMakesNoAPIServerCalls(t *testing.T) {
	t.Parallel()

	t.Run("federated user token check", func(t *testing.T) {
		t.Parallel()

		env := newGuardEnv(t)
		token := env.issueUserToken(t)
		env.arm(t)

		userinfo, _, err := env.replica.GetUserinfo(t.Context(), userinfoRequest(), token)
		require.NoError(t, err)
		require.Equal(t, guardSubject, userinfo.Sub)
		require.Equal(t, []string{guardOrganization}, userinfo.HttpsunikornCloudOrgauthz.OrgIds)
	})

	t.Run("service account token check", func(t *testing.T) {
		t.Parallel()

		env := newGuardEnv(t)
		token := env.issueServiceAccountToken(t)
		env.arm(t)

		userinfo, _, err := env.replica.GetUserinfo(t.Context(), userinfoRequest(), token)
		require.NoError(t, err)
		require.Equal(t, guardAccount, userinfo.Sub)
		require.Equal(t, openapi.Service, userinfo.HttpsunikornCloudOrgauthz.Acctype)
	})

	t.Run("ACL build for a user in an organization with groups and projects", func(t *testing.T) {
		t.Parallel()

		env := newGuardEnv(t)
		env.arm(t)

		ctx := authorization.NewContext(t.Context(), &authorization.Info{
			Userinfo: &openapi.Userinfo{
				Sub: guardSubject,
				HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
					Acctype: openapi.User,
					OrgIds:  []string{guardOrganization},
				},
			},
		})

		acl, err := env.rbac.GetACL(ctx, guardOrganization)
		require.NoError(t, err)
		require.NotNil(t, acl.Organization)
		require.Equal(t, guardOrganization, acl.Organization.Id)
		require.NotNil(t, acl.Projects)
		require.Len(t, *acl.Projects, 1)
		require.Equal(t, guardProject, (*acl.Projects)[0].Id)
		require.NotNil(t, acl.Organizations)
		require.Len(t, *acl.Organizations, 1)
	})

	t.Run("passport exchange", func(t *testing.T) {
		t.Parallel()

		env := newGuardEnv(t)
		token := env.issueUserToken(t)
		env.arm(t)

		organizationID, projectID := guardOrganization, guardProject

		result, err := env.replica.TokenExchange(nil, exchangeRequest(t, token, &openapi.TokenRequestOptions{
			XOrganizationId: &organizationID,
			XProjectId:      &projectID,
		}))
		require.NoError(t, err)
		require.NotEmpty(t, result.AccessToken)
	})
}
