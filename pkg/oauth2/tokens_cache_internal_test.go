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

package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	cachedToken       = "cached-token"
	cachedReplacement = "replacement-token"
	cachedClientID    = "cached-client"
	cachedUserID      = "cached-user"
	cachedSubject     = "cached@example.com"
	cachedServiceID   = "cached-service-account"
)

func cachedTokenScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	return scheme
}

func newCachedAuthenticator(cli client.Client) *Authenticator {
	return &Authenticator{
		client:     cli,
		namespace:  passportTestNamespace,
		issuer:     common.IssuerValue{URL: "https://identity.example.com", Hostname: "identity.example.com"},
		userdb:     userdb.NewUserDatabase(cli, passportTestNamespace),
		tokenCache: cache.NewLRUExpireCache(16),
	}
}

func cachedRequest(t *testing.T) *http.Request {
	t.Helper()

	return httptest.NewRequest(http.MethodGet, "https://identity.example.com/oauth2/v2/userinfo", nil)
}

func cachedFederatedClaims() *Claims {
	return &Claims{
		Type: TokenTypeFederated,
		Federated: &FederatedClaims{
			ClientID: cachedClientID,
		},
		Claims: jwt.Claims{Subject: cachedSubject},
	}
}

func TestCachedFederatedTokenChecksTheStoredSession(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*unikornv1.User){
		"reissue": func(user *unikornv1.User) {
			user.Spec.Sessions[0].AccessToken = cachedReplacement
		},
		"refresh": func(user *unikornv1.User) {
			user.Spec.Sessions[0].AccessToken = cachedReplacement
			user.Spec.Sessions[0].RefreshToken = "replacement-refresh-token"
		},
		"revocation": func(user *unikornv1.User) {
			user.Spec.Sessions = nil
		},
	}

	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			user := &unikornv1.User{
				ObjectMeta: metav1.ObjectMeta{Namespace: passportTestNamespace, Name: cachedUserID},
				Spec: unikornv1.UserSpec{
					Subject: cachedSubject,
					State:   unikornv1.UserStateActive,
					Sessions: []unikornv1.UserSession{{
						ClientID:    cachedClientID,
						AccessToken: cachedToken,
					}},
				},
			}
			organizationUser := &unikornv1.OrganizationUser{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: passportTestNamespace,
					Name:      "cached-organization-user",
					Labels: map[string]string{
						constants.UserLabel:         cachedUserID,
						constants.OrganizationLabel: "cached-organization",
					},
				},
				Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
			}
			cli := fake.NewClientBuilder().WithScheme(cachedTokenScheme(t)).WithObjects(user, organizationUser).Build()

			firstReplica := newCachedAuthenticator(cli)
			secondReplica := newCachedAuthenticator(cli)

			firstReplica.tokenCache.Add(cachedToken, cachedFederatedClaims(), time.Hour)
			secondReplica.tokenCache.Add(cachedToken, cachedFederatedClaims(), time.Hour)

			_, _, err := firstReplica.GetUserinfo(t.Context(), cachedRequest(t), cachedToken)
			require.NoError(t, err)

			stored := &unikornv1.User{}
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(user), stored))
			change(stored)
			require.NoError(t, cli.Update(t.Context(), stored))

			_, _, err = secondReplica.GetUserinfo(t.Context(), cachedRequest(t), cachedToken)
			require.Error(t, err)
		})
	}
}

func TestCachedFederatedTokenReusesTheResolvedUser(t *testing.T) {
	t.Parallel()

	userLists := 0
	cli := fake.NewClientBuilder().WithScheme(cachedTokenScheme(t)).
		WithObjects(
			&unikornv1.User{
				ObjectMeta: metav1.ObjectMeta{Namespace: passportTestNamespace, Name: cachedUserID},
				Spec: unikornv1.UserSpec{
					Subject: cachedSubject,
					State:   unikornv1.UserStateActive,
					Sessions: []unikornv1.UserSession{{
						ClientID:    cachedClientID,
						AccessToken: cachedToken,
					}},
				},
			},
			&unikornv1.OrganizationUser{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: passportTestNamespace,
					Name:      "cached-organization-user",
					Labels: map[string]string{
						constants.UserLabel:         cachedUserID,
						constants.OrganizationLabel: "cached-organization",
					},
				},
				Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
			},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, options ...client.ListOption) error {
				if _, ok := list.(*unikornv1.UserList); ok {
					userLists++
				}

				return inner.List(ctx, list, options...)
			},
		}).
		Build()

	authenticator := newCachedAuthenticator(cli)
	authenticator.tokenCache.Add(cachedToken, cachedFederatedClaims(), time.Hour)

	_, _, err := authenticator.GetUserinfo(t.Context(), cachedRequest(t), cachedToken)
	require.NoError(t, err)
	require.Equal(t, 1, userLists)
}

func TestCachedServiceAccountTokenChecksTheStoredToken(t *testing.T) {
	t.Parallel()

	tests := map[string]func(context.Context, client.Client, *unikornv1.ServiceAccount){
		"rotation": func(ctx context.Context, cli client.Client, serviceAccount *unikornv1.ServiceAccount) {
			serviceAccount.Spec.AccessToken = cachedReplacement
			require.NoError(t, cli.Update(ctx, serviceAccount))
		},
		"deletion": func(ctx context.Context, cli client.Client, serviceAccount *unikornv1.ServiceAccount) {
			require.NoError(t, cli.Delete(ctx, serviceAccount))
		},
	}

	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			serviceAccount := &unikornv1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: "cached-organization", Name: cachedServiceID},
				Spec:       unikornv1.ServiceAccountSpec{AccessToken: cachedToken},
			}
			serviceAccountLists := 0
			organizationGets := 0
			serviceAccountGets := 0
			cli := fake.NewClientBuilder().WithScheme(cachedTokenScheme(t)).
				WithObjects(
					&unikornv1.Organization{
						ObjectMeta: metav1.ObjectMeta{Namespace: passportTestNamespace, Name: "cached-organization"},
						Status:     unikornv1.OrganizationStatus{Namespace: "cached-organization"},
					},
					serviceAccount,
				).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
						switch object.(type) {
						case *unikornv1.Organization:
							organizationGets++
						case *unikornv1.ServiceAccount:
							serviceAccountGets++
						}

						return inner.Get(ctx, key, object, options...)
					},
					List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, options ...client.ListOption) error {
						if _, ok := list.(*unikornv1.ServiceAccountList); ok {
							serviceAccountLists++
						}

						return inner.List(ctx, list, options...)
					},
				}).
				Build()
			firstReplica := newCachedAuthenticator(cli)
			secondReplica := newCachedAuthenticator(cli)
			claims := &Claims{
				Type:   TokenTypeServiceAccount,
				Claims: jwt.Claims{Subject: cachedServiceID},
				ServiceAccount: &ServiceAccountClaims{
					OrganizationID: "cached-organization",
				},
			}
			firstReplica.tokenCache.Add(cachedToken, claims, time.Hour)
			secondReplica.tokenCache.Add(cachedToken, claims, time.Hour)

			_, err := firstReplica.Verify(t.Context(), &VerifyInfo{Token: cachedToken})
			require.NoError(t, err)
			require.Zero(t, serviceAccountLists)
			require.Equal(t, 1, organizationGets)
			require.Equal(t, 1, serviceAccountGets)

			stored := &unikornv1.ServiceAccount{}
			require.NoError(t, cli.Get(t.Context(), client.ObjectKeyFromObject(serviceAccount), stored))
			change(t.Context(), cli, stored)

			_, err = secondReplica.Verify(t.Context(), &VerifyInfo{Token: cachedToken})
			require.Error(t, err)
		})
	}
}
