/*
Copyright 2024-2025 the Unikorn Authors.
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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var errOrganizationReadUsedDirectClient = errors.New("organization read used direct client")

const (
	// JWT claims have second accuracy, so use whole seconds as our time
	// basis.  The access token must survive the 2× RefreshPeriod sleep
	// plus issue + verify round-trip on slow CI runners.
	accessTokenDuration  = 5 * time.Second
	refreshTokenDuration = 30 * time.Second
)

func getScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	return s
}

func TestTokens(t *testing.T) {
	t.Parallel()

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      "fake",
		},
		Spec: unikornv1.UserSpec{
			Subject: "barry@foo.com",
			State:   unikornv1.UserStateActive,
		},
	}

	client := fake.NewClientBuilder().WithScheme(getScheme(t)).WithObjects(user).Build()

	josetesting.RotateCertificate(t, client)

	joseOptions := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, joseOptions)

	ctx := t.Context()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	userDatabase := userdb.NewUserDatabase(client, josetesting.Namespace)
	rbac := rbac.New(client, josetesting.Namespace, &rbac.Options{})

	options := &oauth2.Options{
		AccessTokenDuration:  accessTokenDuration,
		RefreshTokenDuration: refreshTokenDuration,
		TokenLeewayDuration:  accessTokenDuration,
		TokenCacheSize:       1024,
		CodeCacheSize:        1024,
	}

	issuerVal := handlercommon.IssuerValue{
		URL:      "https://foo.com",
		Hostname: "foo.com",
	}

	authenticator, err := oauth2.New(options, josetesting.Namespace, issuerVal, client, client, issuer, userDatabase, rbac)
	require.NoError(t, err)

	time.Sleep(2 * josetesting.RefreshPeriod)

	issueInfo := &oauth2.IssueInfo{
		Issuer:   "https://foo.com",
		Audience: "foo.com",
		Subject:  "barry@foo.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID: "fake",
		},
	}

	tokens, err := authenticator.Issue(ctx, issueInfo)
	require.NoError(t, err)

	verifyInfo := &oauth2.VerifyInfo{
		Issuer:   "https://foo.com",
		Audience: "foo.com",
		Token:    tokens.AccessToken,
	}

	_, err = authenticator.Verify(ctx, verifyInfo)
	require.NoError(t, err)

	// Wait for expiry and verify it doesn't work.
	time.Sleep(2 * accessTokenDuration)

	_, err = authenticator.Verify(ctx, verifyInfo)
	require.Error(t, err)
}

func TestVerifyServiceAccountUsesOrganizationReader(t *testing.T) {
	t.Parallel()

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: "test-org"},
		Status:     unikornv1.OrganizationStatus{Namespace: josetesting.Namespace + "-org"},
	}
	serviceAccount := &unikornv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: organization.Status.Namespace, Name: "test-service-account"},
	}
	scheme := getScheme(t)
	directClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, serviceAccount).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
				if _, ok := object.(*unikornv1.Organization); ok {
					return errOrganizationReadUsedDirectClient
				}

				return inner.Get(ctx, key, object, options...)
			},
		}).Build()
	organizationReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization).Build()

	josetesting.RotateCertificate(t, directClient)
	issuer := jose.NewJWTIssuer(directClient, josetesting.Namespace, &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	})
	require.NoError(t, issuer.Run(t.Context(), &josetesting.FakeCoordinationClientGetter{}))
	time.Sleep(2 * josetesting.RefreshPeriod)

	authenticator, err := oauth2.New(&oauth2.Options{AccessTokenDuration: time.Hour, TokenCacheSize: 1, CodeCacheSize: 1}, josetesting.Namespace, handlercommon.IssuerValue{
		URL:      "https://test.com",
		Hostname: "test.com",
	}, directClient, organizationReader, issuer, userdb.NewUserDatabase(directClient, josetesting.Namespace), rbac.New(directClient, josetesting.Namespace, &rbac.Options{}))
	require.NoError(t, err)

	tokens, err := authenticator.Issue(t.Context(), &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  serviceAccount.Name,
		Type:     oauth2.TokenTypeServiceAccount,
		ServiceAccount: &oauth2.ServiceAccountClaims{
			OrganizationID: organization.Name,
		},
	})
	require.NoError(t, err)

	stored := &unikornv1.ServiceAccount{}
	require.NoError(t, directClient.Get(t.Context(), client.ObjectKeyFromObject(serviceAccount), stored))
	stored.Spec.AccessToken = tokens.AccessToken
	require.NoError(t, directClient.Update(t.Context(), stored))

	_, err = authenticator.Verify(t.Context(), &oauth2.VerifyInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Token:    tokens.AccessToken,
	})
	require.NoError(t, err)
}

// TestUserinfoCustomClaims tests that tokens include correct custom authorization claims.
//
//nolint:maintidx
func TestUserinfoCustomClaims(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		objects        []client.Object
		issueInfo      *oauth2.IssueInfo
		postIssue      func(*testing.T, context.Context, client.Client, *oauth2.Tokens)
		postVerify     func(*testing.T, context.Context, client.Client, *oauth2.Authenticator, *oauth2.Tokens)
		expectedSub    string
		expectedEmail  *string
		expectedType   openapi.AuthClaimsAcctype
		expectedOrgIDs []string
	}{
		"federated user": {
			objects: []client.Object{
				&unikornv1.User{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "test-user",
					},
					Spec: unikornv1.UserSpec{
						Subject: "user@example.com",
						State:   unikornv1.UserStateActive,
					},
				},
			},
			postVerify: func(t *testing.T, ctx context.Context, c client.Client, authenticator *oauth2.Authenticator, tokens *oauth2.Tokens) {
				t.Helper()

				user := &unikornv1.User{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: josetesting.Namespace, Name: "test-user"}, user))
				require.Len(t, user.Spec.Sessions, 1)
				user.Spec.Sessions[0].AccessToken = ""
				require.NoError(t, c.Update(ctx, user))

				req := httptest.NewRequest(http.MethodGet, "https://test.com/oauth2/v2/userinfo", nil)
				_, _, err := authenticator.GetUserinfo(ctx, req, tokens.AccessToken)
				require.ErrorIs(t, err, oauth2.ErrTokenVerification)
			},
			issueInfo: &oauth2.IssueInfo{
				Issuer:   "https://test.com",
				Audience: "test.com",
				Subject:  "user@example.com",
				Type:     oauth2.TokenTypeFederated,
				Federated: &oauth2.FederatedClaims{
					UserID: "test-user",
					Scope:  oauth2.NewScope("openid email"),
				},
			},
			expectedSub:    "user@example.com",
			expectedEmail:  ptr.To("user@example.com"),
			expectedType:   openapi.User,
			expectedOrgIDs: []string{},
		},
		"federated user with orgs": {
			objects: []client.Object{
				&unikornv1.User{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "test-user",
					},
					Spec: unikornv1.UserSpec{
						Subject: "user@example.com",
						State:   unikornv1.UserStateActive,
					},
				},
				&unikornv1.OrganizationUser{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "org1-user",
						Labels: map[string]string{
							constants.UserLabel:         "test-user",
							constants.OrganizationLabel: "org1",
						},
					},
					Spec: unikornv1.OrganizationUserSpec{
						State: unikornv1.UserStateActive,
					},
				},
				&unikornv1.OrganizationUser{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "org2-user",
						Labels: map[string]string{
							constants.UserLabel:         "test-user",
							constants.OrganizationLabel: "org2",
						},
					},
					Spec: unikornv1.OrganizationUserSpec{
						State: unikornv1.UserStateActive,
					},
				},
			},
			issueInfo: &oauth2.IssueInfo{
				Issuer:   "https://test.com",
				Audience: "test.com",
				Subject:  "user@example.com",
				Type:     oauth2.TokenTypeFederated,
				Federated: &oauth2.FederatedClaims{
					UserID: "test-user",
					Scope:  oauth2.NewScope("openid email"),
				},
			},
			expectedSub:    "user@example.com",
			expectedEmail:  ptr.To("user@example.com"),
			expectedType:   openapi.User,
			expectedOrgIDs: []string{"org1", "org2"},
		},
		"federated user excludes suspended orgs": {
			objects: []client.Object{
				&unikornv1.User{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "test-user",
					},
					Spec: unikornv1.UserSpec{
						Subject: "user@example.com",
						State:   unikornv1.UserStateActive,
					},
				},
				&unikornv1.OrganizationUser{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "org1-user",
						Labels: map[string]string{
							constants.UserLabel:         "test-user",
							constants.OrganizationLabel: "org1",
						},
					},
					Spec: unikornv1.OrganizationUserSpec{
						State: unikornv1.UserStateActive,
					},
				},
				&unikornv1.OrganizationUser{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "org2-user",
						Labels: map[string]string{
							constants.UserLabel:         "test-user",
							constants.OrganizationLabel: "org2",
						},
					},
					Spec: unikornv1.OrganizationUserSpec{
						State: unikornv1.UserStateSuspended,
					},
				},
			},
			issueInfo: &oauth2.IssueInfo{
				Issuer:   "https://test.com",
				Audience: "test.com",
				Subject:  "user@example.com",
				Type:     oauth2.TokenTypeFederated,
				Federated: &oauth2.FederatedClaims{
					UserID: "test-user",
					Scope:  oauth2.NewScope("openid email"),
				},
			},
			expectedSub:    "user@example.com",
			expectedEmail:  ptr.To("user@example.com"),
			expectedType:   openapi.User,
			expectedOrgIDs: []string{"org1"},
		},
		"service account": {
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace,
						Name:      "test-org",
					},
					Status: unikornv1.OrganizationStatus{
						Namespace: josetesting.Namespace + "-org",
					},
				},
				&unikornv1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: josetesting.Namespace + "-org",
						Name:      "test-service-account",
					},
					Spec: unikornv1.ServiceAccountSpec{},
				},
			},
			issueInfo: &oauth2.IssueInfo{
				Issuer:   "https://test.com",
				Audience: "test.com",
				Subject:  "test-service-account",
				Type:     oauth2.TokenTypeServiceAccount,
				ServiceAccount: &oauth2.ServiceAccountClaims{
					OrganizationID: "test-org",
				},
			},
			postIssue: func(t *testing.T, ctx context.Context, c client.Client, tokens *oauth2.Tokens) {
				t.Helper()
				serviceAccount := &unikornv1.ServiceAccount{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{
					Namespace: josetesting.Namespace + "-org",
					Name:      "test-service-account",
				}, serviceAccount))
				serviceAccount.Spec.AccessToken = tokens.AccessToken
				require.NoError(t, c.Update(ctx, serviceAccount))
			},
			postVerify: func(t *testing.T, ctx context.Context, c client.Client, authenticator *oauth2.Authenticator, tokens *oauth2.Tokens) {
				t.Helper()

				serviceAccount := &unikornv1.ServiceAccount{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{
					Namespace: josetesting.Namespace + "-org",
					Name:      "test-service-account",
				}, serviceAccount))
				require.NoError(t, c.Delete(ctx, serviceAccount))

				req := httptest.NewRequest(http.MethodGet, "https://test.com/oauth2/v2/userinfo", nil)
				_, _, err := authenticator.GetUserinfo(ctx, req, tokens.AccessToken)
				require.Error(t, err)
				assert.True(t, apierrors.IsNotFound(err))
			},
			expectedSub:    "test-service-account",
			expectedType:   openapi.Service,
			expectedOrgIDs: []string{"test-org"},
		},
		"system service": {
			issueInfo: &oauth2.IssueInfo{
				Issuer:   "https://test.com",
				Audience: "test.com",
				Subject:  "system-service",
				Type:     oauth2.TokenTypeService,
			},
			expectedSub:    "system-service",
			expectedType:   openapi.System,
			expectedOrgIDs: []string{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := fake.NewClientBuilder().WithScheme(getScheme(t)).WithObjects(tc.objects...).Build()

			josetesting.RotateCertificate(t, client)

			issuer := jose.NewJWTIssuer(client, josetesting.Namespace, &jose.Options{
				IssuerSecretName: josetesting.KeySecretName,
				RotationPeriod:   josetesting.RefreshPeriod,
			})

			ctx := t.Context()

			require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

			userDatabase := userdb.NewUserDatabase(client, josetesting.Namespace)
			rbac := rbac.New(client, josetesting.Namespace, &rbac.Options{})

			issuerHost := handlercommon.IssuerValue{
				URL:      tc.issueInfo.Issuer,
				Hostname: tc.issueInfo.Audience, // setting this from the audience is somewhat arbitrary; but it's not under test here.
			}

			authenticator, err := oauth2.New(&oauth2.Options{
				AccessTokenDuration:  accessTokenDuration,
				RefreshTokenDuration: refreshTokenDuration,
				TokenLeewayDuration:  accessTokenDuration,
				TokenCacheSize:       1024,
				CodeCacheSize:        1024,
			}, josetesting.Namespace, issuerHost, client, client, issuer, userDatabase, rbac)
			require.NoError(t, err)

			time.Sleep(2 * josetesting.RefreshPeriod)

			tokens, err := authenticator.Issue(ctx, tc.issueInfo)
			require.NoError(t, err)

			if tc.postIssue != nil {
				tc.postIssue(t, ctx, client, tokens)
			}

			req := httptest.NewRequest(http.MethodGet, "https://test.com/oauth2/v2/userinfo", nil)
			userinfo, _, err := authenticator.GetUserinfo(ctx, req, tokens.AccessToken)
			require.NoError(t, err)
			require.NotNil(t, userinfo)

			assert.Equal(t, tc.expectedSub, userinfo.Sub)

			if tc.expectedEmail != nil {
				require.NotNil(t, userinfo.Email)
				assert.Equal(t, *tc.expectedEmail, *userinfo.Email)
				require.NotNil(t, userinfo.EmailVerified)
				assert.True(t, *userinfo.EmailVerified)
			} else {
				assert.Nil(t, userinfo.Email)
				assert.Nil(t, userinfo.EmailVerified)
			}

			require.NotNil(t, userinfo.HttpsunikornCloudOrgauthz)
			assert.Equal(t, tc.expectedType, userinfo.HttpsunikornCloudOrgauthz.Acctype)

			if tc.expectedOrgIDs != nil {
				require.NotNil(t, userinfo.HttpsunikornCloudOrgauthz.OrgIds)
				assert.ElementsMatch(t, tc.expectedOrgIDs, userinfo.HttpsunikornCloudOrgauthz.OrgIds)
			} else {
				assert.Nil(t, userinfo.HttpsunikornCloudOrgauthz.OrgIds)
			}

			if tc.postVerify != nil {
				tc.postVerify(t, ctx, client, authenticator, tokens)
			}
		})
	}
}

// TestUserinfoReadsUserOnce checks that userinfo for a federated token looks
// the user up once: verification already loads it to check the session, and
// the organization lookup reuses it.
func TestUserinfoReadsUserOnce(t *testing.T) {
	t.Parallel()

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      "fake",
		},
		Spec: unikornv1.UserSpec{
			Subject: "barry@foo.com",
			State:   unikornv1.UserStateActive,
		},
	}

	var userReads atomic.Int64

	counting := interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*unikornv1.User); ok {
				userReads.Add(1)
			}

			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*unikornv1.UserList); ok {
				userReads.Add(1)
			}

			return c.List(ctx, list, opts...)
		},
	}

	cli := fake.NewClientBuilder().WithScheme(getScheme(t)).WithObjects(user).WithInterceptorFuncs(counting).Build()

	josetesting.RotateCertificate(t, cli)

	issuer := jose.NewJWTIssuer(cli, josetesting.Namespace, &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	})

	ctx := t.Context()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	options := &oauth2.Options{
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
		TokenCacheSize:       16,
		CodeCacheSize:        16,
	}

	issuerVal := handlercommon.IssuerValue{URL: "https://foo.com", Hostname: "foo.com"}

	userDatabase := userdb.NewUserDatabase(cli, josetesting.Namespace)

	authenticator, err := oauth2.New(options, josetesting.Namespace, issuerVal, cli, cli, issuer,
		userDatabase, rbac.New(cli, josetesting.Namespace, &rbac.Options{}))
	require.NoError(t, err)

	time.Sleep(2 * josetesting.RefreshPeriod)

	tokens, err := authenticator.Issue(ctx, &oauth2.IssueInfo{
		Issuer:   "https://foo.com",
		Audience: "foo.com",
		Subject:  "barry@foo.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID:   "fake",
			ClientID: "client",
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://foo.com/oauth2/v2/userinfo", nil)

	// The first call decrypts the token and caches its claims.
	_, _, err = authenticator.GetUserinfo(ctx, req, tokens.AccessToken)
	require.NoError(t, err)

	// A lookup may take more than one read, so compare with what looking the
	// user up once costs.
	userReads.Store(0)

	_, err = userDatabase.GetActiveUser(ctx, "barry@foo.com")
	require.NoError(t, err)

	oneLookup := userReads.Load()
	require.Positive(t, oneLookup)

	userReads.Store(0)

	_, _, err = authenticator.GetUserinfo(ctx, req, tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, oneLookup, userReads.Load(), "userinfo should look the user up once")
}
