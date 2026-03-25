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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	// JWT claims have second accuracy, so use whole seconds as our time
	// basis.
	accessTokenDuration  = time.Second
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
		AccessTokenDuration:      accessTokenDuration,
		RefreshTokenDuration:     refreshTokenDuration,
		TokenLeewayDuration:      accessTokenDuration,
		TokenCacheSize:           1024,
		CodeCacheSize:            1024,
		AccountCreationCacheSize: 1024,
	}

	issuerVal := handlercommon.IssuerValue{
		URL:      "https://foo.com",
		Hostname: "foo.com",
	}

	authenticator := oauth2.New(options, josetesting.Namespace, issuerVal, client, issuer, userDatabase, rbac)

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

// TestUserinfoCustomClaims tests that tokens include correct custom authorization claims.
func TestUserinfoCustomClaims(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		objects        []client.Object
		issueInfo      *oauth2.IssueInfo
		postIssue      func(*testing.T, context.Context, client.Client, *oauth2.Tokens)
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
			expectedOrgIDs: nil,
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

			authenticator := oauth2.New(&oauth2.Options{
				AccessTokenDuration:      accessTokenDuration,
				RefreshTokenDuration:     refreshTokenDuration,
				TokenLeewayDuration:      accessTokenDuration,
				TokenCacheSize:           1024,
				CodeCacheSize:            1024,
				AccountCreationCacheSize: 1024,
			}, josetesting.Namespace, issuerHost, client, issuer, userDatabase, rbac)

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
		})
	}
}

// fakeSubjectTokenValidator is a test implementation of SubjectTokenValidator that
// returns a fixed subject for any token it receives.
type fakeSubjectTokenValidator struct {
	subject string
	err     error
}

func (f *fakeSubjectTokenValidator) Authenticate(_ *http.Request, _ string) (*authorization.Info, error) {
	if f.err != nil {
		return nil, f.err
	}

	return &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: f.subject,
		},
	}, nil
}

func TestTokenExchange(t *testing.T) {
	t.Parallel()

	const (
		testClientID     = "test-client"
		testClientSecret = "super-secret"
		testSubject      = "user@example.com"
		testUserID       = "test-user"
	)

	objects := []client.Object{
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      testUserID,
			},
			Spec: unikornv1.UserSpec{
				Subject: testSubject,
				State:   unikornv1.UserStateActive,
			},
		},
		&unikornv1.OAuth2Client{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      testClientID,
			},
			Spec: unikornv1.OAuth2ClientSpec{
				RedirectURI: "https://example.com/callback",
			},
			Status: unikornv1.OAuth2ClientStatus{
				Secret: testClientSecret,
			},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(getScheme(t)).WithObjects(objects...).Build()

	josetesting.RotateCertificate(t, k8sClient)

	issuer := jose.NewJWTIssuer(k8sClient, josetesting.Namespace, &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	})

	ctx := t.Context()
	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	userDatabase := userdb.NewUserDatabase(k8sClient, josetesting.Namespace)
	rbacInstance := rbac.New(k8sClient, josetesting.Namespace, &rbac.Options{})

	issuerVal := handlercommon.IssuerValue{
		URL:      "https://test.com",
		Hostname: "test.com",
	}

	authenticator := oauth2.New(&oauth2.Options{
		AccessTokenDuration:      accessTokenDuration,
		RefreshTokenDuration:     refreshTokenDuration,
		TokenLeewayDuration:      accessTokenDuration,
		TokenCacheSize:           1024,
		CodeCacheSize:            1024,
		AccountCreationCacheSize: 1024,
	}, josetesting.Namespace, issuerVal, k8sClient, issuer, userDatabase, rbacInstance)

	time.Sleep(2 * josetesting.RefreshPeriod)

	t.Run("successful exchange", func(t *testing.T) {
		t.Parallel()

		authenticator.SetSubjectTokenValidator(&fakeSubjectTokenValidator{subject: testSubject})

		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {"some-external-token"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}

		req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, testClientSecret)

		w := httptest.NewRecorder()

		token, err := authenticator.Token(w, req)
		require.NoError(t, err)
		require.NotNil(t, token)

		assert.Equal(t, "Bearer", token.TokenType)
		assert.NotEmpty(t, token.AccessToken)
		assert.GreaterOrEqual(t, token.ExpiresIn, 0)
		assert.NotNil(t, token.IssuedTokenType)
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", *token.IssuedTokenType)
	})

	t.Run("missing subject_token", func(t *testing.T) {
		t.Parallel()

		authenticator.SetSubjectTokenValidator(&fakeSubjectTokenValidator{subject: testSubject})

		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}

		req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, testClientSecret)

		w := httptest.NewRecorder()

		_, err := authenticator.Token(w, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject_token")
	})

	t.Run("missing client credentials", func(t *testing.T) {
		t.Parallel()

		authenticator.SetSubjectTokenValidator(&fakeSubjectTokenValidator{subject: testSubject})

		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {"some-external-token"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}

		req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()

		_, err := authenticator.Token(w, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client credentials")
	})

	t.Run("invalid client secret", func(t *testing.T) {
		t.Parallel()

		authenticator.SetSubjectTokenValidator(&fakeSubjectTokenValidator{subject: testSubject})

		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {"some-external-token"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}

		req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, "wrong-secret")

		w := httptest.NewRecorder()

		_, err := authenticator.Token(w, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client secret")
	})

	t.Run("unsupported subject_token_type", func(t *testing.T) {
		t.Parallel()

		authenticator.SetSubjectTokenValidator(&fakeSubjectTokenValidator{subject: testSubject})

		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {"some-external-token"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:saml2"},
		}

		req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, testClientSecret)

		w := httptest.NewRecorder()

		_, err := authenticator.Token(w, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported subject_token_type")
	})

	t.Run("token exchange not configured", func(t *testing.T) {
		t.Parallel()

		// Create a fresh authenticator without a validator.
		noExchangeAuth := oauth2.New(&oauth2.Options{
			AccessTokenDuration:      accessTokenDuration,
			RefreshTokenDuration:     refreshTokenDuration,
			TokenLeewayDuration:      accessTokenDuration,
			TokenCacheSize:           1024,
			CodeCacheSize:            1024,
			AccountCreationCacheSize: 1024,
		}, josetesting.Namespace, issuerVal, k8sClient, issuer, userDatabase, rbacInstance)

		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {"some-external-token"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}

		req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, testClientSecret)

		w := httptest.NewRecorder()

		_, err := noExchangeAuth.Token(w, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})
}
