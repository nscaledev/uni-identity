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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// passportTestEnv bundles the test dependencies needed to exercise the exchange endpoint.
type passportTestEnv struct {
	authenticator *oauth2.Authenticator
	jwtIssuer     *jose.JWTIssuer
	client        client.Client
}

func setupPassportTestEnv(t *testing.T, objects ...client.Object) *passportTestEnv {
	t.Helper()

	cli := fake.NewClientBuilder().WithScheme(getScheme(t)).WithObjects(objects...).Build()

	josetesting.RotateCertificate(t, cli)

	jwtIssuer := jose.NewJWTIssuer(cli, josetesting.Namespace, &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	})

	ctx := t.Context()
	require.NoError(t, jwtIssuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	userDatabase := userdb.NewUserDatabase(cli, josetesting.Namespace)
	rbacInst := rbac.New(cli, josetesting.Namespace, &rbac.Options{})

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
	}, josetesting.Namespace, issuerVal, cli, jwtIssuer, userDatabase, rbacInst)

	time.Sleep(2 * josetesting.RefreshPeriod)

	return &passportTestEnv{
		authenticator: authenticator,
		jwtIssuer:     jwtIssuer,
		client:        cli,
	}
}

func issueTestToken(t *testing.T, env *passportTestEnv, info *oauth2.IssueInfo) string {
	t.Helper()

	tokens, err := env.authenticator.Issue(t.Context(), info)
	require.NoError(t, err)

	return tokens.AccessToken
}

func exchangeRequest(t *testing.T, token string, body *openapi.ExchangeRequestOptions) *http.Request {
	t.Helper()

	form := url.Values{}

	if body != nil {
		if body.OrganizationId != nil {
			form.Set("organizationId", *body.OrganizationId)
		}

		if body.ProjectId != nil {
			form.Set("projectId", *body.ProjectId)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/exchange",
		strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

// parsePassport parses and verifies a passport JWT using the test JWKS.
func parsePassport(t *testing.T, env *passportTestEnv, passportToken string) *oauth2.PassportClaims {
	t.Helper()

	claims := &oauth2.PassportClaims{}
	require.NoError(t, env.jwtIssuer.DecodeJWT(t.Context(), passportToken, claims))

	return claims
}

func TestExchangeFederatedUser(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t,
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "org1",
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: josetesting.Namespace + "-org1",
			},
		},
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
	)

	token := issueTestToken(t, env, &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  "user@example.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID: "test-user",
			Scope:  oauth2.NewScope("openid email"),
		},
	})

	req := exchangeRequest(t, token, nil)

	result, err := env.authenticator.Exchange(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 120, result.ExpiresIn)
	assert.NotEmpty(t, result.Passport)

	claims := parsePassport(t, env, result.Passport)

	assert.Equal(t, "passport", claims.Type)
	assert.Equal(t, "uni-identity", claims.Issuer)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, openapi.User, claims.Acctype)
	assert.Equal(t, "uni", claims.Source)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, "user@example.com", claims.Actor)
	assert.ElementsMatch(t, []string{"org1"}, claims.OrgIDs)
	assert.NotNil(t, claims.ACL)

	// Verify timing: exp should be iat + 120s.
	assert.Equal(t, claims.IssuedAt.Time().Add(oauth2.PassportTTL), claims.Expiry.Time())
}

func TestExchangeWithOrgScope(t *testing.T) {
	t.Parallel()

	orgNamespace := josetesting.Namespace + "-org1"

	env := setupPassportTestEnv(t,
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "org1",
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: orgNamespace,
			},
		},
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
		&unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "test-role",
			},
			Spec: unikornv1.RoleSpec{
				Scopes: unikornv1.RoleScopes{
					Project: []unikornv1.RoleScope{
						{Name: "compute", Operations: []unikornv1.Operation{unikornv1.Read}},
					},
				},
			},
		},
		&unikornv1.Group{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: orgNamespace,
				Name:      "test-group",
			},
			Spec: unikornv1.GroupSpec{
				Subjects: []unikornv1.GroupSubject{
					{ID: "user@example.com"},
				},
				RoleIDs: []string{"test-role"},
			},
		},
		&unikornv1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: orgNamespace,
				Name:      "project1",
				Labels: map[string]string{
					constants.OrganizationLabel: "org1",
				},
			},
			Spec: unikornv1.ProjectSpec{
				GroupIDs: []string{"test-group"},
			},
		},
	)

	token := issueTestToken(t, env, &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  "user@example.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID: "test-user",
			Scope:  oauth2.NewScope("openid email"),
		},
	})

	orgID := "org1"
	projectID := "project1"
	req := exchangeRequest(t, token, &openapi.ExchangeRequestOptions{
		OrganizationId: &orgID,
		ProjectId:      &projectID,
	})

	result, err := env.authenticator.Exchange(t.Context(), req)
	require.NoError(t, err)

	claims := parsePassport(t, env, result.Passport)

	assert.Equal(t, "org1", claims.OrgID)
	assert.Equal(t, "project1", claims.ProjectID)
}

func TestExchangeInvalidProjectID(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t,
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "org1",
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: josetesting.Namespace + "-org1",
			},
		},
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
	)

	token := issueTestToken(t, env, &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  "user@example.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID: "test-user",
			Scope:  oauth2.NewScope("openid email"),
		},
	})

	orgID := "org1"
	bogusProject := "nonexistent-project"
	req := exchangeRequest(t, token, &openapi.ExchangeRequestOptions{
		OrganizationId: &orgID,
		ProjectId:      &bogusProject,
	})

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project not in scope")
}

func TestExchangeServiceAccount(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t,
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
				Name:      "test-sa",
			},
			Spec: unikornv1.ServiceAccountSpec{},
		},
	)

	info := &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  "test-sa",
		Type:     oauth2.TokenTypeServiceAccount,
		ServiceAccount: &oauth2.ServiceAccountClaims{
			OrganizationID: "test-org",
		},
	}

	tokens, err := env.authenticator.Issue(t.Context(), info)
	require.NoError(t, err)

	// Service accounts need the access token stored on the CRD for verification.
	sa := &unikornv1.ServiceAccount{}
	require.NoError(t, env.client.Get(t.Context(), client.ObjectKey{
		Namespace: josetesting.Namespace + "-org",
		Name:      "test-sa",
	}, sa))

	sa.Spec.AccessToken = tokens.AccessToken
	require.NoError(t, env.client.Update(t.Context(), sa))

	req := exchangeRequest(t, tokens.AccessToken, nil)

	result, err := env.authenticator.Exchange(t.Context(), req)
	require.NoError(t, err)

	claims := parsePassport(t, env, result.Passport)

	assert.Equal(t, "passport", claims.Type)
	assert.Equal(t, openapi.Service, claims.Acctype)
	assert.Equal(t, "test-sa", claims.Subject)
	assert.ElementsMatch(t, []string{"test-org"}, claims.OrgIDs)
}

func TestExchangeMissingAuthHeader(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/exchange", nil)

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization header not set")
}

func TestExchangeInvalidToken(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	req := exchangeRequest(t, "invalid-token-value", nil)

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)
}

func TestExchangeMalformedBody(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t,
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
	)

	token := issueTestToken(t, env, &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  "user@example.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID: "test-user",
			Scope:  oauth2.NewScope("openid email"),
		},
	})

	// Invalid percent-encoding triggers a ParseForm error.
	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/exchange",
		strings.NewReader("organizationId=%zz"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse form data")
}

func TestPassportSignatureVerifiesAgainstJWKS(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t,
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
	)
	// No org needed — federated user with no orgs still gets a valid passport.

	token := issueTestToken(t, env, &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  "user@example.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID: "test-user",
			Scope:  oauth2.NewScope("openid email"),
		},
	})

	req := exchangeRequest(t, token, nil)

	result, err := env.authenticator.Exchange(t.Context(), req)
	require.NoError(t, err)

	// Verify the passport is a valid JWS with ES512.
	parsed, err := jwt.ParseSigned(result.Passport, []gojose.SignatureAlgorithm{gojose.ES512})
	require.NoError(t, err)
	assert.Len(t, parsed.Headers, 1)
	assert.Equal(t, string(gojose.ES512), parsed.Headers[0].Algorithm)
}
