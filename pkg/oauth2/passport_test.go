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
	"encoding/json"
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
	"github.com/unikorn-cloud/identity/pkg/handler"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func passportIssuedTokenType() string {
	return "urn:nscale:params:oauth:token-type:passport"
}

// passportTestEnv bundles the test dependencies needed to exercise the exchange endpoint.
type passportTestEnv struct {
	authenticator *oauth2.Authenticator
	jwtIssuer     *jose.JWTIssuer
	client        client.Client
}

func setupPassportTestEnv(t *testing.T, objects ...client.Object) *passportTestEnv {
	t.Helper()

	return setupPassportTestEnvWithRBACOptions(t, &rbac.Options{}, objects...)
}

func setupPassportTestEnvWithRBACOptions(t *testing.T, rbacOptions *rbac.Options, objects ...client.Object) *passportTestEnv {
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

	if rbacOptions == nil {
		rbacOptions = &rbac.Options{}
	}

	rbacInst := rbac.New(cli, josetesting.Namespace, rbacOptions)

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

func issueSystemToken(t *testing.T, env *passportTestEnv, subject string) string {
	t.Helper()

	return issueTestToken(t, env, &oauth2.IssueInfo{
		Issuer:   "https://test.com",
		Audience: "test.com",
		Subject:  subject,
		Type:     oauth2.TokenTypeService,
	})
}

func exchangeRequest(t *testing.T, token string, body *openapi.TokenRequestOptions) *http.Request {
	t.Helper()

	form := url.Values{
		"grant_type":         {string(openapi.UrnIetfParamsOauthGrantTypeTokenExchange)},
		"subject_token":      {token},
		"subject_token_type": {oauth2.AccessTokenSubjectTokenType()},
	}

	applyExchangeFormBody(form, body)

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

func applyExchangeFormBody(form url.Values, body *openapi.TokenRequestOptions) {
	if body == nil {
		return
	}

	for _, field := range []struct {
		name  string
		value *string
	}{
		{"requested_token_type", body.RequestedTokenType},
		{"audience", body.Audience},
		{"resource", body.Resource},
		{"x_organization_id", body.XOrganizationId},
		{"x_project_id", body.XProjectId},
	} {
		if field.value != nil {
			form.Set(field.name, *field.value)
		}
	}
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

	result, err := env.authenticator.TokenExchange(nil, req)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 120, result.ExpiresIn)
	assert.Equal(t, "Bearer", result.TokenType)
	require.NotNil(t, result.IssuedTokenType)
	assert.Equal(t, passportIssuedTokenType(), *result.IssuedTokenType)
	assert.NotEmpty(t, result.AccessToken)

	claims := parsePassport(t, env, result.AccessToken)

	assert.Equal(t, "passport", claims.Type)
	assert.Equal(t, "uni-identity", claims.Issuer)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, openapi.User, claims.Acctype)
	assert.Equal(t, "uni", claims.Source)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Nil(t, claims.Actor, "act claim must be omitted when subject is the acting party")
	assert.Empty(t, claims.Audience, "aud must be empty when no audience or resource was requested")
	assert.ElementsMatch(t, []string{"org1"}, claims.OrgIDs)

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
	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		XOrganizationId: &orgID,
		XProjectId:      &projectID,
	})

	result, err := env.authenticator.TokenExchange(nil, req)
	require.NoError(t, err)

	claims := parsePassport(t, env, result.AccessToken)

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
	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		XOrganizationId: &orgID,
		XProjectId:      &bogusProject,
	})

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project not in scope")
}

func TestExchangeInvalidOrganizationID(t *testing.T) {
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

	orgID := "org2"
	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		XOrganizationId: &orgID,
	})

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization not in scope")

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
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

	result, err := env.authenticator.TokenExchange(nil, req)
	require.NoError(t, err)

	claims := parsePassport(t, env, result.AccessToken)

	assert.Equal(t, "passport", claims.Type)
	assert.Equal(t, openapi.Service, claims.Acctype)
	assert.Equal(t, "test-sa", claims.Subject)
	assert.ElementsMatch(t, []string{"test-org"}, claims.OrgIDs)
}

func TestExchangeServiceAccountWrongOrganization(t *testing.T) {
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

	sa := &unikornv1.ServiceAccount{}
	require.NoError(t, env.client.Get(t.Context(), client.ObjectKey{
		Namespace: josetesting.Namespace + "-org",
		Name:      "test-sa",
	}, sa))

	sa.Spec.AccessToken = tokens.AccessToken
	require.NoError(t, env.client.Update(t.Context(), sa))

	wrongOrgID := "other-org"
	req := exchangeRequest(t, tokens.AccessToken, &openapi.TokenRequestOptions{
		XOrganizationId: &wrongOrgID,
	})

	_, err = env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization not in scope")

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
}

func TestExchangeSystemAccountWithOrganizationScope(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnvWithRBACOptions(t, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{
			"system-service": "role-super-service",
		},
	}, &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      "role-super-service",
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "org:read", Operations: []unikornv1.Operation{unikornv1.Read}},
					{Name: "project:read", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	})

	token := issueSystemToken(t, env, "system-service")

	orgID := "target-org"
	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		XOrganizationId: &orgID,
	})

	result, err := env.authenticator.TokenExchange(nil, req)
	require.NoError(t, err)
	require.NotNil(t, result)

	claims := parsePassport(t, env, result.AccessToken)

	assert.Equal(t, openapi.System, claims.Acctype)
	assert.Equal(t, "system-service", claims.Subject)
	assert.Empty(t, claims.OrgIDs)
	assert.Equal(t, orgID, claims.OrgID)
}

func TestExchangeSystemAccountWithOrganizationScopeStillUsesRBAC(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	token := issueSystemToken(t, env, "system-service")

	orgID := "target-org"
	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		XOrganizationId: &orgID,
	})

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "organization not in scope")
	assert.Contains(t, err.Error(), "system account 'system-service' not registered")
}

func TestExchangeMissingSubjectToken(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
		strings.NewReader(url.Values{
			"grant_type":         {string(openapi.UrnIetfParamsOauthGrantTypeTokenExchange)},
			"subject_token_type": {oauth2.AccessTokenSubjectTokenType()},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token must be specified")
}

func TestExchangeMissingSubjectTokenType(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
		strings.NewReader(url.Values{
			"grant_type":    {string(openapi.UrnIetfParamsOauthGrantTypeTokenExchange)},
			"subject_token": {"token-value"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_type must be specified")
}

func TestExchangeUnsupportedSubjectTokenType(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
		strings.NewReader(url.Values{
			"grant_type":         {string(openapi.UrnIetfParamsOauthGrantTypeTokenExchange)},
			"subject_token":      {"token-value"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject_token_type is not supported")
}

func TestExchangeInvalidToken(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	req := exchangeRequest(t, "invalid-token-value", nil)

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
	assert.Contains(t, err.Error(), "token validation failed")
}

func TestExchangeHandlerInvalidTokenReturnsUnauthorized(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	h, err := handler.New(nil, nil, "", env.jwtIssuer, env.authenticator, nil, nil, nil)
	require.NoError(t, err)

	req := exchangeRequest(t, "invalid-token-value", nil)
	recorder := httptest.NewRecorder()

	h.PostOauth2V2Token(recorder, req)

	resp := recorder.Result()

	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var oauthResp openapi.Oauth2Error

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&oauthResp))
	assert.Equal(t, openapi.AccessDenied, oauthResp.Error)
	assert.Contains(t, oauthResp.ErrorDescription, "token validation failed")
}

func TestExchangeHandlerSuccess(t *testing.T) {
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

	h, err := handler.New(nil, nil, "", env.jwtIssuer, env.authenticator, nil, nil, nil)
	require.NoError(t, err)

	req := exchangeRequest(t, token, nil)
	recorder := httptest.NewRecorder()

	h.PostOauth2V2Token(recorder, req)

	resp := recorder.Result()

	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Cache-Control"), "no-store")

	var result openapi.Token

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.NotEmpty(t, result.AccessToken)
	assert.Equal(t, 120, result.ExpiresIn)
	assert.Equal(t, "Bearer", result.TokenType)
	require.NotNil(t, result.IssuedTokenType)
	assert.Equal(t, passportIssuedTokenType(), *result.IssuedTokenType)
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

	// Invalid percent-encoding triggers a ParseForm error.
	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
		strings.NewReader("organizationId=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := env.authenticator.TokenExchange(nil, req)
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

	result, err := env.authenticator.TokenExchange(nil, req)
	require.NoError(t, err)

	// Verify the passport is a valid JWS with ES512.
	parsed, err := jwt.ParseSigned(result.AccessToken, []gojose.SignatureAlgorithm{gojose.ES512})
	require.NoError(t, err)
	assert.Len(t, parsed.Headers, 1)
	assert.Equal(t, string(gojose.ES512), parsed.Headers[0].Algorithm)
}

func TestExchangeWithAudienceAndResource(t *testing.T) {
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

	audience := "compute-api"
	resource := "https://compute.example.com/"

	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		Audience: &audience,
		Resource: &resource,
	})

	result, err := env.authenticator.TokenExchange(nil, req)
	require.NoError(t, err)

	claims := parsePassport(t, env, result.AccessToken)

	assert.ElementsMatch(t, []string{audience, resource}, []string(claims.Audience))
}

func TestExchangeRejectsInvalidResourceURI(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	bogus := "not-a-uri"

	req := exchangeRequest(t, "irrelevant", &openapi.TokenRequestOptions{
		Resource: &bogus,
	})

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absolute URI")

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
}

func TestExchangeAcceptsRegisteredAccessTokenRequestedType(t *testing.T) {
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

	requestedType := oauth2.AccessTokenSubjectTokenType()

	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		RequestedTokenType: &requestedType,
	})

	result, err := env.authenticator.TokenExchange(nil, req)
	require.NoError(t, err)
	require.NotNil(t, result.IssuedTokenType)
	assert.Equal(t, passportIssuedTokenType(), *result.IssuedTokenType)
}

func TestExchangeRejectsActorToken(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	form := url.Values{
		"grant_type":         {string(openapi.UrnIetfParamsOauthGrantTypeTokenExchange)},
		"subject_token":      {"some-subject-token"},
		"subject_token_type": {oauth2.AccessTokenSubjectTokenType()},
		"actor_token":        {"some-actor-token"},
		"actor_token_type":   {oauth2.AccessTokenSubjectTokenType()},
	}

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor_token is not supported")

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
}

func TestExchangeRejectsNonFormContentType(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
		strings.NewReader(`{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange"}`))
	req.Header.Set("Content-Type", "application/json")

	_, err := env.authenticator.TokenExchange(nil, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Content-Type must be application/x-www-form-urlencoded")

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
}

func TestExchangeHandlerOutOfScopeOrganizationReturnsInvalidTarget(t *testing.T) {
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

	h, err := handler.New(nil, nil, "", env.jwtIssuer, env.authenticator, nil, nil, nil)
	require.NoError(t, err)

	wrongOrgID := "not-my-org"
	req := exchangeRequest(t, token, &openapi.TokenRequestOptions{
		XOrganizationId: &wrongOrgID,
	})
	recorder := httptest.NewRecorder()

	h.PostOauth2V2Token(recorder, req)

	resp := recorder.Result()

	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var oauthResp openapi.Oauth2Error

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&oauthResp))
	assert.Equal(t, openapi.InvalidTarget, oauthResp.Error)
	assert.Contains(t, oauthResp.ErrorDescription, "organization not in scope")
}
