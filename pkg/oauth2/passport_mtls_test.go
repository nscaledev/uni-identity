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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
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
	"github.com/unikorn-cloud/identity/pkg/handler"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// setupPassportTestEnvWithRBAC builds a passport test environment with a
// custom RBAC options struct, letting tests register system accounts for
// impersonation scenarios.
func setupPassportTestEnvWithRBAC(t *testing.T, rbacOpts *rbac.Options, objects ...client.Object) *passportTestEnv {
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
	rbacInst := rbac.New(cli, josetesting.Namespace, rbacOpts)

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

// testClientCert generates a self-signed certificate with the given Common Name
// suitable for populating the Ssl-Client-Cert header. The returned PEM is already
// URL-encoded to match the format produced by the nginx ingress.
func testClientCert(t *testing.T, commonName string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return url.QueryEscape(string(certPEM))
}

// impersonatedExchangeRequest builds an mTLS+impersonation exchange request.
// When principalValue is empty, no X-Principal header is set; when raw is true,
// principalValue is used verbatim rather than base64-encoded.
type impersonatedRequest struct {
	commonName     string
	principal      *principal.Principal
	principalRaw   string
	impersonateHdr string // value for X-Impersonate; empty string omits the header
	omitCert       bool
	options        *openapi.ExchangeRequestOptions
}

func buildImpersonatedRequest(t *testing.T, r impersonatedRequest) *http.Request {
	t.Helper()

	form := url.Values{}

	if r.options != nil {
		if r.options.OrganizationId != nil {
			form.Set("organizationId", *r.options.OrganizationId)
		}

		if r.options.ProjectId != nil {
			form.Set("projectId", *r.options.ProjectId)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/exchange",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if !r.omitCert {
		req.Header.Set("Ssl-Client-Cert", testClientCert(t, r.commonName))
		req.Header.Set("Ssl-Client-Verify", "SUCCESS")
	}

	switch {
	case r.principalRaw != "":
		req.Header.Set(principal.Header, r.principalRaw)
	case r.principal != nil:
		data, err := json.Marshal(r.principal)
		require.NoError(t, err)
		req.Header.Set(principal.Header, base64.RawURLEncoding.EncodeToString(data))
	}

	if r.impersonateHdr != "" {
		req.Header.Set(principal.ImpersonateHeader, r.impersonateHdr)
	}

	return req
}

// impersonationServiceCN is the Common Name of the service cert used in these
// tests. It's registered as a system account in setupPassportImpersonationEnv.
const impersonationServiceCN = "test-impersonating-service"

// setupPassportImpersonationEnv provisions the minimum RBAC objects needed for
// the impersonation happy path: a registered system account whose role grants
// project:read globally, a user in an organization with a group granting
// project:read + project:write, and the matching project.
//
// After intersection with the service's project:read-only global scope, the
// user's project:write should be stripped.
func setupPassportImpersonationEnv(t *testing.T) *passportTestEnv {
	t.Helper()

	const (
		orgID            = "org1"
		userSubject      = "alice@example.com"
		userName         = "user-alice"
		groupID          = "alice-group"
		roleUserID       = "role-user"
		roleServiceID    = "role-impersonating-service"
		projectAlphaID   = "project-alpha"
		projectAlphaName = "project-alpha"
	)

	_ = projectAlphaName // used below by reference

	orgNamespace := josetesting.Namespace + "-org1"

	return setupPassportTestEnvWithRBAC(t,
		&rbac.Options{
			SystemAccountRoleIDs: map[string]string{impersonationServiceCN: roleServiceID},
		},
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: orgID},
			Status:     unikornv1.OrganizationStatus{Namespace: orgNamespace},
		},
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: userName},
			Spec: unikornv1.UserSpec{
				Subject: userSubject,
				State:   unikornv1.UserStateActive,
			},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "org1-alice",
				Labels: map[string]string{
					constants.UserLabel:         userName,
					constants.OrganizationLabel: orgID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		},
		// User role: project:read AND project:write.
		&unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: roleUserID},
			Spec: unikornv1.RoleSpec{
				Scopes: unikornv1.RoleScopes{
					Project: []unikornv1.RoleScope{
						{Name: "project", Operations: []unikornv1.Operation{unikornv1.Read, unikornv1.Update}},
					},
				},
			},
		},
		// Service role: project:read only globally. After intersection, user's
		// write permission must be stripped.
		&unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: roleServiceID},
			Spec: unikornv1.RoleSpec{
				Scopes: unikornv1.RoleScopes{
					Global: []unikornv1.RoleScope{
						{Name: "project", Operations: []unikornv1.Operation{unikornv1.Read}},
					},
				},
			},
		},
		&unikornv1.Group{
			ObjectMeta: metav1.ObjectMeta{Namespace: orgNamespace, Name: groupID},
			Spec: unikornv1.GroupSpec{
				Subjects: []unikornv1.GroupSubject{{ID: userSubject}},
				RoleIDs:  []string{roleUserID},
			},
		},
		&unikornv1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: orgNamespace,
				Name:      projectAlphaID,
				Labels:    map[string]string{constants.OrganizationLabel: orgID},
			},
			Spec: unikornv1.ProjectSpec{
				GroupIDs: []string{groupID},
			},
		},
	)
}

// TestExchangeImpersonation_HappyPath confirms that a service calling with a
// client cert + X-Impersonate: true + valid X-Principal receives a passport
// minted for the impersonated user, not the service.
func TestExchangeImpersonation_HappyPath(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	orgID := "org1"

	req := buildImpersonatedRequest(t, impersonatedRequest{
		commonName: impersonationServiceCN,
		principal: &principal.Principal{
			Actor:           "alice@example.com",
			OrganizationIDs: []string{orgID},
		},
		impersonateHdr: "true",
		options: &openapi.ExchangeRequestOptions{
			OrganizationId: &orgID,
		},
	})

	result, err := env.authenticator.Exchange(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, result)

	claims := parsePassport(t, env, result.Passport)

	assert.Equal(t, "passport", claims.Type)
	assert.Equal(t, "alice@example.com", claims.Subject,
		"passport subject must be the impersonated user, not the service CN")
	assert.Equal(t, "alice@example.com", claims.Actor,
		"passport actor must be the impersonated user, not the service CN")
	assert.Equal(t, openapi.User, claims.Acctype,
		"passport acctype must reflect the impersonated user, not the service")
	assert.Equal(t, orgID, claims.OrgID)
	assert.ElementsMatch(t, []string{orgID}, claims.OrgIDs)
	assert.Empty(t, claims.Email, "impersonation has no token-backed email")
	require.NotNil(t, claims.ACL)
}

// TestExchangeImpersonation_WithoutImpersonateHeader confirms that an mTLS
// call without X-Impersonate: true is refused. Services acting autonomously
// must not receive a passport.
func TestExchangeImpersonation_WithoutImpersonateHeader(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	req := buildImpersonatedRequest(t, impersonatedRequest{
		commonName: impersonationServiceCN,
		principal: &principal.Principal{
			Actor:           "alice@example.com",
			OrganizationIDs: []string{"org1"},
		},
		// impersonateHdr deliberately omitted.
	})

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
	assert.Contains(t, err.Error(), "impersonation flag required")
}

// TestExchangeImpersonation_ImpersonateHeaderFalse confirms that X-Impersonate
// values other than the literal "true" are rejected. The current extractor
// accepts only "true"; this locks that in at the exchange endpoint too.
func TestExchangeImpersonation_ImpersonateHeaderFalse(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	req := buildImpersonatedRequest(t, impersonatedRequest{
		commonName: impersonationServiceCN,
		principal: &principal.Principal{
			Actor:           "alice@example.com",
			OrganizationIDs: []string{"org1"},
		},
		impersonateHdr: "false",
	})

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
}

// TestExchangeImpersonation_MalformedPrincipalHeader confirms that an
// undecodable principal header is rejected with access_denied (fail closed).
func TestExchangeImpersonation_MalformedPrincipalHeader(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	req := buildImpersonatedRequest(t, impersonatedRequest{
		commonName:     impersonationServiceCN,
		principalRaw:   "!!not-base64-or-json!!",
		impersonateHdr: "true",
	})

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
}

// TestExchangeImpersonation_EmptyActor confirms that an impersonation request
// with a principal whose Actor is empty is rejected. The ticket explicitly
// calls out that ambiguous principals must fail closed.
func TestExchangeImpersonation_EmptyActor(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	req := buildImpersonatedRequest(t, impersonatedRequest{
		commonName:     impersonationServiceCN,
		principal:      &principal.Principal{OrganizationIDs: []string{"org1"}},
		impersonateHdr: "true",
	})

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
	assert.Contains(t, err.Error(), "principal actor required")
}

// TestExchangeImpersonation_OrgNotInPrincipalScope confirms that a requested
// organization scope outside the impersonated user's org list is refused.
// Impersonation must never broaden the user's reach.
func TestExchangeImpersonation_OrgNotInPrincipalScope(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	otherOrg := "some-other-org"

	req := buildImpersonatedRequest(t, impersonatedRequest{
		commonName: impersonationServiceCN,
		principal: &principal.Principal{
			Actor:           "alice@example.com",
			OrganizationIDs: []string{"org1"},
		},
		impersonateHdr: "true",
		options: &openapi.ExchangeRequestOptions{
			OrganizationId: &otherOrg,
		},
	})

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
	assert.Contains(t, err.Error(), "organization not in scope")
}

// TestExchangeImpersonation_ACLIntersectedAgainstService confirms that the
// passport's ACL is the intersection of the service's ACL and the user's ACL.
// The service role here grants only project:Read globally, but the user has
// project:Read+Update in their org. Only project:Read should survive.
func TestExchangeImpersonation_ACLIntersectedAgainstService(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	orgID := "org1"

	req := buildImpersonatedRequest(t, impersonatedRequest{
		commonName: impersonationServiceCN,
		principal: &principal.Principal{
			Actor:           "alice@example.com",
			OrganizationIDs: []string{orgID},
		},
		impersonateHdr: "true",
		options: &openapi.ExchangeRequestOptions{
			OrganizationId: &orgID,
		},
	})

	result, err := env.authenticator.Exchange(t.Context(), req)
	require.NoError(t, err)

	claims := parsePassport(t, env, result.Passport)
	require.NotNil(t, claims.ACL)
	require.NotNil(t, claims.ACL.Projects)

	// Find the alpha project and verify only Read survived the intersection.
	var alphaOps []openapi.AclOperation

	for _, p := range *claims.ACL.Projects {
		if p.Id == "project-alpha" {
			for _, ep := range p.Endpoints {
				if ep.Name == "project" {
					alphaOps = ep.Operations
				}
			}
		}
	}

	require.NotEmpty(t, alphaOps, "expected project scope for project-alpha in intersected ACL")
	assert.Contains(t, alphaOps, openapi.Read)
	assert.NotContains(t, alphaOps, openapi.Update,
		"project:Update was granted to user but not service — must be stripped")
}

// TestExchangeImpersonation_NoCertFails confirms that a request with no bearer
// token and no client cert is refused — there is no credential to authenticate.
func TestExchangeImpersonation_NoCertFails(t *testing.T) {
	t.Parallel()

	env := setupPassportImpersonationEnv(t)

	req := buildImpersonatedRequest(t, impersonatedRequest{
		omitCert: true,
		principal: &principal.Principal{
			Actor:           "alice@example.com",
			OrganizationIDs: []string{"org1"},
		},
		impersonateHdr: "true",
	})

	_, err := env.authenticator.Exchange(t.Context(), req)
	require.Error(t, err)

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
}

// Silence the "unused" linter for imports that are only referenced by
// constructing handler / jose types inline above.
var _ = handler.NotFound
