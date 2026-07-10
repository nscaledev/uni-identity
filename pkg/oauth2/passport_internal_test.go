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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const passportTestNamespace = "passport-test"

var errPassportInternalBoom = goerrors.New("boom")

func getPassportInternalScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	return s
}

func newPassportInternalAuthenticator(t *testing.T, objects ...client.Object) *Authenticator {
	t.Helper()

	cli := fake.NewClientBuilder().WithScheme(getPassportInternalScheme(t)).WithObjects(objects...).Build()

	return &Authenticator{
		client:    cli,
		namespace: passportTestNamespace,
	}
}

func TestRequestedScope(t *testing.T) {
	t.Parallel()

	orgID := "org-1"
	projectID := "project-1"

	testCases := []struct {
		name         string
		options      *openapi.TokenRequestOptions
		expectedOrg  string
		expectedProj string
	}{
		{
			name:    "nil options",
			options: nil,
		},
		{
			name: "organization only",
			options: &openapi.TokenRequestOptions{
				XOrganizationId: &orgID,
			},
			expectedOrg: orgID,
		},
		{
			name: "organization and project",
			options: &openapi.TokenRequestOptions{
				XOrganizationId: &orgID,
				XProjectId:      &projectID,
			},
			expectedOrg:  orgID,
			expectedProj: projectID,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actualOrg, actualProject := requestedScope(test.options)
			assert.Equal(t, test.expectedOrg, actualOrg)
			assert.Equal(t, test.expectedProj, actualProject)
		})
	}
}

func TestValidateOrganizationScope(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		authz          *openapi.AuthClaims
		organizationID string
		expectError    string
	}{
		{
			name:           "empty organization scope is always allowed",
			authz:          nil,
			organizationID: "",
		},
		{
			name:           "nil authz fails closed",
			authz:          nil,
			organizationID: "org-1",
			expectError:    "organization not in scope",
		},
		{
			name: "user in organization succeeds",
			authz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  []string{"org-1"},
			},
			organizationID: "org-1",
		},
		{
			name: "user outside organization defers to rbac",
			authz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  []string{"org-2"},
			},
			organizationID: "org-1",
		},
		{
			name: "service account outside organization is denied",
			authz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  []string{"org-2"},
			},
			organizationID: "org-1",
			expectError:    "organization not in scope",
		},
		{
			name: "system account defers organization authorization to rbac",
			authz: &openapi.AuthClaims{
				Acctype: openapi.System,
			},
			organizationID: "org-1",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateOrganizationScope(test.authz, test.organizationID)

			if test.expectError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.expectError)
		})
	}
}

func TestNormalizeExchangeUserinfoError(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/oauth2/v2/token", nil)
	oauthErr := oauth2errors.OAuth2AccessDenied("token validation failed")
	coreErr := coreerrors.AccessDenied(req, "token validation failed")

	testCases := []struct {
		name string
		err  error
		test func(t *testing.T, err error)
	}{
		{
			name: "oauth2 error is preserved",
			err:  oauthErr,
			test: func(t *testing.T, err error) {
				t.Helper()

				assert.Same(t, oauthErr, err)
			},
		},
		{
			name: "core access denied is normalized",
			err:  coreErr,
			test: func(t *testing.T, err error) {
				t.Helper()

				var normalized *oauth2errors.Error
				require.ErrorAs(t, err, &normalized)
				assert.Equal(t, "token validation failed", normalized.Error())
			},
		},
		{
			name: "other errors are preserved",
			err:  errPassportInternalBoom,
			test: func(t *testing.T, err error) {
				t.Helper()

				assert.Same(t, errPassportInternalBoom, err)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			test.test(t, normalizeExchangeUserinfoError(test.err))
		})
	}
}

func TestHasBroaderScope(t *testing.T) {
	t.Parallel()

	globalACL := &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
		},
	}
	orgACL := &openapi.Acl{
		Organization: &openapi.AclOrganization{
			Id: "org-1",
			Endpoints: &openapi.AclEndpoints{
				{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
			},
		},
	}

	assert.False(t, hasBroaderScope(nil, "org-1"))
	assert.True(t, hasBroaderScope(globalACL, "org-1"))
	assert.True(t, hasBroaderScope(orgACL, "org-1"))
	assert.False(t, hasBroaderScope(orgACL, "org-2"))
	assert.False(t, hasBroaderScope(orgACL, ""))
}

func TestValidateProjectScopeRequiresOrganization(t *testing.T) {
	t.Parallel()

	authenticator := newPassportInternalAuthenticator(t)
	acl := &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "project:read", Operations: openapi.AclOperations{openapi.Read}},
		},
	}

	err := authenticator.validateProjectScope(t.Context(), acl, "", "project-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x_organization_id must be specified")

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, openapi.InvalidRequest, oauthErr.Code())
}

func TestProjectInOrganization(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		objects      []client.Object
		organization string
		project      string
		expected     bool
	}{
		{
			name:         "organization missing",
			organization: "org-1",
			project:      "project-1",
			expected:     false,
		},
		{
			name: "organization has no namespace",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
				},
			},
			organization: "org-1",
			project:      "project-1",
			expected:     false,
		},
		{
			name: "project missing",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
					Status: unikornv1.OrganizationStatus{
						Namespace: "org-1-ns",
					},
				},
			},
			organization: "org-1",
			project:      "project-1",
			expected:     false,
		},
		{
			name: "project found",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
					Status: unikornv1.OrganizationStatus{
						Namespace: "org-1-ns",
					},
				},
				&unikornv1.Project{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "org-1-ns",
						Name:      "project-1",
						Labels: map[string]string{
							constants.OrganizationLabel: "org-1",
						},
					},
				},
			},
			organization: "org-1",
			project:      "project-1",
			expected:     true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authenticator := newPassportInternalAuthenticator(t, test.objects...)
			ok, err := authenticator.projectInOrganization(t.Context(), test.organization, test.project)
			require.NoError(t, err)
			assert.Equal(t, test.expected, ok)
		})
	}
}

func TestValidateProjectScopeWithBroaderGrant(t *testing.T) {
	t.Parallel()

	authenticator := newPassportInternalAuthenticator(t,
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: passportTestNamespace,
				Name:      "org-1",
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: "org-1-ns",
			},
		},
		&unikornv1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "org-1-ns",
				Name:      "project-1",
				Labels: map[string]string{
					constants.OrganizationLabel: "org-1",
				},
			},
		},
	)

	acl := &openapi.Acl{
		Organization: &openapi.AclOrganization{
			Id: "org-1",
			Endpoints: &openapi.AclEndpoints{
				{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
			},
		},
	}

	require.NoError(t, authenticator.validateProjectScope(t.Context(), acl, "org-1", "project-1"))

	err := authenticator.validateProjectScope(t.Context(), acl, "org-1", "project-2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project not in scope")
}

func TestValidateProjectScopeChecksExplicitProjectMembership(t *testing.T) {
	t.Parallel()

	authenticator := newPassportInternalAuthenticator(t,
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: passportTestNamespace,
				Name:      "org-1",
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: "org-1-ns",
			},
		},
		&unikornv1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "org-1-ns",
				Name:      "project-1",
				Labels: map[string]string{
					constants.OrganizationLabel: "org-1",
				},
			},
		},
	)

	acl := &openapi.Acl{
		Projects: &openapi.AclProjectList{
			{
				Id: "project-1",
				Endpoints: openapi.AclEndpoints{
					{Name: "project:read", Operations: openapi.AclOperations{openapi.Read}},
				},
			},
		},
	}

	require.NoError(t, authenticator.validateProjectScope(t.Context(), acl, "org-1", "project-1"))

	err := authenticator.validateProjectScope(t.Context(), acl, "org-2", "project-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project not in scope")
}

func TestValidateProjectScopeK8sFailure(t *testing.T) {
	t.Parallel()

	acl := &openapi.Acl{
		Organization: &openapi.AclOrganization{
			Id: "org-1",
			Endpoints: &openapi.AclEndpoints{
				{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
			},
		},
	}

	testCases := []struct {
		name    string
		objects []client.Object
		get     func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
	}{
		{
			name: "organization lookup fails",
			get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*unikornv1.Organization); ok {
					return errPassportInternalBoom
				}

				return inner.Get(ctx, key, obj, opts...)
			},
		},
		{
			name: "project lookup fails",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
					Status: unikornv1.OrganizationStatus{
						Namespace: "org-1-ns",
					},
				},
			},
			get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*unikornv1.Project); ok {
					return errPassportInternalBoom
				}

				return inner.Get(ctx, key, obj, opts...)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cli := fake.NewClientBuilder().
				WithScheme(getPassportInternalScheme(t)).
				WithObjects(test.objects...).
				WithInterceptorFuncs(interceptor.Funcs{Get: test.get}).
				Build()

			authenticator := &Authenticator{
				client:    cli,
				namespace: passportTestNamespace,
			}

			err := authenticator.validateProjectScope(t.Context(), acl, "org-1", "project-1")
			require.Error(t, err)
			require.ErrorIs(t, err, errPassportInternalBoom)
			assert.Contains(t, err.Error(), "failed to verify project membership")
		})
	}
}

func TestRequestedAudience(t *testing.T) {
	t.Parallel()

	logical := "compute-api"
	resource := "https://compute.example.com/"
	dupResource := "https://compute.example.com/"
	relativeResource := "/foo"
	fragmentResource := "https://compute.example.com/#fragment"

	testCases := []struct {
		name        string
		options     *openapi.TokenRequestOptions
		expected    jwt.Audience
		expectError bool
	}{
		{
			name: "no options yields no audience",
		},
		{
			name:     "audience only",
			options:  &openapi.TokenRequestOptions{Audience: &logical},
			expected: jwt.Audience{logical},
		},
		{
			name:     "resource only",
			options:  &openapi.TokenRequestOptions{Resource: &resource},
			expected: jwt.Audience{resource},
		},
		{
			name: "resource and matching audience deduplicates",
			options: &openapi.TokenRequestOptions{
				Resource: &resource,
				Audience: &dupResource,
			},
			expected: jwt.Audience{resource},
		},
		{
			name: "resource and distinct audience are both included",
			options: &openapi.TokenRequestOptions{
				Resource: &resource,
				Audience: &logical,
			},
			expected: jwt.Audience{resource, logical},
		},
		{
			name:        "relative resource is rejected",
			options:     &openapi.TokenRequestOptions{Resource: &relativeResource},
			expectError: true,
		},
		{
			name:        "resource with fragment is rejected",
			options:     &openapi.TokenRequestOptions{Resource: &fragmentResource},
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			audience, err := requestedAudience(test.options)

			if test.expectError {
				require.Error(t, err)

				var oauthErr *oauth2errors.Error

				require.ErrorAs(t, err, &oauthErr)
				assert.Contains(t, err.Error(), "absolute URI")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expected, audience)
		})
	}
}

func TestValidateTokenExchangeRequest(t *testing.T) {
	t.Parallel()

	subject := "subject-token-value"
	accessTokenType := AccessTokenSubjectTokenType()
	passportType := PassportIssuedTokenType()
	idTokenType := "urn:ietf:params:oauth:token-type:id_token" //nolint:gosec // token type identifier, not a credential
	empty := ""

	testCases := []struct {
		name        string
		options     *openapi.TokenRequestOptions
		expectError string
	}{
		{
			name:        "nil options",
			options:     nil,
			expectError: "token exchange request not parsed",
		},
		{
			name: "missing subject_token",
			options: &openapi.TokenRequestOptions{
				SubjectTokenType: &accessTokenType,
			},
			expectError: "subject_token must be specified",
		},
		{
			name: "empty subject_token",
			options: &openapi.TokenRequestOptions{
				SubjectToken:     &empty,
				SubjectTokenType: &accessTokenType,
			},
			expectError: "subject_token must be specified",
		},
		{
			name: "missing subject_token_type",
			options: &openapi.TokenRequestOptions{
				SubjectToken: &subject,
			},
			expectError: "subject_token_type must be specified",
		},
		{
			name: "unsupported subject_token_type",
			options: &openapi.TokenRequestOptions{
				SubjectToken:     &subject,
				SubjectTokenType: &idTokenType,
			},
			expectError: "subject_token_type is not supported",
		},
		{
			name: "passport requested_token_type accepted",
			options: &openapi.TokenRequestOptions{
				SubjectToken:       &subject,
				SubjectTokenType:   &accessTokenType,
				RequestedTokenType: &passportType,
			},
		},
		{
			name: "registered access_token requested_token_type accepted as default synonym",
			options: &openapi.TokenRequestOptions{
				SubjectToken:       &subject,
				SubjectTokenType:   &accessTokenType,
				RequestedTokenType: &accessTokenType,
			},
		},
		{
			name: "unsupported requested_token_type rejected",
			options: &openapi.TokenRequestOptions{
				SubjectToken:       &subject,
				SubjectTokenType:   &accessTokenType,
				RequestedTokenType: &idTokenType,
			},
			expectError: "requested_token_type is not supported",
		},
		{
			name: "project scope without organization scope is rejected",
			options: &openapi.TokenRequestOptions{
				SubjectToken:     &subject,
				SubjectTokenType: &accessTokenType,
				XProjectId:       &subject,
			},
			expectError: "x_organization_id must be specified",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateTokenExchangeRequest(test.options)

			if test.expectError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.expectError)
		})
	}
}

func TestBearerTokenIsJWE(t *testing.T) {
	t.Parallel()

	header := func(claims string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(claims))
	}

	testCases := []struct {
		name        string
		token       string
		expectJWE   bool
		expectError bool
	}{
		{
			name:      "JWS is not a JWE",
			token:     header(`{"alg":"RS256","typ":"at+jwt"}`) + ".payload.signature",
			expectJWE: false,
		},
		{
			name:      "JWE detected by enc header",
			token:     header(`{"alg":"A256GCMKW","enc":"A256GCM"}`) + ".key.iv.ciphertext.tag",
			expectJWE: true,
		},
		{
			name:        "opaque token has no header",
			token:       "opaque-token",
			expectError: true,
		},
		{
			name:        "undecodable header",
			token:       "!!!.payload.signature",
			expectError: true,
		},
		{
			name:        "unparseable header",
			token:       header("not json") + ".payload.signature",
			expectError: true,
		},
		{
			name:        "header without alg is neither",
			token:       header(`{"enc":"A256GCM"}`) + ".key.iv.ciphertext.tag",
			expectError: true,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
		},
		{
			name:      "case-mismatched Enc is not treated as enc",
			token:     header(`{"alg":"RS256","Enc":"A256GCM"}`) + ".payload.signature",
			expectJWE: false,
		},
		{
			name:        "case-mismatched ALG fails the alg check",
			token:       header(`{"ALG":"RS256"}`) + ".payload.signature",
			expectError: true,
		},
		{
			name:        "JWS header with JWE segment count",
			token:       header(`{"alg":"RS256"}`) + ".a.b.c.d",
			expectError: true,
		},
		{
			name:        "JWE header with JWS segment count",
			token:       header(`{"alg":"A256GCMKW","enc":"A256GCM"}`) + ".payload.signature",
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			isJWE, err := bearerTokenIsJWE(test.token)

			if test.expectError {
				require.ErrorIs(t, err, errUnrecognizedToken)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectJWE, isJWE)
		})
	}
}

// TestDispatchUserinfoCountsUnroutableTokens pins the metric contract the
// README markets: every unroutable bearer increments unroutableTokens, while
// an empty bearer (a benign client misconfiguration) does not. It also covers
// the unroutable × no-Auth0-validator cell. The unroutable path short-circuits
// before touching any other Authenticator field, so a bare struct literal with
// only the counter set is sufficient and parallel-safe.
func TestDispatchUserinfoCountsUnroutableTokens(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()

	counter, err := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test").Int64Counter("unroutable")
	require.NoError(t, err)

	authenticator := &Authenticator{unroutableTokens: counter}
	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/api/v1/x", nil)

	// An opaque bearer is unroutable: counted, the parse cause is attached to
	// the returned error for logging, and no partial result leaks out.
	res, err := authenticator.dispatchUserinfo(t.Context(), req, "opaque", dispatchSurfaceBearer)
	require.ErrorIs(t, err, errUnrecognizedToken)
	require.Nil(t, res)

	// An empty bearer is rejected but must not pollute the format-change signal.
	res, err = authenticator.dispatchUserinfo(t.Context(), req, "", dispatchSurfaceBearer)
	require.Error(t, err)
	require.NotErrorIs(t, err, errUnrecognizedToken)
	require.Nil(t, res)

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))
	require.Len(t, rm.ScopeMetrics, 1)
	require.Len(t, rm.ScopeMetrics[0].Metrics, 1)

	sum, ok := rm.ScopeMetrics[0].Metrics[0].Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, sum.DataPoints, 1)

	// Only the opaque token counted; the empty bearer did not.
	assert.Equal(t, int64(1), sum.DataPoints[0].Value)
}

// ── externalUserinfo tests ────────────────────────────────────────────────────
//
// externalUserinfo is the shared implementation for all bearer-trust paths.
// These tests exercise the AllowExternalIdentity branch and confirm the reject
// path is preserved when the flag is false.
//
// externalUserinfoTestIssuer is a minimal JWKS-backed OIDC issuer that produces
// RS256-signed access tokens recognised by auth0.Validator. It mirrors the
// auth0TestIssuer helper in passport_test.go (package oauth2_test) but lives in
// the internal-test package so we can call externalUserinfo directly.

const (
	// emailNotInUserDB is an email address that is deliberately absent from
	// every externalUserinfo test environment's user database.
	emailNotInUserDB = "external@example.com"

	// externalTestAudience is the audience used by externalUserinfo tests.
	externalTestAudience = "https://external-idp.example.com"
)

type externalUserinfoTestIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newExternalUserinfoTestIssuer(t *testing.T) *externalUserinfoTestIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := gojose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     "test-key",
			Algorithm: string(gojose.RS256),
			Use:       "sig",
		}

		assert.NoError(t, json.NewEncoder(w).Encode(gojose.JSONWebKeySet{
			Keys: []gojose.JSONWebKey{pub},
		}))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &externalUserinfoTestIssuer{server: srv, key: key}
}

func (i *externalUserinfoTestIssuer) issuer() string { return i.server.URL }

// token mints a minimal RS256 access token accepted by the validator. The
// authz claim is intentionally omitted — RequireAuthzClaim is left false
// for these tests so the focus stays on the AllowExternalIdentity branch.
func (i *externalUserinfoTestIssuer) token(t *testing.T, audience, email string, expiry time.Time) string {
	t.Helper()

	verified := true

	//nolint:tagliatelle
	type tokenClaims struct {
		jwt.Claims

		Email         string `json:"https://unikorn-cloud.org/email"`
		EmailVerified *bool  `json:"https://unikorn-cloud.org/email_verified"`
	}

	claims := &tokenClaims{
		Claims: jwt.Claims{
			Issuer:    i.issuer(),
			Subject:   "sub|" + email,
			Audience:  jwt.Audience{audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Second)),
			Expiry:    jwt.NewNumericDate(expiry),
		},
		Email:         email,
		EmailVerified: &verified,
	}

	signer, err := gojose.NewSigner(
		gojose.SigningKey{
			Algorithm: gojose.RS256,
			Key: gojose.JSONWebKey{
				Key:   i.key,
				KeyID: "test-key",
			},
		},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return tok
}

// externalUserinfoTestConfig accumulates options for the externalUserinfo test
// helpers below.
type externalUserinfoTestConfig struct {
	allowExternalIdentity bool
}

type externalUserinfoOpt func(*externalUserinfoTestConfig)

func withAllowExternalIdentity(v bool) externalUserinfoOpt {
	return func(c *externalUserinfoTestConfig) { c.allowExternalIdentity = v }
}

// buildExternalUserinfoEnv constructs a minimal Authenticator backed by a fake
// client and a real JWKS server; the user database contains no record for
// emailNotInUserDB. opts control the synthesized BearerTrustSpec.
func buildExternalUserinfoEnv(t *testing.T, opts ...externalUserinfoOpt) (*Authenticator, *externalUserinfoTestIssuer, *unikornv1.BearerTrustSpec, *auth0.Validator) {
	t.Helper()

	cfg := &externalUserinfoTestConfig{}
	for _, o := range opts {
		o(cfg)
	}

	// Use a fresh scheme; we only need unikornv1 types for the fake client.
	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	cli := fake.NewClientBuilder().WithScheme(s).Build()

	udb := userdb.NewUserDatabase(cli, passportTestNamespace)

	a := &Authenticator{
		client:    cli,
		namespace: passportTestNamespace,
		userdb:    udb,
	}

	iss := newExternalUserinfoTestIssuer(t)

	v, err := auth0.NewValidator(auth0.Options{
		Issuer:                iss.issuer(),
		Audience:              externalTestAudience,
		SkipEmailVerification: false,
		RequireAuthzClaim:     false,
	})
	require.NoError(t, err)

	trust := &unikornv1.BearerTrustSpec{
		Audience:              externalTestAudience,
		AllowExternalIdentity: cfg.allowExternalIdentity,
	}

	return a, iss, trust, v
}

// tryExternalUserinfo invokes externalUserinfo and returns its results.
func tryExternalUserinfo(t *testing.T, opts ...externalUserinfoOpt) (*openapi.Userinfo, *Claims, error) {
	t.Helper()

	a, iss, trust, v := buildExternalUserinfoEnv(t, opts...)

	tok := iss.token(t, externalTestAudience, emailNotInUserDB, time.Now().Add(30*time.Second))

	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/api/v1/x", nil)

	return a.externalUserinfo(t.Context(), req, tok, iss.issuer(), trust, v)
}

// mustExternalUserinfo calls tryExternalUserinfo and requires no error.
func mustExternalUserinfo(t *testing.T, opts ...externalUserinfoOpt) *openapi.Userinfo {
	t.Helper()

	ui, _, err := tryExternalUserinfo(t, opts...)
	require.NoError(t, err)

	return ui
}

func TestExternalUserinfoAllowExternalIdentity(t *testing.T) {
	t.Parallel()

	// No UNI user record for the email; AllowExternalIdentity=true → empty
	// orgIds accepted without error.
	ui := mustExternalUserinfo(t, withAllowExternalIdentity(true))

	require.NotNil(t, ui.HttpsunikornCloudOrgauthz)

	// Must be a non-nil empty slice: orgIds is non-nullable in the userinfo
	// OpenAPI schema, so a nil slice (JSON null) fails response validation.
	require.NotNil(t, ui.HttpsunikornCloudOrgauthz.OrgIds)
	assert.Empty(t, ui.HttpsunikornCloudOrgauthz.OrgIds)

	require.NotNil(t, ui.Email)
	assert.Equal(t, emailNotInUserDB, *ui.Email)
}

func TestExternalUserinfoRejectsUnknownWhenNotAllowed(t *testing.T) {
	t.Parallel()

	// No UNI user record and AllowExternalIdentity=false → must be rejected.
	if _, _, err := tryExternalUserinfo(t, withAllowExternalIdentity(false)); err == nil {
		t.Fatal("expected reject for unknown user when AllowExternalIdentity is false")
	}
}

func TestExternalUserinfoStampsIssuer(t *testing.T) {
	t.Parallel()

	// sourceClaims.Issuer must equal the verbatim issuer so srcIssForSource can
	// embed the correct src_iss in the resulting passport.
	a, iss, trust, v := buildExternalUserinfoEnv(t, withAllowExternalIdentity(true))

	tok := iss.token(t, externalTestAudience, emailNotInUserDB, time.Now().Add(30*time.Second))

	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/api/v1/x", nil)

	_, sourceClaims, err := a.externalUserinfo(t.Context(), req, tok, iss.issuer(), trust, v)
	require.NoError(t, err)
	require.NotNil(t, sourceClaims)

	assert.Equal(t, iss.issuer(), sourceClaims.Issuer, "sourceClaims.Issuer must be the verbatim issuer")
}

// newPassportInternalAuthenticatorWithOpts builds a minimal Authenticator
// wired to a fake client, with options and unroutableTokens initialised so
// dispatchUserinfo can be called directly.
func newPassportInternalAuthenticatorWithOpts(t *testing.T, opts *Options, objects ...client.Object) *Authenticator {
	t.Helper()

	cli := fake.NewClientBuilder().WithScheme(getPassportInternalScheme(t)).WithObjects(objects...).Build()

	counter, err := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader())).
		Meter("test").Int64Counter("test_unroutable_" + t.Name())
	require.NoError(t, err)

	return &Authenticator{
		client:           cli,
		namespace:        passportTestNamespace,
		options:          opts,
		validatorCache:   newValidatorCache(opts.ValidatorCacheSize),
		unroutableTokens: counter,
	}
}

func TestDispatchUnknownIssuerRejected(t *testing.T) {
	t.Parallel()

	// Build an authenticator with one trusted provider for a DIFFERENT issuer
	// than what the JWS token will claim.
	trustedProvider := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: passportTestNamespace,
			Name:      "trusted",
		},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer: "https://trusted.example.com",
			BearerTrust: &unikornv1.BearerTrustSpec{
				Audience: "https://api.example.com",
			},
		},
	}

	a := newPassportInternalAuthenticatorWithOpts(t, &Options{
		ValidatorCacheSize: 64,
	}, trustedProvider)

	// Build a JWS from an untrusted issuer (not "https://trusted.example.com").
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: key},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		Issuer:   "https://untrusted.example.com",
		Subject:  "user@example.com",
		Audience: jwt.Audience{"https://api.example.com"},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://test.com/api/v1/organizations", nil)

	_, err = a.dispatchUserinfo(t.Context(), req, token, "bearer")
	require.Error(t, err, "expected reject for unknown issuer")
}

func TestDispatchCacheNotReadySurfaces503(t *testing.T) {
	t.Parallel()

	// Create a client that fails on List (simulating cache not synced).
	cli := fake.NewClientBuilder().
		WithScheme(getPassportInternalScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				return ErrCacheNotReady
			},
		}).
		Build()

	authenticator := &Authenticator{
		client:         cli,
		namespace:      passportTestNamespace,
		options:        &Options{ValidatorCacheSize: 64},
		validatorCache: newValidatorCache(64),
	}

	// Build a JWS from an external issuer.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: key},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		Issuer:   "https://external.example.com",
		Subject:  "user@example.com",
		Audience: jwt.Audience{"https://api.example.com"},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://test.com/api/v2/userinfo", nil)

	_, err = authenticator.dispatchUserinfo(t.Context(), req, token, "bearer")
	require.Error(t, err)

	// Check that the error has 503 status code.
	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
	require.Equal(t, http.StatusServiceUnavailable, oauthErr.StatusCode(), "expected 503 Service Unavailable")
}

func TestDirectBearerExternalDoesNotInheritUNIAdmin(t *testing.T) {
	t.Parallel()

	// Build a JWS from an external issuer; the dispatch must return
	// SrcIss = the external issuer (verbatim), NOT the UNI sentinel.

	// Set up a mock JWKS server so the external token validates.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		publicKey := gojose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     "test-key",
			Algorithm: string(gojose.RS256),
			Use:       "sig",
		}
		assert.NoError(t, json.NewEncoder(w).Encode(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{publicKey}}))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	externalIssuer := server.URL

	trustedProvider := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: passportTestNamespace,
			Name:      "external-provider",
		},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer: externalIssuer,
			BearerTrust: &unikornv1.BearerTrustSpec{
				Audience:              "https://api.example.com",
				AllowExternalIdentity: true,
			},
		},
	}

	a := newPassportInternalAuthenticatorWithOpts(t, &Options{
		TokenVerificationLeeway: 0,
		ValidatorCacheSize:      64,
	}, trustedProvider)

	// Also wire a userdb so externalUserinfo can call GetOrganizationIDs.
	a.userdb = userdb.NewUserDatabase(
		fake.NewClientBuilder().WithScheme(getPassportInternalScheme(t)).Build(),
		passportTestNamespace,
	)

	// Build the JWS token.
	signer, err := gojose.NewSigner(
		gojose.SigningKey{
			Algorithm: gojose.RS256,
			Key: gojose.JSONWebKey{
				Key:   key,
				KeyID: "test-key",
			},
		},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	//nolint:tagliatelle
	type extClaims struct {
		jwt.Claims
		Email         string `json:"https://unikorn-cloud.org/email"`
		EmailVerified *bool  `json:"https://unikorn-cloud.org/email_verified"`
	}

	verified := true
	tokenClaims := &extClaims{
		Claims: jwt.Claims{
			Issuer:   externalIssuer,
			Subject:  "admin@x",
			Audience: jwt.Audience{"https://api.example.com"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email:         "admin@x",
		EmailVerified: &verified,
	}

	token, err := jwt.Signed(signer).Claims(tokenClaims).Serialize()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://test.com/api/v1/organizations", nil)

	res, err := a.dispatchUserinfo(t.Context(), req, token, "bearer")
	require.NoError(t, err)
	require.NotNil(t, res)

	if res.SrcIss == PassportSourceUNI {
		t.Fatal("external bearer must not resolve to UNI sentinel (fail-open)")
	}
}

// TestDispatchMultipleTrustedIssuers exercises the multi-issuer guarantee: with
// two bearerTrust providers configured simultaneously, each pinned to its own
// JWKS, a token from either issuer validates and is routed to its own validator,
// while a token claiming one issuer but signed by the other's key is rejected
// (per-issuer JWKS isolation).
func TestDispatchMultipleTrustedIssuers(t *testing.T) {
	t.Parallel()

	const (
		audA  = "https://api-a.example.com"
		audB  = "https://api-b.example.com"
		email = "user@example.com"
	)

	issuerA := newExternalUserinfoTestIssuer(t)
	issuerB := newExternalUserinfoTestIssuer(t)

	providerA := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{Namespace: passportTestNamespace, Name: "issuer-a"},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer:      issuerA.issuer(),
			BearerTrust: &unikornv1.BearerTrustSpec{Audience: audA, AllowExternalIdentity: true},
		},
	}

	providerB := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{Namespace: passportTestNamespace, Name: "issuer-b"},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer:      issuerB.issuer(),
			BearerTrust: &unikornv1.BearerTrustSpec{Audience: audB, AllowExternalIdentity: true},
		},
	}

	a := newPassportInternalAuthenticatorWithOpts(t, &Options{
		TokenVerificationLeeway: 0,
		ValidatorCacheSize:      64,
	}, providerA, providerB)

	// Empty userdb + AllowExternalIdentity=true → happy path resolves to empty orgIds.
	a.userdb = userdb.NewUserDatabase(
		fake.NewClientBuilder().WithScheme(getPassportInternalScheme(t)).Build(),
		passportTestNamespace,
	)

	t.Run("issuer A token validates and stamps issuer A", func(t *testing.T) {
		t.Parallel()

		tok := issuerA.token(t, audA, email, time.Now().Add(time.Hour))
		req := httptest.NewRequest(http.MethodGet, "https://test.com/api/v1/organizations", nil)

		res, err := a.dispatchUserinfo(t.Context(), req, tok, "bearer")
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, issuerA.issuer(), res.SrcIss)
	})

	t.Run("issuer B token validates and stamps issuer B", func(t *testing.T) {
		t.Parallel()

		tok := issuerB.token(t, audB, email, time.Now().Add(time.Hour))
		req := httptest.NewRequest(http.MethodGet, "https://test.com/api/v1/organizations", nil)

		res, err := a.dispatchUserinfo(t.Context(), req, tok, "bearer")
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Equal(t, issuerB.issuer(), res.SrcIss)
	})

	t.Run("token claiming issuer A but signed by issuer B key is rejected", func(t *testing.T) {
		t.Parallel()

		// iss=A with A's correct audience, so the only thing that can fail is the
		// signature: dispatch routes to validator A, which fetches A's JWKS and
		// cannot verify a token signed by B's key.
		signer, err := gojose.NewSigner(
			gojose.SigningKey{
				Algorithm: gojose.RS256,
				Key:       gojose.JSONWebKey{Key: issuerB.key, KeyID: "test-key"},
			},
			(&gojose.SignerOptions{}).WithType("at+jwt"),
		)
		require.NoError(t, err)

		verified := true

		//nolint:tagliatelle
		type extClaims struct {
			jwt.Claims

			Email         string `json:"https://unikorn-cloud.org/email"`
			EmailVerified *bool  `json:"https://unikorn-cloud.org/email_verified"`
		}

		claims := &extClaims{
			Claims: jwt.Claims{
				Issuer:   issuerA.issuer(),
				Subject:  "sub|" + email,
				Audience: jwt.Audience{audA},
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Email:         email,
			EmailVerified: &verified,
		}

		tok, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "https://test.com/api/v1/organizations", nil)

		_, err = a.dispatchUserinfo(t.Context(), req, tok, "bearer")
		require.Error(t, err, "token signed by a foreign key must fail issuer A's JWKS check")
	})
}

// TestDispatchTrailingSlashIssuer is the real-Auth0 regression guard: the
// provider issuer and the token `iss` both carry a trailing slash (as Auth0
// emits). Dispatch selection and token verification both match the issuer
// verbatim, and the slash-bearing issuer is stamped onto src_iss unchanged.
// In-process issuers default to no trailing slash, which is why the original
// unit tests missed this.
func TestDispatchTrailingSlashIssuer(t *testing.T) {
	t.Parallel()

	const (
		audience = "https://api.example.com"
		email    = "user@example.com"
	)

	iss := newExternalUserinfoTestIssuer(t)
	slashIssuer := iss.issuer() + "/" // as a real Auth0 tenant is configured/emits

	provider := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{Namespace: passportTestNamespace, Name: "staff"},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer:      slashIssuer,
			BearerTrust: &unikornv1.BearerTrustSpec{Audience: audience, AllowExternalIdentity: true},
		},
	}

	a := newPassportInternalAuthenticatorWithOpts(t, &Options{
		TokenVerificationLeeway: 0,
		ValidatorCacheSize:      64,
	}, provider)
	a.userdb = userdb.NewUserDatabase(
		fake.NewClientBuilder().WithScheme(getPassportInternalScheme(t)).Build(),
		passportTestNamespace,
	)

	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: gojose.JSONWebKey{Key: iss.key, KeyID: "test-key"}},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	verified := true

	//nolint:tagliatelle
	type extClaims struct {
		jwt.Claims

		Email         string `json:"https://unikorn-cloud.org/email"`
		EmailVerified *bool  `json:"https://unikorn-cloud.org/email_verified"`
	}

	claims := &extClaims{
		Claims: jwt.Claims{
			Issuer:   slashIssuer,
			Subject:  "sub|" + email,
			Audience: jwt.Audience{audience},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email:         email,
		EmailVerified: &verified,
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://test.com/api/v1/organizations", nil)

	res, err := a.dispatchUserinfo(t.Context(), req, token, "bearer")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, slashIssuer, res.SrcIss) // verbatim — trailing slash preserved
}
