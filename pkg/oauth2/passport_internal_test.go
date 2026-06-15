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
	"encoding/base64"
	goerrors "errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"

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
	userinfo, claims, source, err := authenticator.dispatchUserinfo(t.Context(), req, "opaque", dispatchSurfaceBearer)
	require.ErrorIs(t, err, errUnrecognizedToken)
	require.Nil(t, userinfo)
	require.Nil(t, claims)
	require.Empty(t, source)

	// An empty bearer is rejected but must not pollute the format-change signal.
	userinfo, claims, source, err = authenticator.dispatchUserinfo(t.Context(), req, "", dispatchSurfaceBearer)
	require.Error(t, err)
	require.NotErrorIs(t, err, errUnrecognizedToken)
	require.Nil(t, userinfo)
	require.Nil(t, claims)
	require.Empty(t, source)

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
