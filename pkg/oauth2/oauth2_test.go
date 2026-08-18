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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"github.com/unikorn-cloud/core/pkg/spiffetest"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"
	"github.com/unikorn-cloud/identity/pkg/util"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

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

	authenticator, err := oauth2.New(options, josetesting.Namespace, issuerVal, client, issuer, userDatabase, rbac)
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

// TestUserinfoCustomClaims tests that tokens include correct custom authorization claims.
//
//nolint:maintidx
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
			}, josetesting.Namespace, issuerHost, client, issuer, userDatabase, rbac)
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
		})
	}
}

// svidTestSPIFFEID is the identity the SVID shaped test certificate carries.
const svidTestSPIFFEID = "spiffe://my-platform/region-server"

// addServiceCertificateHeader sets the client certificate header the ingress injects, with a
// certificate identified either by a common name or, when commonName is empty, the way SPIRE
// issues an X509-SVID: no common name, and the SPIFFE ID in a URI SAN.
func addServiceCertificateHeader(t *testing.T, r *http.Request, commonName, spiffeID string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subject := pkix.Name{}

	if commonName != "" {
		subject.CommonName = commonName
	} else {
		subject.Country = []string{"US"}
		subject.Organization = []string{"SPIRE"}
	}

	var uris []*url.URL

	if spiffeID != "" {
		uri, err := url.Parse(spiffeID)
		require.NoError(t, err)

		uris = append(uris, uri)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		URIs:                  uris,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	r.Header.Set("Ssl-Client-Cert", url.QueryEscape(string(certPEM)))
	r.Header.Set("Ssl-Client-Verify", "SUCCESS")
}

// addVerifiedPeerCertificate sets the request's TLS connection state as if it
// arrived over a mutual TLS connection whose peer presented a certificate
// identified either by a common name or, when commonName is empty, the way SPIRE
// issues an X509-SVID: no common name, and the SPIFFE ID in a URI SAN.  Unlike
// addServiceCertificateHeader, this sets no Ssl-Client-Cert header at all, which is
// what a request on the mutual TLS listener actually looks like.
func addVerifiedPeerCertificate(t *testing.T, r *http.Request, commonName, spiffeID string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	subject := pkix.Name{}

	if commonName != "" {
		subject.CommonName = commonName
	} else {
		subject.Country = []string{"US"}
		subject.Organization = []string{"SPIRE"}
	}

	var uris []*url.URL

	if spiffeID != "" {
		uri, err := url.Parse(spiffeID)
		require.NoError(t, err)

		uris = append(uris, uri)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		URIs:                  uris,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
}

// TestTokenClientCredentialsSubject asserts what names a service in a service token.
//
// An X509-SVID has no common name, so reading only that field yields an empty subject.  The
// grant still succeeds and the token is still correctly bound to the certificate, so nothing
// fails here: the first call that uses the token fails instead, as an unregistered system
// account, which is a diagnostic pointing nowhere near the mint that caused it.  The common
// name case is asserted alongside because the SPIFFE ID is a fallback and must not displace
// it for the callers that have one.
func TestTokenClientCredentialsSubject(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		commonName string
		spiffeID   string
		expected   string
	}{
		{
			name:     "an SVID is named by its SPIFFE ID",
			spiffeID: svidTestSPIFFEID,
			expected: svidTestSPIFFEID,
		},
		{
			name:       "a common name is preferred when there is one",
			commonName: "uni-region",
			expected:   "uni-region",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := setupPassportTestEnv(t)

			r := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
				strings.NewReader(url.Values{
					"grant_type": {"client_credentials"},
				}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			addServiceCertificateHeader(t, r, tc.commonName, tc.spiffeID)

			result, err := env.authenticator.TokenClientCredentials(httptest.NewRecorder(), r)
			require.NoError(t, err)
			require.NotNil(t, result)

			var claims oauth2.Claims

			require.NoError(t, env.jwtIssuer.DecodeJWEToken(
				t.Context(),
				result.AccessToken,
				&claims,
				jose.TokenTypeAccessToken,
			))

			assert.Equal(t, tc.expected, claims.Subject)

			// The binding is what makes the subject load bearing rather than cosmetic: the
			// token is usable only by a caller presenting this same certificate.
			require.NotNil(t, claims.Service)
			assert.NotEmpty(t, claims.Service.X509Thumbprint)
		})
	}
}

// TestTokenClientCredentialsAcceptsVerifiedPeer is the regression test for the mint
// side of the RFC 8705 binding gap this task closes.  local/authorizer.go validates
// a bound token's thumbprint against authorization.ClientCertFromContext, which this
// task already made prefer a verified TLS peer; before this fix, minting still read
// only Ssl-Client-Cert, so a caller with no such header -- exactly what a request on
// the mutual TLS listener looks like -- could not mint a bound token at all.  Left
// open, a later task proving a peer-bound token is accepted end to end would have
// had to mint over the ingress instead, and would pass without ever exercising the
// peer path -- the same vacuous-pass failure mode this project has hit before.
func TestTokenClientCredentialsAcceptsVerifiedPeer(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	r := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
		strings.NewReader(url.Values{
			"grant_type": {"client_credentials"},
		}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	addVerifiedPeerCertificate(t, r, "", svidTestSPIFFEID)

	result, err := env.authenticator.TokenClientCredentials(httptest.NewRecorder(), r)
	require.NoError(t, err)
	require.NotNil(t, result)

	var claims oauth2.Claims

	require.NoError(t, env.jwtIssuer.DecodeJWEToken(
		t.Context(),
		result.AccessToken,
		&claims,
		jose.TokenTypeAccessToken,
	))

	assert.Equal(t, svidTestSPIFFEID, claims.Subject)

	require.NotNil(t, claims.Service)
	assert.NotEmpty(t, claims.Service.X509Thumbprint)
}

// TestTokenClientCredentialsRefusesARelayOnlyRequest is the negative half of the mint
// side.  A caller carrying only the relayed Unikorn-Client-Certificate header -- no TLS
// peer this process verified, no Ssl-Client-Cert the ingress verified -- has proven
// nothing about itself, and must not be able to mint a token naming the identity in that
// header.
//
// This is reachable from outside the cluster.  validateAndAuthorize runs ExtractClientCert
// for every route, /oauth2/v2/token included, and that endpoint carries no security
// requirements.  So if this grant were ever "unified" with the validate side by reading
// authorization.ClientCertFromContext -- a plausible tidy-up, because local/authorizer.go
// legitimately does exactly that when checking a bound token -- anyone able to reach the
// endpoint could mint a service token whose Subject is whatever that public certificate
// names.  Minting and validating are different questions; this pins them apart.
//
// The context is built by ExtractClientCert rather than left empty on purpose: that is
// what the handler sees in production, and an empty context would make this test pass
// under that substitution for the wrong reason -- a missing context value rather than a
// refused relay identity.
func TestTokenClientCredentialsRefusesARelayOnlyRequest(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	r := httptest.NewRequest(http.MethodPost, "https://test.com/oauth2/v2/token",
		strings.NewReader(url.Values{
			"grant_type": {"client_credentials"},
		}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// An SVID shaped certificate, encoded the way a service relays one, so the only
	// thing missing is any proof that this caller holds its private key.
	svid, _ := spiffetest.NewSVID(t, svidTestSPIFFEID)
	r.Header.Set("Unikorn-Client-Certificate", util.EncodeCertificatePEM(svid.Certificates[0]))

	ctx, err := authorization.ExtractClientCert(t.Context(), r)
	require.NoError(t, err)

	// Guards the fixture: if the certificate did not land in the context as the relayed
	// header, the refusal below would hold for a reason unrelated to the behaviour under
	// test.
	require.Equal(t, authorization.ProvenanceRelayedHeader, authorization.ProvenanceFromContext(ctx))

	result, err := env.authenticator.TokenClientCredentials(httptest.NewRecorder(), r.WithContext(ctx))
	require.Nil(t, result)
	require.ErrorContains(t, err, "mTLS client verification failed")
}
