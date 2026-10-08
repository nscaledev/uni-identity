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
	"crypto/rand"
	"crypto/rsa"
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

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	casingClientID    = "casing-client"
	casingSecret      = "casing-secret"
	casingUserID      = "casing-user"
	casingRedirectURI = "https://client.example.com/callback"
	// casingFolded is the stored subject, in canonical form.
	casingFolded = "bob@example.com"
	// casingLegacy is the same subject in the case that a token or cookie
	// minted before the claim folded can carry.
	casingLegacy = "Bob@Example.com"
)

// newCasingAuthenticator returns an authenticator with a running token issuer.
// The store holds a user with a canonical subject, a session for one client,
// and that client.
func newCasingAuthenticator(t *testing.T) (*Authenticator, *jose.JWTIssuer, client.Client) {
	t.Helper()

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: casingUserID},
		Spec: unikornv1.UserSpec{
			Subject:  casingFolded,
			State:    unikornv1.UserStateActive,
			Sessions: []unikornv1.UserSession{{ClientID: casingClientID}},
		},
	}

	oauth2Client := &unikornv1.OAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: casingClientID},
		Status:     unikornv1.OAuth2ClientStatus{Secret: casingSecret},
	}

	cli := fake.NewClientBuilder().WithScheme(getPassportInternalScheme(t)).WithObjects(user, oauth2Client).Build()

	josetesting.RotateCertificate(t, cli)

	issuer := jose.NewJWTIssuer(cli, josetesting.Namespace, &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	})
	require.NoError(t, issuer.Run(t.Context(), &josetesting.FakeCoordinationClientGetter{}))

	options := &Options{
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
		TokenCacheSize:       16,
		CodeCacheSize:        16,
	}

	issuerValue := handlercommon.IssuerValue{URL: "https://test.com", Hostname: "test.com"}

	authenticator, err := New(options, josetesting.Namespace, issuerValue, cli, cli, issuer,
		userdb.NewUserDatabase(cli, josetesting.Namespace), rbac.New(cli, josetesting.Namespace, &rbac.Options{}))
	require.NoError(t, err)

	time.Sleep(2 * josetesting.RefreshPeriod)

	return authenticator, issuer, cli
}

// TestRefreshFoldsALegacyMixedCaseSubject pins the subject of a reissued token.
// A refresh token that an earlier release minted can carry an unfolded subject.
// If the reissue copies it, every token that the session mints keeps that case.
func TestRefreshFoldsALegacyMixedCaseSubject(t *testing.T) {
	t.Parallel()

	authenticator, issuer, cli := newCasingAuthenticator(t)
	ctx := t.Context()

	claims := &RefreshTokenClaims{
		Claims: jwt.Claims{
			Subject: casingLegacy,
			Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Federated: &FederatedClaims{ClientID: casingClientID, UserID: casingUserID},
	}

	refreshToken, err := issuer.EncodeJWEToken(ctx, claims, jose.TokenTypeRefreshToken)
	require.NoError(t, err)

	user := &unikornv1.User{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: josetesting.Namespace, Name: casingUserID}, user))
	user.Spec.Sessions[0].RefreshToken = refreshToken
	require.NoError(t, cli.Update(ctx, user))

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}

	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/oauth2/v2/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(casingClientID, casingSecret)
	require.NoError(t, r.ParseForm())

	token, err := authenticator.TokenRefreshToken(httptest.NewRecorder(), r)
	require.NoError(t, err)

	access := &Claims{}
	require.NoError(t, issuer.DecodeJWEToken(ctx, token.AccessToken, access, jose.TokenTypeAccessToken))
	assert.Equal(t, casingFolded, access.Subject)
}

// silentReissue sets a session cookie that holds the given id_token, runs the
// silent authorization path, and returns the code that it mints.
func silentReissue(t *testing.T, idToken *oidc.IDToken) *Code {
	t.Helper()

	authenticator, issuer, _ := newCasingAuthenticator(t)
	ctx := t.Context()

	query := url.Values{
		"client_id":    {casingClientID},
		"redirect_uri": {casingRedirectURI},
		"prompt":       {"none"},
	}

	cookie, err := issuer.EncodeJWEToken(ctx, &Code{
		ID:          "cookie-code",
		UserID:      casingUserID,
		ClientQuery: query.Encode(),
		IDToken:     idToken,
	}, jose.TokenTypeAuthorizationCode)
	require.NoError(t, err)

	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/oauth2/v2/authorization?"+query.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})

	w := httptest.NewRecorder()

	require.True(t, authenticator.authorizationSilent(r, newRedirector(w, r, casingRedirectURI, ""), query))

	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)

	reissued := &Code{}
	require.NoError(t, issuer.DecodeJWEToken(ctx, location.Query().Get("code"), reissued, jose.TokenTypeAuthorizationCode))

	return reissued
}

// TestSilentAuthorizationFoldsALegacyCookieSubject pins the session cookie.  A
// cookie that an earlier release set can carry an unfolded claim, and the code
// that the silent path mints reuses its id_token.  So every token that the code
// mints would keep that case.
func TestSilentAuthorizationFoldsALegacyCookieSubject(t *testing.T) {
	t.Parallel()

	reissued := silentReissue(t, &oidc.IDToken{Email: oidc.Email{Email: casingLegacy}})

	require.NotNil(t, reissued.IDToken)
	assert.Equal(t, casingFolded, reissued.IDToken.Email.Email)
}

// TestSilentAuthorizationWithNoIDTokenDoesNotPanic pins the nil guard in
// normalizeIDTokenSubject.  The id_token of a code is a pointer, and the silent
// path must not be the place where a code without one panics.
func TestSilentAuthorizationWithNoIDTokenDoesNotPanic(t *testing.T) {
	t.Parallel()

	reissued := silentReissue(t, nil)

	assert.Nil(t, reissued.IDToken)
}

// newCasingIdentityProvider starts an OIDC provider that answers every code
// exchange with an id_token for the given email, and returns its issuer URL.
func newCasingIdentityProvider(t *testing.T, clientID, email string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := gojose.NewSigner(gojose.SigningKey{
		Algorithm: gojose.RS256,
		Key:       gojose.JSONWebKey{Key: key, KeyID: "casing-key"},
	}, nil)
	require.NoError(t, err)

	var issuer string

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{string(gojose.RS256)},
		}))
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		assert.NoError(t, json.NewEncoder(w).Encode(gojose.JSONWebKeySet{
			Keys: []gojose.JSONWebKey{{Key: &key.PublicKey, KeyID: "casing-key", Algorithm: string(gojose.RS256), Use: "sig"}},
		}))
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		idToken, err := jwt.Signed(signer).Claims(&oidc.IDToken{
			Claims: jwt.Claims{
				Issuer:   issuer,
				Subject:  "idp-subject",
				Audience: jwt.Audience{clientID},
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Email: oidc.Email{Email: email, EmailVerified: true},
		}).Serialize()
		assert.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token": "idp-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		}))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	issuer = server.URL

	return issuer
}

// TestCallbackFoldsAMixedCaseClaim pins the interactive login.  The code and the
// session cookie store the id_token, and every token that the session mints
// takes its subject from the claim.  So an IdP that gives the address in
// another case must not put that case into the session.
func TestCallbackFoldsAMixedCaseClaim(t *testing.T) {
	t.Parallel()

	const (
		providerName = "casing-provider"
		idpClientID  = "casing-idp-client"
	)

	authenticator, issuer, cli := newCasingAuthenticator(t)
	ctx := t.Context()

	require.NoError(t, cli.Create(ctx, &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: providerName},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer:       newCasingIdentityProvider(t, idpClientID, casingLegacy),
			ClientID:     idpClientID,
			ClientSecret: "casing-idp-secret",
		},
	}))

	clientQuery := url.Values{"client_id": {casingClientID}, "redirect_uri": {casingRedirectURI}}

	state, err := issuer.EncodeJWEToken(ctx, &State{
		CodeVerifier:   "casing-verifier",
		OAuth2Provider: providerName,
		ClientQuery:    clientQuery.Encode(),
	}, jose.TokenTypeLoginState)
	require.NoError(t, err)

	query := url.Values{"state": {state}, "code": {"idp-code"}}

	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/oidc/callback?"+query.Encode(), nil)
	w := httptest.NewRecorder()

	authenticator.Callback(w, r)

	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.True(t, location.Query().Has("code"), "the login must succeed, got %q", location.String())

	code := &Code{}
	require.NoError(t, issuer.DecodeJWEToken(ctx, location.Query().Get("code"), code, jose.TokenTypeAuthorizationCode))

	require.NotNil(t, code.IDToken)
	assert.Equal(t, casingFolded, code.IDToken.Email.Email)
}
