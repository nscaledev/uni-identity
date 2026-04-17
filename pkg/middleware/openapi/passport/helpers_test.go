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

package passport //nolint:testpackage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	identityoauth2 "github.com/unikorn-cloud/identity/pkg/oauth2"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// testKeyPair holds a JWK key pair for signing and verifying test tokens.
type testKeyPair struct {
	pub  jose.JSONWebKey
	priv jose.JSONWebKey
}

// newTestKeyPair generates a fresh P-521 ECDSA key pair and returns JWKs for it.
func newTestKeyPair(t *testing.T, kid string) testKeyPair {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	return testKeyPair{
		pub:  jose.JSONWebKey{Key: privateKey.Public(), KeyID: kid, Algorithm: string(jose.ES512), Use: "sig"},
		priv: jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: string(jose.ES512), Use: "sig"},
	}
}

// mintPassport creates a signed passport JWT using the given key pair.
func mintPassport(t *testing.T, kp testKeyPair, opts ...func(*identityoauth2.PassportClaims)) string {
	t.Helper()

	signingKey := jose.SigningKey{Algorithm: jose.ES512, Key: kp.priv}
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")

	signer, err := jose.NewSigner(signingKey, signerOptions)
	require.NoError(t, err)

	now := time.Now()

	claims := &identityoauth2.PassportClaims{
		Claims: jwt.Claims{
			Issuer:   identityoauth2.PassportIssuer,
			Subject:  "test-subject",
			Expiry:   jwt.NewNumericDate(now.Add(2 * time.Minute)),
			IssuedAt: jwt.NewNumericDate(now),
		},
		Type:    identityoauth2.PassportType,
		Acctype: identityapi.User,
	}

	for _, o := range opts {
		o(claims)
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

// withExpired makes the passport token appear already expired.
func withExpired(c *identityoauth2.PassportClaims) {
	c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Hour))
}

// withACL attaches an ACL to the passport.
func withACL(acl *identityapi.Acl) func(*identityoauth2.PassportClaims) {
	return func(c *identityoauth2.PassportClaims) {
		c.ACL = acl
	}
}
