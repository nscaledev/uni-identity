/*
Copyright 2025 the Unikorn Authors.

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

package common_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/common"
)

const (
	localIssuer    = "https://local.example.com"
	externalIssuer = "https://external.example.com"
	unknownIssuer  = "https://unknown.example.com"
)

func setupKey(t *testing.T) (*ecdsa.PrivateKey, *jose.JSONWebKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "test-key-id",
		Algorithm: "ES512",
		Use:       "sig",
	}

	return privateKey, jwk
}

func createJWTWithIssuer(t *testing.T, iss string) string {
	t.Helper()

	_, jwk := setupKey(t)

	signingKey := jose.SigningKey{
		Algorithm: jose.ES512,
		Key:       jwk,
	}

	signer, err := jose.NewSigner(signingKey, nil)
	require.NoError(t, err)

	claims := &jwt.Claims{
		Subject:  "test-subject",
		Issuer:   iss,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

func createJWEWithIssuer(t *testing.T, iss string) string {
	t.Helper()

	privateKey, jwk := setupKey(t)

	// Create a JWE with 5 parts (header.encrypted_key.iv.ciphertext.tag)
	// For testing purposes, we'll create a simple mock JWE structure
	recipient := jose.Recipient{
		Algorithm: jose.ECDH_ES,
		Key:       &privateKey.PublicKey,
		KeyID:     jwk.KeyID,
	}

	encrypterOptions := &jose.EncrypterOptions{}
	if iss != "" {
		// Add issuer to header for testing
		encrypterOptions = encrypterOptions.WithHeader("iss", iss)
	}

	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, encrypterOptions)
	require.NoError(t, err)

	payload := `{"sub":"test-service-account","iss":"` + iss + `"}`

	object, err := encrypter.Encrypt([]byte(payload))
	require.NoError(t, err)

	token, err := object.CompactSerialize()
	require.NoError(t, err)

	return token
}

func createJWEWithoutIssuer(t *testing.T) string {
	t.Helper()

	privateKey, jwk := setupKey(t)

	recipient := jose.Recipient{
		Algorithm: jose.ECDH_ES,
		Key:       &privateKey.PublicKey,
		KeyID:     jwk.KeyID,
	}

	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, nil)
	require.NoError(t, err)

	payload := `{"sub":"test-service-account"}`

	object, err := encrypter.Encrypt([]byte(payload))
	require.NoError(t, err)

	token, err := object.CompactSerialize()
	require.NoError(t, err)

	return token
}

func TestTokenDetector_DetectTokenIssuer_JWT_LocalIssuer(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	token := createJWTWithIssuer(t, localIssuer)
	result := detector.DetectTokenIssuer(token)

	require.Equal(t, common.Local, result)
}

func TestTokenDetector_DetectTokenIssuer_JWT_ExternalIssuer(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	token := createJWTWithIssuer(t, externalIssuer)
	result := detector.DetectTokenIssuer(token)

	require.Equal(t, common.Remote, result)
}

func TestTokenDetector_DetectTokenIssuer_JWT_UnknownIssuer(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	token := createJWTWithIssuer(t, unknownIssuer)
	result := detector.DetectTokenIssuer(token)

	require.Equal(t, common.Invalid, result)
}

func TestTokenDetector_DetectTokenIssuer_JWE_LocalIssuer(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	token := createJWEWithIssuer(t, localIssuer)
	result := detector.DetectTokenIssuer(token)

	require.Equal(t, common.Local, result)
}

func TestTokenDetector_DetectTokenIssuer_JWE_ExternalIssuer(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	token := createJWEWithIssuer(t, externalIssuer)
	result := detector.DetectTokenIssuer(token)

	require.Equal(t, common.Remote, result)
}

func TestTokenDetector_DetectTokenIssuer_JWE_NoIssuerDefaultsToLocal(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	token := createJWEWithoutIssuer(t)
	result := detector.DetectTokenIssuer(token)

	// JWE without issuer defaults to Local (historically service account tokens)
	require.Equal(t, common.Local, result)
}

func TestTokenDetector_DetectTokenIssuer_OpaqueToken(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	// Opaque token (not JWT/JWE format)
	token := "opaque-token-12345" // #nosec G101
	result := detector.DetectTokenIssuer(token)

	// Opaque tokens default to Remote
	require.Equal(t, common.Remote, result)
}

func TestTokenDetector_DetectTokenIssuer_MalformedToken(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	// Malformed token with wrong number of parts
	token := "part1.part2" // #nosec G101
	result := detector.DetectTokenIssuer(token)

	// Malformed tokens default to Remote
	require.Equal(t, common.Remote, result)
}

func TestTokenDetector_DetectTokenIssuer_EmptyToken(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	token := ""
	result := detector.DetectTokenIssuer(token)

	// Empty token defaults to Remote
	require.Equal(t, common.Remote, result)
}

func TestTokenDetector_DetectTokenIssuer_JWT_MalformedHeader(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	// JWT with malformed base64 header
	token := "not-base64!.payload.signature" // #nosec G101
	result := detector.DetectTokenIssuer(token)

	// Can't extract issuer from malformed header, defaults to Invalid for JWT
	require.Equal(t, common.Invalid, result)
}

func TestTokenDetector_DetectTokenIssuer_JWE_MalformedHeader(t *testing.T) {
	t.Parallel()

	detector := &common.TokenDetector{
		ExternalIssuer: externalIssuer,
		LocalIssuer:    localIssuer,
	}

	// JWE with malformed base64 header
	token := "not-base64!.encrypted_key.iv.ciphertext.tag" // #nosec G101
	result := detector.DetectTokenIssuer(token)

	// Can't extract issuer from malformed header, defaults to Local for JWE
	require.Equal(t, common.Local, result)
}
