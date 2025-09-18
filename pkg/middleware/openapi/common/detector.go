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

package common

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// TokenType represents different token formats
type TokenType int

const (
	// TokenTypeUnknown represents an unrecognized token format
	TokenTypeUnknown TokenType = iota
	// TokenTypeLocalJWE represents encrypted tokens from local service
	TokenTypeLocalJWE
	// TokenTypeExternalJWE represents encrypted tokens from external OIDC
	TokenTypeExternalJWE
	// TokenTypeExternalOpaque represents opaque tokens from external OIDC
	TokenTypeExternalOpaque
	// TokenTypeJWT represents signed tokens (external OIDC)
	TokenTypeJWT
)

// TokenDetector detects token types based on format
type TokenDetector struct{}

// DetectTokenType analyzes a token and returns its type
func (d *TokenDetector) DetectTokenType(token string) TokenType {
	parts := strings.Split(token, ".")

	// JWE tokens have 5 parts: header.encrypted_key.iv.ciphertext.tag
	if len(parts) == 5 {
		isJWE, hasIssuer := d.analyzeJWEHeader(parts[0])
		if isJWE {
			if hasIssuer { // FIXME: we should also check that the iss field matches our expected issuer. Although, we will subsequently try validating the access token with the configured external provider.
				return TokenTypeExternalJWE
			}
			return TokenTypeLocalJWE
		}
	}

	// JWT tokens have 3 parts: header.payload.signature
	if len(parts) == 3 {
		return TokenTypeJWT
	}

	// if it's just one part, assume it's an opaque token, and use the external provider.
	if len(parts) == 1 {
		return TokenTypeExternalOpaque
	}

	return TokenTypeUnknown
}

// analyzeJWEHeader checks if the token header indicates JWE encryption and if it has an issuer
func (d *TokenDetector) analyzeJWEHeader(headerB64 string) (isJWE bool, hasIssuer bool) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return false, false
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false, false
	}

	// JWE headers have both "alg" and "enc" fields
	_, hasAlg := header["alg"]
	_, hasEnc := header["enc"]
	isJWE = hasAlg && hasEnc

	// Check for issuer field (Auth0 uses a directly encrypted access token, with this field set in the header)
	_, hasIss := header["iss"]

	return isJWE, hasIss
}
