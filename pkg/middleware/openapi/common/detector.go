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
	// TokenTypeJWE represents encrypted tokens (local service)
	TokenTypeJWE
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
		if d.isJWEHeader(parts[0]) {
			return TokenTypeJWE
		}
	}

	// JWT tokens have 3 parts: header.payload.signature
	if len(parts) == 3 {
		return TokenTypeJWT
	}

	return TokenTypeUnknown
}

// isJWEHeader checks if the token header indicates JWE encryption
func (d *TokenDetector) isJWEHeader(headerB64 string) bool {
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return false
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}

	// JWE headers have both "alg" and "enc" fields
	_, hasAlg := header["alg"]
	_, hasEnc := header["enc"]

	return hasAlg && hasEnc
}