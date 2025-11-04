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

type TokenType int

const (
	Local   TokenType = iota
	Remote  TokenType = iota
	Invalid TokenType = iota
)

// TokenDetector detects token types based on what it can introspect about the token.
type TokenDetector struct {
	ExternalIssuer string
	LocalIssuer    string
}

func (d *TokenDetector) detectIssuer(header string, def TokenType) TokenType {
	if iss := tryExtractIssuer(header); iss != "" {
		switch iss {
		case d.ExternalIssuer:
			return Remote
		case d.LocalIssuer:
			return Local
		default:
			return Invalid // signaling: not an OK issuer
		}
	}

	return def // signaling: try the default
}

// DetectTokenIssuer analyzes a token and returns its issuer, so far as it can tell.
func (d *TokenDetector) DetectTokenIssuer(token string) TokenType {
	parts := strings.Split(token, ".")

	// JWE tokens have 5 parts: header.encrypted_key.iv.ciphertext.tag
	// The issuer _might_ be included in the unencrypted header (it's not standard);
	// if it's not, we conclude it's the local issuer. (Historically, JWE have been used by UNI for service account tokens)
	if len(parts) == 5 {
		return d.detectIssuer(parts[0], Local)
	}

	// JWT tokens have 3 parts: header.payload.signature
	// The issuer is in the payload, so check there. If not present, we conclude it's a dodgy token and return Invalid.
	if len(parts) == 3 {
		return d.detectIssuer(parts[1], Invalid)
	}

	// Apparently not a JWT token; try the remote, on the basis that it might be an opaque token.
	return Remote
}

// tryExtractIssuer tries to get the `iss` field from a header; and returns "" if it's not a valid header, or the value is not present.
func tryExtractIssuer(headerB64 string) string {
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return ""
	}

	type header struct {
		Issuer string `json:"iss,omitempty"`
	}

	var hdr header
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return ""
	}

	return hdr.Issuer
}
