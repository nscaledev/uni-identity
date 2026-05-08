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

package exchange

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ErrMalformedToken indicates the bearer was not a parseable JWT — for
// instance, missing segments or non-base64 payload. Treat as routing failure;
// the exchange path must reject before any validator is consulted.
var ErrMalformedToken = errors.New("token is not a parseable JWT")

// SourceDetector inspects the unverified JWT payload to choose a per-source
// validator. The returned Source is a routing hint only — actual trust
// decisions happen inside the validator after signature and claim checks.
type SourceDetector struct {
	uniIssuer   string
	auth0Issuer string
}

// NewSourceDetector configures a detector with the issuers each validator
// trusts. Either issuer may be empty to disable that source — useful when an
// operator has not configured Auth0 yet.
func NewSourceDetector(uniIssuer, auth0Issuer string) *SourceDetector {
	return &SourceDetector{
		uniIssuer:   strings.TrimSpace(uniIssuer),
		auth0Issuer: strings.TrimSpace(auth0Issuer),
	}
}

// Detect returns the Source matching the token's untrusted `iss` claim.
// Returns SourceUnknown (no error) when the issuer matches none of the
// configured sources — the caller should reject. Returns ErrMalformedToken
// when the token cannot be parsed at all.
func (d *SourceDetector) Detect(rawToken string) (Source, error) {
	iss, err := unverifiedIssuer(rawToken)
	if err != nil {
		return SourceUnknown, err
	}

	switch {
	case d.uniIssuer != "" && iss == d.uniIssuer:
		return SourceUNI, nil
	case d.auth0Issuer != "" && iss == d.auth0Issuer:
		return SourceAuth0, nil
	default:
		return SourceUnknown, nil
	}
}

// unverifiedIssuer extracts the iss claim from a JWT payload without verifying
// the signature. Used solely for routing.
func unverifiedIssuer(rawToken string) (string, error) {
	var claims struct {
		Issuer string `json:"iss"`
	}

	if err := parseJWTPayload(rawToken, &claims); err != nil {
		return "", err
	}

	return claims.Issuer, nil
}

func parseJWTPayload(rawToken string, dest any) error {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return ErrMalformedToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrMalformedToken
	}

	if err := json.Unmarshal(payload, dest); err != nil {
		return ErrMalformedToken
	}

	return nil
}
