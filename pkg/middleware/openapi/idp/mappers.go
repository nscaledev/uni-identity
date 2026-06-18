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

package idp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// grantTypeClientCredentials is the OAuth2 `gty` claim value for the
// client-credentials grant — a machine principal. Type is discriminated on this
// claim, never on the subject string (token-resolution note §6).
const grantTypeClientCredentials = "client-credentials"

var (
	ErrMissingEmail    = errors.New("email claim is missing")
	ErrEmailUnverified = errors.New("email is not verified")
	// ErrNotAUser is returned for a token that is not a human user (e.g. a
	// client-credentials grant) on an issuer configured for users only.
	ErrNotAUser = errors.New("token is not a user")
)

// EmailUserMapper maps a federated-user token to a user principal: it rejects
// machine (client-credentials) grants, requires a verified email, and uses the
// email as the subject. The email/verified claim names are configured because a
// provider may surface them under a namespaced claim (our tenant emits
// https://unikorn-cloud.org/email on the access token via a post-login action,
// since a bare email cannot be set there).
func EmailUserMapper(emailClaim, emailVerifiedClaim string) Mapper {
	return func(_ jwt.Claims, payload []byte) (*Principal, error) {
		var grant struct {
			GrantType string `json:"gty"`
		}

		if err := json.Unmarshal(payload, &grant); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}

		if grant.GrantType == grantTypeClientCredentials {
			return nil, ErrNotAUser
		}

		raw := map[string]json.RawMessage{}
		if err := json.Unmarshal(payload, &raw); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}

		var email string
		if msg, ok := raw[emailClaim]; ok {
			_ = json.Unmarshal(msg, &email)
		}

		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			return nil, ErrMissingEmail
		}

		var verified bool
		if msg, ok := raw[emailVerifiedClaim]; ok {
			_ = json.Unmarshal(msg, &verified)
		}

		if !verified {
			return nil, ErrEmailUnverified
		}

		return &Principal{Subject: email, Type: openapi.User}, nil
	}
}

// SubjectTypeMapper maps a token whose subject is the standard `sub` claim and
// whose account type is read from a configured claim via the given value map
// (e.g. the platform's own issuer: subject = sub, type from the "typ" claim).
func SubjectTypeMapper(typeClaim string, types map[string]openapi.AuthClaimsAcctype) Mapper {
	return func(standard jwt.Claims, payload []byte) (*Principal, error) {
		if standard.Subject == "" {
			return nil, fmt.Errorf("%w: missing subject", ErrInvalidToken)
		}

		raw := map[string]json.RawMessage{}
		if err := json.Unmarshal(payload, &raw); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}

		var typeValue string
		if msg, ok := raw[typeClaim]; ok {
			_ = json.Unmarshal(msg, &typeValue)
		}

		accountType, ok := types[typeValue]
		if !ok {
			return nil, fmt.Errorf("%w: unrecognised account type %q", ErrInvalidToken, typeValue)
		}

		return &Principal{Subject: standard.Subject, Type: accountType}, nil
	}
}
