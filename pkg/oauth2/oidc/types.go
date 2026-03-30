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

package oidc

import (
	"github.com/go-jose/go-jose/v4/jwt"
)

// Default are claims defined by default for an id_token.
//
//nolint:tagliatelle
type Default struct {
	// Nonce should match the nonce provided by the client at authorization
	// time and should be verfified against the original nonce.
	Nonce string `json:"nonce,omitempty"`
	// ATHash is a hash of the access_token and should be verified by the
	// client before use.
	ATHash string `json:"at_hash,omitempty"`
	// AuthTime is when the token was issued if max_age was requested.
	AuthTime *int64 `json:"auth_time,omitempty"`
	// AuthenticationContextClass represents the level of trust in this user.
	// A value of "0" means it doesn't  even meet ISO29115 level 1, so you have
	// zero trust in this user.
	AuthenticationContextClass string `json:"acr,omitempty"`
	// AuthorizedParty is the authorized party aka the client ID.
	AuthorizedParty string `json:"azp,omitempty"`
}

// Profile are claims that may be returned by requesting the
// profile scope.
//
//nolint:tagliatelle
type Profile struct {
	// Name is the user's full name.
	Name string `json:"name,omitempty"`
	// GivenName is the user's forename.
	GivenName string `json:"given_name,omitempty"`
	// FamilyName is the user's surname.
	FamilyName string `json:"family_name,omitempty"`
	// MiddleName is the user's middle name(s).
	MiddleName string `json:"middle_name,omitempty"`
	// Nickname is the user's nickname.
	Nickname string `json:"nickname,omitempty"`
	// PreferredUsername is how the user chooses to be addressed.
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Profile is a URL to the user's profile page.
	Profile string `json:"profile,omitempty"`
	// Picture is a URL to the user's picture.
	Picture string `json:"picture,omitempty"`
	// Website is a URL to the user's website.
	Website string `json:"website,omitempty"`
	// Gender is the user's gender.
	Gender string `json:"gender,omitempty"`
	// BirthDate is the users' birth date formatted according to ISO8601.  The year
	// portion may be 0000 if they choose not to reveal they are really old.
	BirthDate string `json:"birthdate,omitempty"`
	// ZoneInfo is the user's IANA assigned timezone.
	ZoneInfo string `json:"zoneinfo,omitempty"`
	// Locale is the user's RFC5646 language tag.
	Locale string `json:"locale,omitempty"`
	// UpdatedAt is when the user's profile was last updated.
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Email are claims that make be returned by requesting the
// email scope.
//
//nolint:tagliatelle
type Email struct {
	// Email is the user's email address.
	Email string `json:"email,omitempty"`
	// EmailVerified indicates whether this email address has been verified
	// and can be trusted as far as the issuer can tell.
	EmailVerified bool `json:"email_verified,omitempty"`
}

// IDToken defines an id_token.
// Reference https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
type IDToken struct {
	// Claims are the standard claims expected in a JWT.
	jwt.Claims `json:",inline"`
	// Default are claims defined by default for an id_token.
	Default `json:",inline"`
	// Profile are claims returned by the "profile" scope.
	Profile `json:",inline"`
	// Email are claims returned by the "email" scope.
	Email `json:",inline"`
}
