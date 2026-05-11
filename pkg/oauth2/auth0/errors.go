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

package auth0

import "errors"

var (
	// ErrNotConfigured indicates the Auth0 verifier is missing required configuration.
	ErrNotConfigured = errors.New("auth0 verifier not configured")

	// ErrInvalidToken indicates the token failed parsing, signature verification,
	// or one of the standard claim checks (iss, aud, exp, nbf).
	ErrInvalidToken = errors.New("auth0 token invalid")

	// ErrTokenExpired indicates the token's exp/nbf failed.
	ErrTokenExpired = errors.New("auth0 token expired")

	// ErrInsufficientScope indicates the token's scope/permissions claim does
	// not include the required exchange scope.
	ErrInsufficientScope = errors.New("auth0 token has insufficient scope")

	// ErrJWKSUnavailable indicates the JWKS endpoint could not be reached or
	// returned an unexpected response.
	ErrJWKSUnavailable = errors.New("auth0 JWKS unavailable")

	// ErrUserinfoUnavailable indicates the Auth0 /userinfo endpoint could not be
	// reached or returned a transient failure.
	ErrUserinfoUnavailable = errors.New("auth0 userinfo unavailable")

	// ErrUserinfoCircuitOpen indicates /userinfo calls are short-circuited due to
	// repeated upstream failures.
	ErrUserinfoCircuitOpen = errors.New("auth0 userinfo circuit open")
)
