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

package passport

import "errors"

var (
	// ErrNotPassport is returned when the token payload does not carry
	// typ:"passport". The caller should delegate to the remote authorizer.
	ErrNotPassport = errors.New("not a passport token")

	// ErrPassportExpired is returned when the passport's exp claim has passed.
	// Fail closed — do not fall back to the remote authorizer.
	ErrPassportExpired = errors.New("passport token has expired")

	// ErrPassportInvalidSig is returned when the JWT cannot be parsed or its
	// signature fails verification. Fail closed.
	ErrPassportInvalidSig = errors.New("passport token has an invalid signature")

	// ErrJWKSUnavailable is returned when the JWKS cannot be fetched and the
	// token is a confirmed passport. The remote authorizer cannot validate a
	// passport — return a server error, not a credential error.
	ErrJWKSUnavailable = errors.New("JWKS unavailable")

	// ErrTokenExchangeUnauthorized indicates the source token failed token exchange
	// authentication and should be surfaced as 401.
	ErrTokenExchangeUnauthorized = errors.New("token exchange unauthorized")

	// ErrTokenExchangeUnavailable indicates token exchange could not be completed
	// due to transport or upstream unavailability and should degrade to remote.
	ErrTokenExchangeUnavailable = errors.New("token exchange unavailable")

	// ErrTokenExchangeFailed indicates token exchange returned a non-retriable
	// non-success response status.
	ErrTokenExchangeFailed = errors.New("token exchange failed")

	// ErrTokenExchangeInvalidResponse indicates a malformed successful response body.
	ErrTokenExchangeInvalidResponse = errors.New("token exchange invalid response")

	// ErrTokenExchangeMissingAccessToken indicates a successful response omitted
	// the access_token field.
	ErrTokenExchangeMissingAccessToken = errors.New("token exchange response missing access token")
)
