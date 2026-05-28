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

package authorizer

import "errors"

var (
	// ErrTokenExchangeUnauthorized maps rejected source tokens to 401.
	ErrTokenExchangeUnauthorized = errors.New("token exchange unauthorized")

	// ErrTokenExchangeForbidden signals a valid subject token whose principal
	// is not authorized for the requested scope. Identity emits this as
	// 400 invalid_scope (RFC 6749 §5.2); the middleware projects it as 403
	// at the API edge.
	ErrTokenExchangeForbidden = errors.New("token exchange forbidden")

	// ErrTokenExchangeUnavailable classifies transport and upstream availability failures.
	ErrTokenExchangeUnavailable = errors.New("token exchange unavailable")

	// ErrTokenExchangeFailed indicates token exchange returned a non-retriable
	// non-success response status that is neither 401 nor 5xx.
	ErrTokenExchangeFailed = errors.New("token exchange failed")

	// ErrTokenExchangeInvalidResponse indicates a malformed successful response body.
	ErrTokenExchangeInvalidResponse = errors.New("token exchange invalid response")

	// ErrTokenExchangeMissingAccessToken indicates a successful response omitted
	// the access_token field.
	ErrTokenExchangeMissingAccessToken = errors.New("token exchange response missing access token")

	// ErrPassportInvalid indicates exchange returned an unusable passport payload.
	ErrPassportInvalid = errors.New("passport invalid")
)
