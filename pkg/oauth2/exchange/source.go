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

// Package exchange provides token-source detection and per-source validation
// for the OAuth2 exchange endpoint. It separates the "which IdP issued this
// token?" decision from the validation logic so that adding a new source is a
// new TokenValidator wired into the Router rather than conditional branches
// scattered through token issuance.
//
// The exchange path uses the Router as follows:
//
//	identity, err := router.Validate(ctx, rawToken)
//	if err != nil { ... fail closed ... }
//	passport := mintPassport(identity)  // identity.Source is propagated
//
// Only fully-verified identities ever reach passport minting. The unverified
// payload is read solely to pick a validator; trust comes from per-validator
// signature/claim checks.
package exchange

// Source identifies which IdP issued a token presented to the exchange endpoint.
// It is propagated into the minted passport so downstream services can audit
// where authorization flowed from.
type Source string

const (
	// SourceUNI denotes a token issued by this identity service.
	SourceUNI Source = "uni"

	// SourceAuth0 denotes an Auth0-issued access token validated locally via JWKS.
	SourceAuth0 Source = "auth0"

	// SourceUnknown is returned by SourceDetector when the issuer claim does not
	// match any configured validator. The exchange path must reject these.
	SourceUnknown Source = ""
)
