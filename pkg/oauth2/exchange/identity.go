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
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// ValidatedIdentity is the source-agnostic view of a verified subject that the
// exchange path uses to mint a passport. Per-source validators are responsible
// for normalizing their claim shape into this struct before returning.
//
// All fields here are derived from claims that have passed signature and
// audience/issuer/expiry checks — passport minting may trust them without
// further validation against the original token.
type ValidatedIdentity struct {
	// Source identifies which IdP validated the token.
	Source Source

	// Subject is the subject claim — for Auth0 tokens, e.g. "auth0|user-id";
	// for UNI tokens, the subject (typically the user's email).
	Subject string

	// Email is the user's email when the IdP exposed it on the access token.
	// Empty for service tokens or when the upstream omitted it.
	Email string

	// AccountType identifies user/service/system actor classes.
	AccountType identityapi.AuthClaimsAcctype

	// OrganizationIDs is the full set of organizations the actor can access.
	OrganizationIDs []string

	// Fallback is true when identity was resolved through migration-only
	// Auth0 /userinfo fallback rather than local JWT validation.
	Fallback bool
}
