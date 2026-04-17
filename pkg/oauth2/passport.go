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

package oauth2

import (
	"github.com/go-jose/go-jose/v4/jwt"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

const (
	// PassportType is the JWT body claim value that identifies a passport token.
	// This is a payload claim, not a JOSE header field — auto-detection reads the
	// JWT body without verifying the signature.
	PassportType = "passport"

	// PassportIssuer is the expected issuer claim value for passport tokens.
	PassportIssuer = "uni-identity"
)

// PassportClaims are the claims embedded in a passport JWT minted by the
// /oauth2/v2/exchange endpoint and verified locally by downstream services via JWKS.
type PassportClaims struct {
	jwt.Claims `json:",inline"`

	// Type must equal PassportType. Checked without signature verification
	// during auto-detection, and again after full verification (defence-in-depth).
	Type string `json:"typ"`

	// Email is the human actor's email address. Omitted for machine accounts.
	// This is PII — do not log beyond the sub/actor verbosity level.
	Email string `json:"email,omitempty"`

	// Acctype is the account type (user, service, system).
	Acctype identityapi.AuthClaimsAcctype `json:"acctype"`

	// OrgIDs is the full set of organisations the actor can access.
	OrgIDs []string `json:"org_ids,omitempty"` //nolint:tagliatelle

	// OrgID is the organisation scope set at exchange time.
	OrgID string `json:"org_id,omitempty"` //nolint:tagliatelle

	// ProjectID is the project scope set at exchange time.
	ProjectID string `json:"project_id,omitempty"` //nolint:tagliatelle

	// Actor is the human-readable actor identifier. For human users this is
	// typically an email address — do not log.
	Actor string `json:"actor,omitempty"`

	// ACL is the embedded access control list, scoped at exchange time.
	ACL *identityapi.Acl `json:"acl,omitempty"`
}
