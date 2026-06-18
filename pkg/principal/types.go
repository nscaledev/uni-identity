/*
Copyright 2025 the Unikorn Authors.
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

package principal

import "github.com/unikorn-cloud/identity/pkg/openapi"

// Principal records the identity that instigated a request. The subject is who
// the request is performed as and attributed to; the issuer is the identity
// provider that vouched for that subject. The party actually performing an
// impersonated request (the "actor" in RFC 8693 terms) and who approved it are a
// separate, as-yet-unmodelled delegation-provenance concern.
type Principal struct {
	// OrganizationID of the originating request (optional).
	OrganizationID string `json:"organizationId,omitempty"`
	// ProjectID of the originating request (optional).
	ProjectID string `json:"projectId,omitempty"`
	// Type of the subject. This reuses the OpenAPI auth claim values.
	Type openapi.AuthClaimsAcctype `json:"type,omitempty"`
	// Subject the request is performed as: an email address for an end-user, a
	// service identifier for a system service, or the service account name.
	Subject string `json:"subject,omitempty"`
	// Issuer is the identity provider that authenticated the subject — the token
	// `iss`, or a marker for non-token (e.g. X.509) identities. Carried for audit
	// provenance.
	Issuer string `json:"issuer,omitempty"`
}
