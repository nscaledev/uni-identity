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

package enclave

import "github.com/unikorn-cloud/identity/pkg/openapi"

// OrganizationIDParameter aliases the shared type: the subset generates only
// the router, so the path parameter's type comes from the full package.
type OrganizationIDParameter = openapi.OrganizationIDParameter

// Oauth2AuthenticationScopes aliases the shared context key, so the subset
// injects the SAME key the full router does.
const Oauth2AuthenticationScopes = openapi.Oauth2AuthenticationScopes
