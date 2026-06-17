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

import (
	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
)

// AuthenticationInfo describes how this resource server authenticates the
// bearer tokens it is presented:
//
//   - Unikorn-issued tokens (users and service accounts) are the fallback and
//     are resolved via the identity service's userinfo endpoint (introspection
//     and the service-token revocation point). This needs no state here.
//   - An optional third-party IdP (users only) is validated fully locally
//     against its JWKS. thirdParty is nil when no third-party IdP is configured.
//
// The provider behaviour is hard-coded to Auth0 for now; the configuration
// (auth0.Options, with its shared --oidc-* flags) is kept generic so a
// different issuer is a config change rather than a reshape.
type AuthenticationInfo struct {
	thirdParty *auth0.Validator
}

// NewAuthenticationInfo builds the authentication info from the third-party
// OIDC options. When they are unset, the resource server accepts only
// Unikorn-issued tokens; when partially set, an error is returned.
func NewAuthenticationInfo(oidc *auth0.Options) (*AuthenticationInfo, error) {
	// Provider behaviour is hard-coded to Auth0 for now.
	validator, err := auth0.NewValidatorOrNil(*oidc)
	if err != nil {
		return nil, err
	}

	return &AuthenticationInfo{
		thirdParty: validator,
	}, nil
}
