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

package openapi

import (
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/idp"
)

// AuthenticationInfo describes how a resource server authenticates the bearer
// tokens it is presented. It is shared by both authorizers:
//
//   - Unikorn-issued tokens (users and service accounts) are the fallback. The
//     local authorizer decrypts them in-process; the remote authorizer resolves
//     them via identity's userinfo endpoint. Neither needs state here.
//   - An optional third-party IdP (users only) is validated fully locally
//     against its JWKS. ThirdParty returns nil when none is configured.
//
// The provider behaviour is hard-coded to Auth0 for now; the configuration
// (idp.Options, with its shared --oidc-* flags) is kept generic so a different
// issuer is a config change rather than a reshape.
type AuthenticationInfo struct {
	thirdParty *idp.Validator
}

// NewAuthenticationInfo builds the authentication info from the third-party
// OIDC options. When they are unset, the resource server accepts only
// Unikorn-issued tokens; when partially set, an error is returned.
func NewAuthenticationInfo(oidc *idp.Options) (*AuthenticationInfo, error) {
	// Provider behaviour is hard-coded to Auth0 for now.
	validator, err := idp.NewValidatorOrNil(*oidc)
	if err != nil {
		return nil, err
	}

	return &AuthenticationInfo{
		thirdParty: validator,
	}, nil
}

// ThirdParty returns the third-party IdP validator, or nil when no third-party
// IdP is configured (in which case only Unikorn-issued tokens are accepted).
func (a *AuthenticationInfo) ThirdParty() *idp.Validator {
	return a.thirdParty
}
