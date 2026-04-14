/*
Copyright 2024-2025 the Unikorn Authors.
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

package types

import (
	"net/url"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// ConfigParameters are common parameters when creating an oauth2 client.
type ConfigParameters struct {
	// Host is the current HTTP 1.1 hostname.
	Host string
	// Provider describes the oauth2 provider.
	Provider *unikornv1.OAuth2Provider
}

// AuthorizationParamters are common parameters when starting the oauth2
// authorization code flow.
type AuthorizationParamters struct {
	// State is the state that's preserved across the authorization.
	State string
	// CodeVerifier is the PKCE code verifier used to compare against
	// the one supplied during exchange. OIDC only.
	CodeVerifier string
	// Nonce is the single use value required by OIDC that's encoded
	// in the id_token.  OIDC only.
	Nonce string
	// Email address of the user, used to inject the login_hint.
	// OIDC only.
	Email string
	// Query is the client query.
	Query url.Values
}

// CodeExchangeParameters are common parameters when performing the oauth2
// code exchange.
type CodeExchangeParameters struct {
	// ConfigParameters are used to contact the authorization server
	// and also for ID token validation when using OIDC.
	ConfigParameters
	// Code is the code returned by the authorization server.
	Code string
	// CodeVerifier is the corresponding key to the authorization code
	// challenge that proves we requested the token.
	CodeVerifier string
	// SkipIssuerCheck is a hack for non-compliant providers like
	// microsoft.  OIDC only.
	SkipIssuerCheck bool
}
