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

package openapi_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/idp"
)

// TestNewRemoteAuthenticationInfo asserts the convenience constructor wires the
// platform issuer into the resolver automatically — the thing a downstream
// resource server must not forget, since omitting it fails every UNI JWS closed.
func TestNewRemoteAuthenticationInfo(t *testing.T) {
	t.Parallel()

	oidc := (&idp.Options{
		Issuer:   "https://auth0.example.com/",
		Audience: "https://api.example.com",
	}).IssuerConfig()

	auth, err := openapimiddleware.NewRemoteAuthenticationInfo("https://identity.example.com", oidc)
	require.NoError(t, err)

	// The platform issuer is the routing key for our own tokens, and is trusted
	// by the resolver so a UNI JWS can be verified locally.
	assert.Equal(t, "https://identity.example.com", auth.UNIIssuer())
	assert.True(t, auth.Resolver().Trusts("https://identity.example.com"))

	// Configured external issuers are trusted; anything else is not.
	assert.True(t, auth.Resolver().Trusts("https://auth0.example.com/"))
	assert.False(t, auth.Resolver().Trusts("https://evil.example.com"))
}
