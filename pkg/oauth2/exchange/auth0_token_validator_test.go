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

//nolint:testpackage // verifier is unexported; tests need internal access via Auth0TokenValidator literal
package exchange

import (
	"context"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

var errFakeVerifier = errors.New("verifier failed")

type fakeAuth0Verifier struct {
	claims *auth0.Claims
	err    error
}

func (f *fakeAuth0Verifier) Verify(_ context.Context, _ string) (*auth0.Claims, error) {
	if f.err != nil {
		return nil, f.err
	}

	return f.claims, nil
}

func TestAuth0TokenValidator_Source(t *testing.T) {
	t.Parallel()

	assert.Equal(t, SourceAuth0, (&Auth0TokenValidator{}).Source())
}

func TestAuth0TokenValidator_Validate(t *testing.T) {
	t.Parallel()

	t.Run("lifts claims into identity and defaults user account type", func(t *testing.T) {
		t.Parallel()

		verifier := &fakeAuth0Verifier{
			claims: &auth0.Claims{
				Claims: jwt.Claims{Subject: "auth0|user-id"},
				Email:  "user@example.com",
			},
		}

		validator := &Auth0TokenValidator{verifier: verifier}

		identity, err := validator.Validate(t.Context(), "raw-token")
		require.NoError(t, err)

		assert.Equal(t, SourceAuth0, identity.Source)
		assert.Equal(t, "auth0|user-id", identity.Subject)
		assert.Equal(t, "user@example.com", identity.Email)
		assert.Equal(t, identityapi.User, identity.AccountType)
		assert.Empty(t, identity.OrganizationIDs)
	})

	t.Run("propagates verifier errors", func(t *testing.T) {
		t.Parallel()

		validator := &Auth0TokenValidator{verifier: &fakeAuth0Verifier{err: errFakeVerifier}}

		_, err := validator.Validate(t.Context(), "raw-token")
		require.ErrorIs(t, err, errFakeVerifier)
	})
}
