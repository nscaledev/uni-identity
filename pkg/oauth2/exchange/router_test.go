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

package exchange_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/oauth2/exchange"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

var errFakeValidator = errors.New("boom")

// fakeValidator records which token it saw so we can assert routing happened.
type fakeValidator struct {
	source     exchange.Source
	receivedAt *string
	identity   *exchange.ValidatedIdentity
	err        error
}

func (f *fakeValidator) Source() exchange.Source { return f.source }

func (f *fakeValidator) Validate(_ context.Context, raw string) (*exchange.ValidatedIdentity, error) {
	if f.receivedAt != nil {
		*f.receivedAt = raw
	}

	if f.err != nil {
		//nolint:wrapcheck // intentionally surface the test error verbatim
		return nil, f.err
	}

	return f.identity, nil
}

func TestNewRouter(t *testing.T) {
	t.Parallel()

	t.Run("nil detector", func(t *testing.T) {
		t.Parallel()

		_, err := exchange.NewRouter(nil)
		require.Error(t, err)
	})

	t.Run("validator declares Unknown source", func(t *testing.T) {
		t.Parallel()

		detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
		_, err := exchange.NewRouter(detector, &fakeValidator{source: exchange.SourceUnknown})
		require.Error(t, err)
	})

	t.Run("duplicate validator for same source", func(t *testing.T) {
		t.Parallel()

		detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
		_, err := exchange.NewRouter(detector,
			&fakeValidator{source: exchange.SourceUNI},
			&fakeValidator{source: exchange.SourceUNI},
		)
		require.Error(t, err)
	})

	t.Run("nil validators are silently dropped", func(t *testing.T) {
		t.Parallel()

		detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
		uni := &fakeValidator{source: exchange.SourceUNI}

		_, err := exchange.NewRouter(detector, uni, nil)
		require.NoError(t, err)
	})
}

func TestRouter_Validate(t *testing.T) {
	t.Parallel()

	t.Run("dispatches to matching validator", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name           string
			token          string
			expectedSource exchange.Source
		}{
			{
				name:           "uni token routes to uni validator",
				token:          fakeJWT(t, uniIssuer),
				expectedSource: exchange.SourceUNI,
			},
			{
				name:           "auth0 token routes to auth0 validator",
				token:          fakeJWT(t, auth0Issuer),
				expectedSource: exchange.SourceAuth0,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				var seen string

				uni := &fakeValidator{
					source:   exchange.SourceUNI,
					identity: &exchange.ValidatedIdentity{Source: exchange.SourceUNI, Subject: "uni-user", AccountType: identityapi.User, OrganizationIDs: []string{"org-1"}},
				}

				auth0 := &fakeValidator{
					source:     exchange.SourceAuth0,
					receivedAt: &seen,
					identity:   &exchange.ValidatedIdentity{Source: exchange.SourceAuth0, Subject: "auth0|user", AccountType: identityapi.User, OrganizationIDs: []string{"org-1"}},
				}

				detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
				router, err := exchange.NewRouter(detector, uni, auth0)
				require.NoError(t, err)

				identity, err := router.Validate(t.Context(), tt.token)
				require.NoError(t, err)
				require.NotNil(t, identity)
				assert.Equal(t, tt.expectedSource, identity.Source)
			})
		}
	})

	t.Run("rejects unknown issuer", func(t *testing.T) {
		t.Parallel()

		uni := &fakeValidator{source: exchange.SourceUNI}
		detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
		router, err := exchange.NewRouter(detector, uni)
		require.NoError(t, err)

		_, err = router.Validate(t.Context(), fakeJWT(t, "https://attacker.example.com/"))
		require.ErrorIs(t, err, exchange.ErrUnsupportedSource)
	})

	t.Run("propagates validator error", func(t *testing.T) {
		t.Parallel()

		uni := &fakeValidator{source: exchange.SourceUNI, err: errFakeValidator}
		detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
		router, err := exchange.NewRouter(detector, uni)
		require.NoError(t, err)

		_, err = router.Validate(t.Context(), fakeJWT(t, uniIssuer))
		require.ErrorIs(t, err, errFakeValidator)
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		t.Parallel()

		uni := &fakeValidator{source: exchange.SourceUNI}
		detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
		router, err := exchange.NewRouter(detector, uni)
		require.NoError(t, err)

		_, err = router.Validate(t.Context(), "garbage")
		require.ErrorIs(t, err, exchange.ErrMalformedToken)
	})

	t.Run("rejects configured but unregistered source", func(t *testing.T) {
		t.Parallel()

		// Detector knows about Auth0, but no Auth0 validator is wired — for instance,
		// when the Auth0 verifier fails to construct at startup. Router must reject
		// rather than silently fall back to UNI.
		uni := &fakeValidator{source: exchange.SourceUNI}
		detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)
		router, err := exchange.NewRouter(detector, uni)
		require.NoError(t, err)

		_, err = router.Validate(t.Context(), fakeJWT(t, auth0Issuer))
		require.ErrorIs(t, err, exchange.ErrUnsupportedSource)
	})
}
