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

var errFakeIntrospector = errors.New("introspect failed")

type fakeUNITokenIntrospector struct {
	identity *exchange.UNIIdentity
	err      error
}

func (f *fakeUNITokenIntrospector) IntrospectUNIToken(_ context.Context, _ string) (*exchange.UNIIdentity, error) {
	if f.err != nil {
		//nolint:wrapcheck // intentionally surface the test error verbatim
		return nil, f.err
	}

	return f.identity, nil
}

func TestUNITokenValidator_Source(t *testing.T) {
	t.Parallel()

	assert.Equal(t, exchange.SourceUNI, exchange.NewUNITokenValidator(nil).Source())
}

func TestUNITokenValidator_Validate(t *testing.T) {
	t.Parallel()

	t.Run("lifts introspector identity", func(t *testing.T) {
		t.Parallel()

		introspector := &fakeUNITokenIntrospector{
			identity: &exchange.UNIIdentity{
				Subject:         "user@example.com",
				Email:           "user@example.com",
				AccountType:     identityapi.User,
				OrganizationIDs: []string{"org-1"},
			},
		}

		validator := exchange.NewUNITokenValidator(introspector)

		identity, err := validator.Validate(t.Context(), "raw-token")
		require.NoError(t, err)

		assert.Equal(t, exchange.SourceUNI, identity.Source)
		assert.Equal(t, "user@example.com", identity.Subject)
		assert.Equal(t, identityapi.User, identity.AccountType)
		assert.Equal(t, []string{"org-1"}, identity.OrganizationIDs)
	})

	t.Run("propagates introspector error", func(t *testing.T) {
		t.Parallel()

		validator := exchange.NewUNITokenValidator(&fakeUNITokenIntrospector{err: errFakeIntrospector})

		_, err := validator.Validate(t.Context(), "raw-token")
		require.ErrorIs(t, err, errFakeIntrospector)
	})
}
