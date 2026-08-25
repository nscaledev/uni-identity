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

package principal_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/principal"
)

func TestPrincipalIssuerWireCompatibility(t *testing.T) {
	t.Parallel()

	t.Run("an empty issuer is omitted", func(t *testing.T) {
		t.Parallel()

		data, err := json.Marshal(&principal.Principal{Actor: "alice@example.com"})
		require.NoError(t, err)
		require.JSONEq(t, `{"actor":"alice@example.com"}`, string(data))
	})

	t.Run("an older header decodes with an empty issuer", func(t *testing.T) {
		t.Parallel()

		var p principal.Principal

		require.NoError(t, json.Unmarshal([]byte(`{"actor":"alice@example.com"}`), &p))
		require.Empty(t, p.Issuer)
		require.Equal(t, "alice@example.com", p.Actor)
	})

	t.Run("a populated issuer survives the wire format", func(t *testing.T) {
		t.Parallel()

		want := principal.Principal{Issuer: "https://issuer.example.com/", Actor: "alice@example.com"}
		data, err := json.Marshal(&want)
		require.NoError(t, err)

		var got principal.Principal

		require.NoError(t, json.Unmarshal(data, &got))
		require.Equal(t, want, got)
	})
}
