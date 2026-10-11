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

package authorization_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
)

func TestExtractClientCertUsesTheRelayExactlyWhenHasRelayedClientCert(t *testing.T) {
	t.Parallel()

	relay := http.Header{authorization.ClientCertificateHeader: {"relayed-certificate"}}
	peer := http.Header{"Ssl-Client-Cert": {"peer-certificate"}, "Ssl-Client-Verify": {"SUCCESS"}}
	both := peer.Clone()
	both.Set(authorization.ClientCertificateHeader, "relayed-certificate")

	for name, header := range map[string]http.Header{"Relay": relay, "Peer": peer, "Both": both, "Neither": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, err := authorization.ExtractClientCert(t.Context(), header)
			require.NoError(t, err)

			certificate, _ := authorization.ClientCertFromContext(ctx)
			fromRelay := certificate != "" && certificate == header.Get(authorization.ClientCertificateHeader)

			require.Equal(t, authorization.HasRelayedClientCert(header), fromRelay,
				"the passport check refuses a relay only if HasRelayedClientCert sees the relay that the caller CN came from")
		})
	}
}
