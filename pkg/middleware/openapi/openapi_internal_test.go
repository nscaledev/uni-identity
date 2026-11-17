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
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// TestExpiredPeerAtALaterReadRefused checks the reads of the peer certificate
// that follow the first read of a request.  A verified peer whose leaf expired
// after the first read gets the generic 401 at each later read.
func TestExpiredPeerAtALaterReadRefused(t *testing.T) {
	t.Parallel()

	userinfo := &identityapi.Userinfo{Sub: "joe@acme.com"}

	reads := map[string]func(v *Validator, r *http.Request) error{
		"system account check": func(v *Validator, r *http.Request) error {
			return v.checkSystemAccount(r, &authorization.Info{Userinfo: userinfo})
		},
		"principal": func(v *Validator, r *http.Request) error {
			_, err := v.extractOrGeneratePrincipal(r.Context(), r, nil, userinfo)

			return err
		},
	}

	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var events []AuthenticationEvent

			v := NewValidator(&Options{ACLCacheSize: 1}, nil,
				WithSystemAccounts(map[string]string{}),
				WithAuthenticationRecorder(func(_ context.Context, event AuthenticationEvent) {
					events = append(events, event)
				}),
			)

			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/protected", nil)
			require.NoError(t, err)

			r.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						NotAfter: time.Now().Add(-time.Minute),
						URIs:     []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/relayer"}},
					},
				},
			}
			r.Header.Set("Authorization", "bearer foo")
			r.Header.Set(principal.Header, "e30")

			require.True(t, errors.IsAccessDenied(read(v, r)))
			require.Len(t, events, 1)
			require.Equal(t, reasonPeerExpired, events[0].Reason)
		})
	}
}
