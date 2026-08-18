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

package server_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/unikorn-cloud/core/pkg/spiffetest"
	"github.com/unikorn-cloud/identity/pkg/server"
)

const (
	serverID = "spiffe://example.org/ns/unikorn-identity/sa/identity-server"
	clientID = "spiffe://example.org/ns/unikorn-region/sa/region-server"
)

// serve starts a listener with the SPIFFE server config and returns its address.
// net.Listen plus tls.NewListener rather than httptest.NewTLSServer, because
// httptest injects its own certificate when Certificates is empty and we need
// GetCertificate to be the only source.
func serve(t *testing.T, config *tls.Config, handler http.Handler) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	tlsListener := tls.NewListener(listener, config)
	// ReadHeaderTimeout is required on a loopback test server too, and any small
	// value is fine here since there is no real client to be slow.
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}

	go func() {
		_ = httpServer.Serve(tlsListener)
	}()

	t.Cleanup(func() {
		_ = httpServer.Close()
	})

	return listener.Addr().String()
}

func handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.TLS.PeerCertificates[0].URIs[0].String()))
	})
}

// TestListenerRequiresAndIdentifiesAPeer matters because the whole design rests on
// the handler seeing a verified peer.  Asserting the SPIFFE ID reaches the handler,
// rather than merely that the request succeeded, is what distinguishes real mutual
// TLS from server-only TLS that happens to work.
func TestListenerRequiresAndIdentifiesAPeer(t *testing.T) {
	t.Parallel()

	// One CA for both peers, so the only thing that differs is the SPIFFE ID.  Giving
	// each peer its own root would prove nothing about verification.
	serverSVID, clientSVID, bundle := spiffetest.NewSVIDs(t, serverID, clientID)

	serverSources := &spiffetest.Source{SVID: serverSVID, Bundle: bundle}

	address := serve(t, server.SPIFFEServerTLSConfig(serverSources), handler())

	clientSources := &spiffetest.Source{SVID: clientSVID, Bundle: bundle}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(clientSources, clientSources,
				tlsconfig.AuthorizeID(spiffeid.RequireFromString(serverID))),
		},
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", response.StatusCode)
	}

	if string(body) != clientID {
		t.Errorf("peer SPIFFE ID at the handler: got %q, want %q", body, clientID)
	}
}

// TestListenerRefusesAPeerFromAnotherCA is the only thing standing between an
// arbitrary certificate a caller minted for itself and a subject that
// --system-account-roles-ids may map to a role: authorization here is AuthorizeAny, so
// bundle verification inside VerifyPeerCertificate is the whole of the check.  The two
// tests either side of it -- a trusted peer is identified, no certificate is refused --
// both keep passing if that verification stops happening, which is why this one exists.
//
// The client deliberately verifies nothing itself.  Were it given its own bundle, it
// would reject the server first and the handshake would fail for the client's reason,
// so the test would pass whether or not the server rejected anything.
func TestListenerRefusesAPeerFromAnotherCA(t *testing.T) {
	t.Parallel()

	serverSVID, bundle := spiffetest.NewSVID(t, serverID)

	// A second NewSVID call mints an independent root, which is the point: this peer's
	// certificate is well formed and correctly signed, just not by anything the server
	// trusts.
	foreignSVID, _ := spiffetest.NewSVID(t, clientID)

	address := serve(t, server.SPIFFEServerTLSConfig(&spiffetest.Source{SVID: serverSVID, Bundle: bundle}), handler())

	//nolint:gosec // G402: the point of this test is what the server rejects, not what this client verifies.
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{foreignSVID.Certificates[0].Raw},
			PrivateKey:  foreignSVID.PrivateKey,
		}},
	}

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: clientConfig}}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	// The body is read on the unexpected-success path only, because it names the
	// identity the foreign peer would have been granted, which is the escalation.
	response, err := httpClient.Do(request)
	if err == nil {
		body, _ := io.ReadAll(response.Body)

		response.Body.Close()

		t.Fatalf("a peer signed by an unrelated CA reached the handler as %q, want a handshake failure", body)
	}
}

// TestListenerRefusesAClientWithNoCertificate matters because criterion 5 requires
// the refusal to happen in the handshake.  A 401 from the handler would mean the
// request reached the bearer path, which is a different and much weaker outcome.
func TestListenerRefusesAClientWithNoCertificate(t *testing.T) {
	t.Parallel()

	serverSVID, bundle := spiffetest.NewSVID(t, serverID)

	address := serve(t, server.SPIFFEServerTLSConfig(&spiffetest.Source{SVID: serverSVID, Bundle: bundle}), handler())

	//nolint:gosec // G402: the point of this test is what the server does, not what this client verifies.
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	// A response only exists to close on the unexpected-success path: the
	// expected outcome is an error from Do, with no response at all.
	response, err := httpClient.Do(request)
	if err == nil {
		response.Body.Close()

		t.Fatal("connecting with no client certificate succeeded, want a handshake failure")
	}
}
