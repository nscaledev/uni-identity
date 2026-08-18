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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/unikorn-cloud/core/pkg/spiffetest"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/util"
)

const (
	peerID     = "spiffe://example.org/ns/unikorn-region/sa/region-server"
	attackerID = "spiffe://example.org/ns/attacker/sa/attacker"
	// relayHeaderID and terminatedHeaderID name the two lower-precedence sources in
	// TestRelayedHeaderBeatsTerminatedHeaderWithoutAPeer: the relayed
	// Unikorn-Client-Certificate and the ingress-verified Ssl-Client-Cert.
	relayHeaderID      = "spiffe://example.org/ns/relay/sa/relay-service"
	terminatedHeaderID = "spiffe://example.org/ns/ingress/sa/terminated-service"
)

func requestWithPeer(t *testing.T, certificate *x509.Certificate) *http.Request {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://identity.example/api/v1/acl", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}

	return request
}

// TestPeerCertificateBeatsARelayedHeader is the criterion 3 unit test and the reason
// this design exists.  A relayed Unikorn-Client-Certificate is attacker-controlled
// from outside the cluster (finding 13); a verified TLS peer is not.  If this ever
// regresses, a bound token becomes replayable by anyone holding a public
// certificate, so the assertion is about which identity wins, not merely that one
// is present.
func TestPeerCertificateBeatsARelayedHeader(t *testing.T) {
	t.Parallel()

	// One CA for both, so the only difference between them is the SPIFFE ID.
	peer, attacker, _ := spiffetest.NewSVIDs(t, peerID, attackerID)

	request := requestWithPeer(t, peer.Certificates[0])
	request.Header.Set("Unikorn-Client-Certificate", util.EncodeCertificatePEM(attacker.Certificates[0]))

	ctx, err := authorization.ExtractClientCert(t.Context(), request)
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}

	certPEM, err := authorization.ClientCertFromContext(ctx)
	if err != nil {
		t.Fatalf("reading from context: %v", err)
	}

	certificate, err := util.GetClientCertificate(certPEM)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if got := util.GetClientCertificateSubject(certificate); got != peerID {
		t.Errorf("subject: got %q, want the verified peer %q", got, peerID)
	}

	if got := authorization.ProvenanceFromContext(ctx); got != authorization.ProvenanceVerifiedPeer {
		t.Errorf("provenance: got %q, want %q", got, authorization.ProvenanceVerifiedPeer)
	}
}

// TestRelayedHeaderStillWinsWithoutAPeer matters because onward-hop token binding
// depends on it.  On the plaintext listener there is no r.TLS, so the relayed
// certificate must keep its precedence or service B relaying service A's identity
// breaks.  Preferring the peer must be conditional on there being one.
func TestRelayedHeaderStillWinsWithoutAPeer(t *testing.T) {
	t.Parallel()

	relayed, _ := spiffetest.NewSVID(t, peerID)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://identity.example/api/v1/acl", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	request.Header.Set("Unikorn-Client-Certificate", util.EncodeCertificatePEM(relayed.Certificates[0]))

	ctx, err := authorization.ExtractClientCert(t.Context(), request)
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}

	if _, err := authorization.ClientCertFromContext(ctx); err != nil {
		t.Fatalf("relayed certificate not propagated: %v", err)
	}

	if got := authorization.ProvenanceFromContext(ctx); got != authorization.ProvenanceRelayedHeader {
		t.Errorf("provenance: got %q, want %q", got, authorization.ProvenanceRelayedHeader)
	}
}

// TestRelayedHeaderBeatsTerminatedHeaderWithoutAPeer pins the header-only ordering
// between the two lowest-precedence sources.  It was previously untested: swapping
// which of these two branches runs first produces zero failures anywhere else in
// ./pkg/..., yet getting it backwards would bind every onward-hop token to this
// hop's own certificate instead of the identity that started the call chain,
// silently breaking token binding for every relayed request on the plaintext
// listener.  Both certificates share one CA and carry different SPIFFE IDs, so the
// assertion is about which one wins, not merely that one is present.
func TestRelayedHeaderBeatsTerminatedHeaderWithoutAPeer(t *testing.T) {
	t.Parallel()

	relayed, terminated, _ := spiffetest.NewSVIDs(t, relayHeaderID, terminatedHeaderID)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://identity.example/api/v1/acl", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	request.Header.Set("Unikorn-Client-Certificate", util.EncodeCertificatePEM(relayed.Certificates[0]))
	request.Header.Set("Ssl-Client-Cert", util.EncodeCertificatePEM(terminated.Certificates[0]))
	request.Header.Set("Ssl-Client-Verify", "SUCCESS")

	ctx, err := authorization.ExtractClientCert(t.Context(), request)
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}

	certPEM, err := authorization.ClientCertFromContext(ctx)
	if err != nil {
		t.Fatalf("reading from context: %v", err)
	}

	certificate, err := util.GetClientCertificate(certPEM)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if got := util.GetClientCertificateSubject(certificate); got != relayHeaderID {
		t.Errorf("subject: got %q, want the relayed identity %q", got, relayHeaderID)
	}

	if got := authorization.ProvenanceFromContext(ctx); got != authorization.ProvenanceRelayedHeader {
		t.Errorf("provenance: got %q, want %q", got, authorization.ProvenanceRelayedHeader)
	}
}

// TestNoCertificateAnywhereIsNotAnError matters because the bearer-token path shares
// this middleware.  A browser request carries no certificate and must pass through
// with an empty context rather than being refused here.
func TestNoCertificateAnywhereIsNotAnError(t *testing.T) {
	t.Parallel()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://identity.example/api/v1/acl", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	ctx, err := authorization.ExtractClientCert(t.Context(), request)
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}

	if _, err := authorization.ClientCertFromContext(ctx); err == nil {
		t.Error("a certificate was propagated when none was present")
	}
}
