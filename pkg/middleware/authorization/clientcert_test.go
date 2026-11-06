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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/util"
)

const (
	relayerID      = "spiffe://example.org/ns/region/sa/region"
	relayedCert    = "relayed-certificate"
	ingressCert    = "ingress-certificate"
	relayHeader    = "Unikorn-Client-Certificate"
	ingressHeader  = "Ssl-Client-Cert"
	verifiedHeader = "Ssl-Client-Verify"
)

func newPeer(t *testing.T, commonName string, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	id, err := url.Parse(relayerID)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		URIs:      []*url.URL{id},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return certificate
}

func peerCertificate(t *testing.T, peer *x509.Certificate) string {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)
	r.TLS.PeerCertificates = []*x509.Certificate{peer}

	certificate, err := util.GetVerifiedPeerCertificate(r)
	require.NoError(t, err)

	return certificate
}

// TestExtractClientCertFromRequest has one case for each combination of a
// verified peer and the propagation headers.  Every case with a peer also sends
// ingress headers for another certificate, which must never be read.
func TestExtractClientCertFromRequest(t *testing.T) {
	t.Parallel()

	validPeer := newPeer(t, "", time.Now().Add(time.Hour))

	tests := []struct {
		name     string
		peer     *x509.Certificate
		relayed  string
		relayers []string
		ingress  string
		verified string
		expected string
		err      error
	}{
		{
			name:     "an expired peer is refused",
			peer:     newPeer(t, "", time.Now().Add(-time.Minute)),
			relayed:  relayedCert,
			relayers: []string{relayerID},
			err:      util.ErrPeerExpired,
		},
		{
			name:     "a peer with a common name is refused, also when it is a listed relayer",
			peer:     newPeer(t, "unikorn-region", time.Now().Add(time.Hour)),
			relayed:  relayedCert,
			relayers: []string{relayerID},
			err:      util.ErrPeerHasCommonName,
		},
		{
			name:     "a peer without a relay header is the certificate",
			peer:     validPeer,
			relayers: []string{relayerID},
			expected: peerCertificate(t, validPeer),
		},
		{
			name:     "a listed relayer passes on the relayed certificate",
			peer:     validPeer,
			relayed:  relayedCert,
			relayers: []string{relayerID},
			expected: relayedCert,
		},
		{
			name:    "a peer that is not a listed relayer cannot relay",
			peer:    validPeer,
			relayed: relayedCert,
			err:     authorization.ErrRelayNotPermitted,
		},
		{
			name:     "without a peer the relayed certificate is used",
			relayed:  relayedCert,
			expected: relayedCert,
		},
		{
			name:     "without a peer the verified ingress certificate is used",
			ingress:  ingressCert,
			verified: "SUCCESS",
			expected: ingressCert,
		},
		{
			name:    "without a peer an unverified ingress certificate is an error",
			ingress: ingressCert,
			err:     util.ErrClientCertificateError,
		},
		{
			name: "without a peer or headers there is no certificate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)

			if test.peer != nil {
				r.TLS.PeerCertificates = []*x509.Certificate{test.peer}
				r.Header.Set(ingressHeader, ingressCert)
				r.Header.Set(verifiedHeader, "SUCCESS")
			}

			if test.relayed != "" {
				r.Header.Set(relayHeader, test.relayed)
			}

			if test.ingress != "" {
				r.Header.Set(ingressHeader, test.ingress)
			}

			if test.verified != "" {
				r.Header.Set(verifiedHeader, test.verified)
			}

			ctx, err := authorization.ExtractClientCertFromRequest(t.Context(), r, test.relayers)
			if test.err != nil {
				require.ErrorIs(t, err, test.err)

				return
			}

			require.NoError(t, err)

			certificate, err := authorization.ClientCertFromContext(ctx)

			if test.expected == "" {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, test.expected, certificate)
		})
	}
}
