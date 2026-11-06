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

package util_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/util"
)

const (
	spiffeID      = "spiffe://example.org/ns/region/sa/region"
	otherSPIFFEID = "spiffe://example.org/ns/compute/sa/compute"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

// newCertificate issues a self-signed certificate, so that Raw is set as it is
// for a certificate from a TLS handshake.
func newCertificate(t *testing.T, commonName string, uri string, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
	}

	if uri != "" {
		template.URIs = []*url.URL{mustParseURL(t, uri)}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return certificate
}

func requestWithPeer(t *testing.T, peer *x509.Certificate) *http.Request {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)
	r.TLS.PeerCertificates = []*x509.Certificate{peer}

	return r
}

func TestGetClientCertificateSubject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cn       string
		uris     []string
		expected string
	}{
		{
			name:     "a common name only is the subject",
			cn:       "unikorn-region",
			expected: "unikorn-region",
		},
		{
			name:     "a SPIFFE ID only is the subject",
			uris:     []string{spiffeID},
			expected: spiffeID,
		},
		{
			name:     "the common name wins over a SPIFFE ID",
			cn:       "unikorn-region",
			uris:     []string{spiffeID},
			expected: "unikorn-region",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			certificate := &x509.Certificate{Subject: pkix.Name{CommonName: test.cn}}

			for _, uri := range test.uris {
				certificate.URIs = append(certificate.URIs, mustParseURL(t, uri))
			}

			subject, err := util.GetClientCertificateSubject(certificate)
			require.NoError(t, err)
			require.Equal(t, test.expected, subject)
		})
	}
}

func TestGetClientCertificateSubjectRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cn       string
		uris     []string
		expected error
	}{
		{
			name:     "no common name and no URI SAN is empty",
			expected: util.ErrSubjectEmpty,
		},
		{
			name:     "a common name that starts with spiffe:// is malformed",
			cn:       spiffeID,
			expected: util.ErrSubjectMalformed,
		},
		{
			name:     "two SPIFFE IDs are malformed",
			uris:     []string{spiffeID, otherSPIFFEID},
			expected: util.ErrSubjectMalformed,
		},
		{
			name:     "a URI SAN that is not a SPIFFE ID is malformed",
			uris:     []string{"https://example.org/region"},
			expected: util.ErrSubjectMalformed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			certificate := &x509.Certificate{Subject: pkix.Name{CommonName: test.cn}}

			for _, uri := range test.uris {
				certificate.URIs = append(certificate.URIs, mustParseURL(t, uri))
			}

			subject, err := util.GetClientCertificateSubject(certificate)
			require.ErrorIs(t, err, test.expected)
			require.Empty(t, subject)
		})
	}
}

func TestGetVerifiedPeerCertificateWithoutTLS(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost/", nil)

	require.False(t, util.HasVerifiedPeer(r))

	_, err := util.GetVerifiedPeerCertificate(r)
	require.ErrorIs(t, err, util.ErrClientCertificateNotPresent)
}

// TestGetVerifiedPeerCertificateWithoutPeer covers the TLS state that httptest
// makes for an https URL: TLS is set, but no client certificate was presented.
func TestGetVerifiedPeerCertificateWithoutPeer(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)
	require.NotNil(t, r.TLS)

	require.False(t, util.HasVerifiedPeer(r))

	_, err := util.GetVerifiedPeerCertificate(r)
	require.ErrorIs(t, err, util.ErrClientCertificateNotPresent)
}

func TestGetVerifiedPeerCertificate(t *testing.T) {
	t.Parallel()

	peer := newCertificate(t, "", spiffeID, time.Now().Add(time.Hour))

	r := requestWithPeer(t, peer)

	require.True(t, util.HasVerifiedPeer(r))

	certPEM, err := util.GetVerifiedPeerCertificate(r)
	require.NoError(t, err)

	// The result has the form of the propagation header, so the shared parser
	// reads it back to the same certificate.
	certificate, err := util.GetClientCertificate(certPEM)
	require.NoError(t, err)
	require.Equal(t, peer.Raw, certificate.Raw)
}

func TestGetVerifiedPeerCertificateWithCommonName(t *testing.T) {
	t.Parallel()

	r := requestWithPeer(t, newCertificate(t, "unikorn-region", spiffeID, time.Now().Add(time.Hour)))

	_, err := util.GetVerifiedPeerCertificate(r)
	require.ErrorIs(t, err, util.ErrPeerHasCommonName)
}

// TestGetVerifiedPeerCertificateExpired stands for a connection that stays open
// after the peer certificate expires.
func TestGetVerifiedPeerCertificateExpired(t *testing.T) {
	t.Parallel()

	r := requestWithPeer(t, newCertificate(t, "", spiffeID, time.Now().Add(-time.Minute)))

	_, err := util.GetVerifiedPeerCertificate(r)
	require.ErrorIs(t, err, util.ErrPeerExpired)
}

func TestGetImmediateCallerCertificatePrefersVerifiedPeer(t *testing.T) {
	t.Parallel()

	peer := newCertificate(t, "", spiffeID, time.Now().Add(time.Hour))
	other := newCertificate(t, "unikorn-compute", "", time.Now().Add(time.Hour))

	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})

	r := requestWithPeer(t, peer)
	r.Header.Set("Ssl-Client-Cert", url.QueryEscape(string(otherPEM)))
	r.Header.Set("Ssl-Client-Verify", "SUCCESS")

	certPEM, err := util.GetImmediateCallerCertificate(r)
	require.NoError(t, err)

	certificate, err := util.GetClientCertificate(certPEM)
	require.NoError(t, err)
	require.Equal(t, peer.Raw, certificate.Raw)
}

func TestGetImmediateCallerCertificateFromHeaders(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)
	r.Header.Set("Ssl-Client-Cert", "certificate")
	r.Header.Set("Ssl-Client-Verify", "SUCCESS")

	certPEM, err := util.GetImmediateCallerCertificate(r)
	require.NoError(t, err)
	require.Equal(t, "certificate", certPEM)
}
