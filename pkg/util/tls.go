/*
Copyright 2024-2025 the Unikorn Authors.
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

package util

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

var (
	ErrClientCertificateNotPresent = errors.New("client certificate not presented")

	ErrClientCertificateError = errors.New("client certificate error")
)

// GetClientCertificateHeader extracts a client certificate from any present headers.
// TODO: may need to extract into a canonical form.
// NOTE: propagation at present expects this to be url encoded.
func GetClientCertificateHeader(header http.Header) (string, error) {
	// Nginx
	if cert := header.Get("Ssl-Client-Cert"); cert != "" {
		if header.Get("Ssl-Client-Verify") != "SUCCESS" {
			return "", fmt.Errorf("%w: client certificate verification header error", ErrClientCertificateError)
		}

		return cert, nil
	}

	return "", ErrClientCertificateNotPresent
}

// EncodeCertificatePEM renders a certificate as PEM, then URL-encodes it, which is
// the form the client certificate travels in through the request context and the
// relay header: GetClientCertificate always url.QueryUnescape's its input, matching
// the ingress, which sets Ssl-Client-Cert to an escaped PEM.  A raw, un-escaped PEM
// would round-trip through that unescape corrupted on almost every certificate,
// because base64 output contains a literal '+' -- which QueryUnescape turns into a
// space -- far more often than not.
func EncodeCertificatePEM(certificate *x509.Certificate) string {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})

	return url.QueryEscape(string(certPEM))
}

// GetVerifiedPeerCertificatePEM returns the peer certificate from the TLS
// connection, or the empty string when the request did not arrive over mutual TLS.
//
// It keys off PeerCertificates and NOT VerifiedChains.  go-spiffe's server config
// uses RequireAnyClientCert and verifies in VerifyPeerCertificate, so Go never
// builds a chain and VerifiedChains is empty even for a fully verified peer.  A
// handshake that failed SPIFFE verification is aborted and never reaches a handler,
// so the presence of a peer certificate here is the verified case.
func GetVerifiedPeerCertificatePEM(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}

	return EncodeCertificatePEM(r.TLS.PeerCertificates[0])
}

// GetImmediateCallerCertificatePEM returns the certificate that authenticated this
// request's own connection to this process: a peer this process verified in the TLS
// handshake, or the header the ingress verified and injected into Ssl-Client-Cert.
// It returns ErrClientCertificateNotPresent if neither is set.
//
// This answers "who is the immediate caller", and must never be confused with the
// relayed Unikorn-Client-Certificate header, which answers "which certificate owns
// this token" and can name an earlier caller in the chain rather than this
// connection -- see authorization.ExtractClientCert's precedence for that separate
// question.  Every caller that needs to know whether *this* connection was
// certificate-authenticated (the mTLS gate, and legacy signed-principal
// verification, which checks a signature against the certificate that actually
// terminated the connection) must use this and not the relay header, or a caller
// with no mTLS to this service at all could impersonate one that does.
func GetImmediateCallerCertificatePEM(r *http.Request) (string, error) {
	if peer := GetVerifiedPeerCertificatePEM(r); peer != "" {
		return peer, nil
	}

	return GetClientCertificateHeader(r.Header)
}

// GetClientCertificate retrieves the client certificate from headers injected by
// the ingress controller.
func GetClientCertificate(in string) (*x509.Certificate, error) {
	// The certificate is escaped, so undo that, then get the base64 encoded SHA256 of
	// the certificate DER information, and we will use that as a binding of the token to
	// the client certificate.  We'll use that later for authentication...
	certPEM, err := url.QueryUnescape(in)
	if err != nil {
		return nil, fmt.Errorf("%w: client certificate unescape failed", ErrClientCertificateError)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: client certificate not PEM encoded", ErrClientCertificateError)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: client certificate PEM encoding is not CERTIFICATE", ErrClientCertificateError)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: client certificate parse failed", ErrClientCertificateError)
	}

	return certificate, nil
}

// GetClientCertifcateThumbprint returns the client certificate thumbprint as defined
// by RFC8705.
func GetClientCertifcateThumbprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)

	return base64.URLEncoding.EncodeToString(sum[:])
}

// GetClientCertificateSubject resolves the identity of a calling service from its already
// verified certificate.  A common name is used when there is one.  An X509-SVID has no
// common name and carries its SPIFFE ID in a URI SAN instead, so that is the fallback.
// Only the spiffe scheme is accepted, so an unrelated URI SAN cannot become an identity.
func GetClientCertificateSubject(certificate *x509.Certificate) string {
	if certificate.Subject.CommonName != "" {
		return certificate.Subject.CommonName
	}

	for _, uri := range certificate.URIs {
		if uri.Scheme == "spiffe" {
			return uri.String()
		}
	}

	return ""
}
