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
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// AccessDeniedDescription is the only description that a refused certificate
// subject gets, so that the response does not name the reason.
const AccessDeniedDescription = "access denied"

var (
	ErrClientCertificateNotPresent = errors.New("client certificate not presented")

	ErrClientCertificateError = errors.New("client certificate error")

	ErrSubjectEmpty = errors.New("certificate subject is empty")

	ErrSubjectMalformed = errors.New("certificate subject is malformed")

	ErrPeerHasCommonName = errors.New("verified peer certificate has a common name")

	ErrPeerExpired = errors.New("verified peer certificate has expired")
)

// HasClientCertificateHeader checks if mTLS is in use, thus we are being called
// from a trusted service.
//
// Deprecated: use GetImmediateCallerCertificate, which also sees a verified TLS peer.
func HasClientCertificateHeader(header http.Header) bool {
	// Nginx
	if header.Get("Ssl-Client-Cert") != "" {
		return true
	}

	return false
}

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

// HasVerifiedPeer returns true when the request arrived on a TLS connection that
// presented a client certificate.  A verified SPIFFE peer has no VerifiedChains,
// and httptest sets TLS state with no peer certificates, so this tests the peer
// certificates only.  It does not verify the certificate.  The caller must serve
// TLS with a configuration that verifies the client certificate.
func HasVerifiedPeer(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.PeerCertificates) > 0
}

// GetVerifiedPeerCertificate returns the leaf certificate of the verified TLS peer,
// in the escaped PEM form of the propagation header.  Go verifies the peer at the
// handshake only, so the expiry is checked again on each request.
func GetVerifiedPeerCertificate(r *http.Request) (string, error) {
	if !HasVerifiedPeer(r) {
		return "", ErrClientCertificateNotPresent
	}

	leaf := r.TLS.PeerCertificates[0]

	if time.Now().After(leaf.NotAfter) {
		return "", ErrPeerExpired
	}

	if leaf.Subject.CommonName != "" {
		return "", ErrPeerHasCommonName
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaf.Raw,
	})

	return url.QueryEscape(string(certPEM)), nil
}

// GetImmediateCallerCertificate returns the certificate of the caller on this
// connection: the verified TLS peer when there is one, otherwise the certificate
// from the ingress headers.
func GetImmediateCallerCertificate(r *http.Request) (string, error) {
	if HasVerifiedPeer(r) {
		return GetVerifiedPeerCertificate(r)
	}

	return GetClientCertificateHeader(r.Header)
}

// GetClientCertificateSubject returns the subject of a certificate: the common
// name, or else exactly one SPIFFE ID URI SAN.  A common name that starts with
// "spiffe://" is refused, so that a subject is either a common name or a
// SPIFFE ID.
func GetClientCertificateSubject(certificate *x509.Certificate) (string, error) {
	if commonName := certificate.Subject.CommonName; commonName != "" {
		if strings.HasPrefix(commonName, "spiffe://") {
			return "", fmt.Errorf("%w: common name is a SPIFFE ID", ErrSubjectMalformed)
		}

		return commonName, nil
	}

	if len(certificate.URIs) == 0 {
		return "", ErrSubjectEmpty
	}

	id, err := x509svid.IDFromCert(certificate)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSubjectMalformed, err)
	}

	return id.String(), nil
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
