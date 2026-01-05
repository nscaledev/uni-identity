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

// HasClientCertificateHeader checks if mTLS is in use, thus we are being called
// from a trusted service.
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
