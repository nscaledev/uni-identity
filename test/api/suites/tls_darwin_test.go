//go:build integration && darwin

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

package suites

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega" //nolint:revive
)

// patchTLSTransport injects the self-signed ingress CA into http.DefaultTransport.
// On macOS, Go uses the system keychain and ignores SSL_CERT_FILE, so the CA must
// be set explicitly. The non-darwin build uses a no-op.
func patchTLSTransport() {
	caCertPath := os.Getenv("IDENTITY_CA_CERT")
	if caCertPath == "" {
		caCertPath = os.Getenv("SSL_CERT_FILE")
	}

	if caCertPath == "" {
		ginkgo.GinkgoWriter.Println("WARNING: IDENTITY_CA_CERT and SSL_CERT_FILE are unset on macOS — " +
			"TLS connections to the self-signed ingress will fail")
		return
	}

	caCert, err := os.ReadFile(caCertPath)
	Expect(err).NotTo(HaveOccurred(), "reading CA cert from %s", caCertPath)

	pool := x509.NewCertPool()
	Expect(pool.AppendCertsFromPEM(caCert)).To(BeTrue(), "appending CA cert to pool")

	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}
}
