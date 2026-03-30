/*
Copyright 2025 the Unikorn Authors.
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

package mtlstest_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/mtlstest"
)

func verifyRequest(t *testing.T, s *mtlstest.MTLSServer, c *http.Client) {
	t.Helper()

	// Make request
	resp, err := c.Get(s.URL() + "/test") //nolint:noctx
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Hello, mTLS!", string(body))
}

var hello http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) { //nolint: gochecknoglobals
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello, mTLS!"))
}

func TestMTLSServer(t *testing.T) {
	t.Parallel()

	// Create mTLS server
	server, err := mtlstest.NewMTLSServer(hello)
	require.NoError(t, err)
	defer server.Close()

	// Create client with mTLS certificates
	client, err := server.Client()
	require.NoError(t, err)

	verifyRequest(t, server, client)
}

func TestMTLSServerClientWithoutCert(t *testing.T) {
	t.Parallel()

	// Create mTLS server
	server, err := mtlstest.NewMTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	require.NoError(t, err)
	defer server.Close()

	// Try to connect without client certificate (should fail)
	client := &http.Client{}

	_, err = client.Get(server.URL() + "/test") //nolint:noctx,bodyclose
	require.Error(t, err, "Connection without client certificate should fail")
}

func TestMTLSServerCertificateAvailability(t *testing.T) {
	t.Parallel()

	// Create mTLS server
	server, err := mtlstest.NewMTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	require.NoError(t, err)
	defer server.Close()

	// Verify all certificates are available
	require.NotNil(t, server.CACert)
	require.NotNil(t, server.CAKey)
	require.NotEmpty(t, server.CACertPEM)
	require.NotEmpty(t, server.CAKeyPEM)
	require.NotEmpty(t, server.ServerCertPEM)
	require.NotEmpty(t, server.ServerKeyPEM)
	require.NotEmpty(t, server.ClientCertPEM)
	require.NotEmpty(t, server.ClientKeyPEM)
	require.NotEmpty(t, server.URL)
}

func TestMTLSServerClientTLSConfig(t *testing.T) {
	t.Parallel()

	// Create mTLS server
	server, err := mtlstest.NewMTLSServer(hello)
	require.NoError(t, err)
	defer server.Close()

	// Get client TLS config
	tlsConfig, err := server.ClientTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	// Verify TLS config has client certificate
	require.Len(t, tlsConfig.Certificates, 1)
	require.NotNil(t, tlsConfig.RootCAs)

	c := &http.Client{}
	c.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	verifyRequest(t, server, c)
}
