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

package mtlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

// MTLSServer is a test server that provides mTLS (mutual TLS) authentication.
// It automatically generates a CA, server certificate, and client certificate,
// making them available for test clients. Similar to httptest.Server but with
// mTLS support.
type MTLSServer struct {
	// Server is the underlying httptest server
	server *httptest.Server

	// CACert is the CA certificate (parsed)
	CACert *x509.Certificate

	// CAKey is the CA private key
	CAKey *ecdsa.PrivateKey

	// CACertPEM is the CA certificate in PEM format
	CACertPEM []byte

	// CAKeyPEM is the CA private key in PEM format
	CAKeyPEM []byte

	// ServerCertPEM is the server certificate in PEM format
	ServerCertPEM []byte

	// ServerKeyPEM is the server private key in PEM format
	ServerKeyPEM []byte

	// ClientCertPEM is the client certificate in PEM format
	ClientCertPEM []byte

	// ClientKeyPEM is the client private key in PEM format
	ClientKeyPEM []byte
}

// NewMTLSServer creates a new mTLS test server with the given handler.
// The server automatically generates:
// - A self-signed CA certificate
// - A server certificate signed by the CA
// - A client certificate signed by the CA
//
// The server requires and verifies client certificates.
//
// Example usage:
//
//	server := mtlstest.NewMTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    w.WriteHeader(http.StatusOK)
//	}))
//	defer server.Close()
//
//	// Use server.ClientCertPEM and server.ClientKeyPEM to create client
//	// Use server.CACertPEM for client to verify server
func NewMTLSServer(handler http.Handler) (*MTLSServer, error) {
	s := &MTLSServer{}

	// Generate CA certificate
	caCert, caKey, caCertPEM, caKeyPEM, err := GenerateCACerts()
	if err != nil {
		return nil, err
	}

	s.CACert = caCert
	s.CAKey = caKey
	s.CACertPEM = caCertPEM
	s.CAKeyPEM = caKeyPEM

	// Generate server certificate signed by CA
	serverCertPEM, serverKeyPEM, err := generateCertificate("test-server", caCert, caKey)
	if err != nil {
		return nil, err
	}

	s.ServerCertPEM = serverCertPEM
	s.ServerKeyPEM = serverKeyPEM

	// Generate client certificate signed by CA
	clientCertPEM, clientKeyPEM, err := generateCertificate("test-client", caCert, caKey)
	if err != nil {
		return nil, err
	}

	s.ClientCertPEM = clientCertPEM
	s.ClientKeyPEM = clientKeyPEM

	// Create CA pool for client certificate verification
	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(caCertPEM)

	// Load server certificate
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, err
	}

	// Create httptest server
	server := httptest.NewUnstartedServer(handler)

	// Configure TLS before starting
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server.StartTLS()

	s.server = server

	return s, nil
}

func (s *MTLSServer) URL() string {
	return s.server.URL
}

// Close shuts down the server and blocks until all outstanding requests
// have completed.
func (s *MTLSServer) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

// ClientTLSConfig returns a *tls.Config suitable for clients connecting to
// this mTLS server. The config includes the client certificate and trusts
// the server's CA.
func (s *MTLSServer) ClientTLSConfig() (*tls.Config, error) {
	// Load client certificate
	clientCert, err := tls.X509KeyPair(s.ClientCertPEM, s.ClientKeyPEM)
	if err != nil {
		return nil, err
	}

	// Create CA pool to trust the server
	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(s.CACertPEM)

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverCAPool,
	}, nil
}

// Client returns an *http.Client configured to use mTLS with this server.
// The client uses the generated client certificate and trusts the server's CA.
func (s *MTLSServer) Client() (*http.Client, error) {
	tlsConfig, err := s.ClientTLSConfig()
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// generateCA creates a self-signed CA certificate for testing.
func GenerateCACerts() (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return cert, privateKey, certPEM, privPEM, nil
}

// generateCertificate creates a certificate signed by the given CA for testing.
func generateCertificate(cn string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return certPEM, privPEM, nil
}
