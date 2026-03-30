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

// Package mtlstest provides utilities for testing mTLS (mutual TLS) connections.
//
// MTLSServer is similar to httptest.Server but automatically sets up a complete
// mTLS environment with a CA, server certificate, and client certificate.
//
// # Basic Usage
//
// Create an mTLS server with a handler:
//
//	server, err := mtlstest.NewMTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    w.WriteHeader(http.StatusOK)
//	    w.Write([]byte("Hello, mTLS!"))
//	}))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer server.Close()
//
// Create a client that can connect to the server:
//
//	client, err := server.Client()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	resp, err := client.Get(server.URL + "/api/v1/test")
//	// ... use response
//
// # Advanced Usage
//
// Access the certificates directly for custom use cases:
//
//	// Create Kubernetes secrets with the certificates
//	serverSecret := &corev1.Secret{
//	    ObjectMeta: metav1.ObjectMeta{
//	        Name: "server-cert",
//	        Namespace: "test",
//	    },
//	    Type: corev1.SecretTypeTLS,
//	    Data: map[string][]byte{
//	        corev1.TLSCertKey:       server.ServerCertPEM,
//	        corev1.TLSPrivateKeyKey: server.ServerKeyPEM,
//	    },
//	}
//
//	clientSecret := &corev1.Secret{
//	    ObjectMeta: metav1.ObjectMeta{
//	        Name: "client-cert",
//	        Namespace: "test",
//	    },
//	    Type: corev1.SecretTypeTLS,
//	    Data: map[string][]byte{
//	        corev1.TLSCertKey:       server.ClientCertPEM,
//	        corev1.TLSPrivateKeyKey: server.ClientKeyPEM,
//	    },
//	}
//
//	caSecret := &corev1.Secret{
//	    ObjectMeta: metav1.ObjectMeta{
//	        Name: "ca-cert",
//	        Namespace: "test",
//	    },
//	    Data: map[string][]byte{
//	        corev1.TLSCertKey: server.CACertPEM,
//	    },
//	}
//
// Get a TLS config for custom client setup:
//
//	tlsConfig, err := server.ClientTLSConfig()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	client := &http.Client{
//	    Transport: &http.Transport{
//	        TLSClientConfig: tlsConfig,
//	    },
//	}
//
// # Certificate Details
//
// The generated certificates have the following properties:
//   - CA: Self-signed with KeyUsageCertSign and KeyUsageCRLSign
//   - Server cert: Signed by CA, valid for localhost, 127.0.0.1, and ::1
//   - Client cert: Signed by CA, valid for both server and client authentication
//   - All certificates: ECDSA P-521, TLS 1.3, 24-hour validity
//
// The server requires and verifies client certificates (RequireAndVerifyClientCert).
package mtlstest
