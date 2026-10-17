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

package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/yaronf/httpsign"

	coreclient "github.com/unikorn-cloud/core/pkg/client"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ErrSigningKey is returned when the signing key cannot be loaded.
var ErrSigningKey = errors.New("audit signing key error")

// signatureLabel names our signature within the Signature-Input and Signature
// dictionaries, which RFC 9421 allows to carry several.
const signatureLabel = "sig1"

// signedComponents are the parts of the request the signature covers.  The
// digest is what binds the body: signing the digest rather than the body keeps
// the signature constant size and avoids re-serializing JSON, which is how a
// signature that should match stops matching.  See the README.
//
//nolint:gochecknoglobals
var signedComponents = []string{"@method", "@authority", "@path", "content-digest"}

// signingKey is the key and the id the collector knows it by, always read
// together so the two cannot drift.
type signingKey struct {
	id  string
	key ed25519.PrivateKey
}

// parseEd25519PrivateKey decodes a PKCS#8 PEM private key, rejecting anything
// that is not Ed25519.  Accepting another algorithm would produce signatures
// that the algorithm we declare does not describe.
func parseEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: not PEM encoded", ErrSigningKey)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningKey, err)
	}

	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not an Ed25519 key", ErrSigningKey)
	}

	return key, nil
}

// signingKeySource loads the signing key from its Secret.
type signingKeySource struct {
	client    client.Client
	namespace string
	name      string
}

// get reads the key afresh.  It MUST NOT cache: rotation is an atomic write of
// the Secret and has to take effect without a restart.  See the README's
// rotation section.
func (s *signingKeySource) get(ctx context.Context) (*signingKey, error) {
	secret := &corev1.Secret{}

	if err := s.client.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: s.name}, secret); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningKey, err)
	}

	id, ok := secret.Data[SigningKeySecretID]
	if !ok || len(id) == 0 {
		return nil, fmt.Errorf("%w: secret missing %q", ErrSigningKey, SigningKeySecretID)
	}

	material, ok := secret.Data[SigningKeySecretKey]
	if !ok || len(material) == 0 {
		return nil, fmt.Errorf("%w: secret missing %q", ErrSigningKey, SigningKeySecretKey)
	}

	key, err := parseEd25519PrivateKey(material)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningKey, err)
	}

	return &signingKey{id: string(id), key: key}, nil
}

// signingTransport adds the digest and signature to every request.  It runs as
// a RoundTripper so the digest covers exactly the bytes that go on the wire,
// rather than a re-serialization of them.
type signingTransport struct {
	next http.RoundTripper
	keys *signingKeySource
}

func (t *signingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// A RoundTripper must not modify the request it is given.
	request := r.Clone(r.Context())

	body, err := requestBody(r)
	if err != nil {
		return nil, err
	}

	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))

	// The digest covers exactly the bytes that go on the wire.  Re-serializing
	// the body to compute it is how a signature that should match stops
	// matching, because key order and whitespace are not stable across encoders.
	digest, err := httpsign.GenerateContentDigestHeader(&request.Body, []string{httpsign.DigestSha256})
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Digest", digest)
	request.Body = io.NopCloser(bytes.NewReader(body))

	key, err := t.keys.get(r.Context())
	if err != nil {
		return nil, err
	}

	config := httpsign.NewSignConfig().
		SetKeyID(key.id).
		// A fresh nonce per request, including per retry: re-sending a request
		// byte for byte is recorded by the collector as a replay.
		SetNonce(uuid.New().String())

	signer, err := httpsign.NewEd25519Signer(key.key, config, httpsign.Headers(signedComponents...))
	if err != nil {
		return nil, err
	}

	input, signature, err := httpsign.SignRequest(signatureLabel, *signer, request)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Signature-Input", input)
	request.Header.Set("Signature", signature)

	return t.next.RoundTrip(request)
}

// requestBody returns the body bytes without consuming the caller's copy.
func requestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	if r.GetBody != nil {
		body, err := r.GetBody()
		if err != nil {
			return nil, err
		}

		defer body.Close()

		return io.ReadAll(body)
	}

	return io.ReadAll(r.Body)
}

// httpSink posts records to an external collector.
type httpSink struct {
	client   *http.Client
	endpoint string
}

// NewHTTPSink returns a sink that posts audit records to the configured
// collector over mutual TLS, with an RFC 9421 signature over each body.
//
// It fails if the TLS material or signing key cannot be read, so a
// misconfiguration stops the process at startup rather than silently dropping
// audit records for its lifetime.
func NewHTTPSink(ctx context.Context, cli client.Client, options *Options) (Sink, error) {
	tlsConfig, err := coreclient.TLSClientConfig(ctx, cli, options.server, options.client)
	if err != nil {
		return nil, err
	}

	keys := &signingKeySource{
		client:    cli,
		namespace: options.signingKeyNamespace,
		name:      options.signingKeyName,
	}

	// Prove the key is readable and usable now, not at the first audited request.
	if _, err := keys.get(ctx); err != nil {
		return nil, err
	}

	return &httpSink{
		client: &http.Client{
			Transport: &signingTransport{
				next: &http.Transport{TLSClientConfig: tlsConfig},
				keys: keys,
			},
			Timeout: options.timeout,
		},
		endpoint: options.server.Host(),
	}, nil
}

// Emit delivers one record.  It reports its own failures and never returns
// them: audit delivery must not affect the request being audited.  The record
// is logged with any failure so it stays recoverable from stdout.
func (s *httpSink) Emit(ctx context.Context, record *Record) {
	logger := log.FromContext(ctx)

	body, err := json.Marshal(record)
	if err != nil {
		logger.Error(err, "audit record could not be encoded", record.logValues()...)
		return
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		logger.Error(err, "audit record could not be delivered", record.logValues()...)
		return
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		logger.Error(err, "audit record could not be delivered", record.logValues()...)
		return
	}

	defer response.Body.Close()

	// Drain so the connection can be reused.
	_, _ = io.Copy(io.Discard, response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		logger.Error(nil, "audit collector rejected the record",
			append([]any{"status", response.StatusCode}, record.logValues()...)...)
	}
}
