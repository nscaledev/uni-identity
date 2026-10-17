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

package audit_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/yaronf/httpsign"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// signingSecretNamespace is where the test fixtures put the signing key.
const (
	signingSecretNamespace = "unikorn"
	// The name of a Secret, not a credential.
	signingSecretName = "audit-signing-key" //nolint:gosec
)

// captured is one request the collector received.
type captured struct {
	body    []byte
	headers http.Header
}

type collector struct {
	mu       sync.Mutex
	requests []captured
	status   int
	delay    time.Duration
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	c.mu.Lock()
	c.requests = append(c.requests, captured{body: body, headers: r.Header.Clone()})
	status := c.status
	delay := c.delay
	c.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	if status == 0 {
		status = http.StatusNoContent
	}

	w.WriteHeader(status)
}

func (c *collector) all() []captured {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]captured{}, c.requests...)
}

func mustSigningSecret(t *testing.T, keyID string) (*corev1.Secret, ed25519.PublicKey) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: signingSecretNamespace, Name: signingSecretName},
		Data: map[string][]byte{
			audit.SigningKeySecretID:  []byte(keyID),
			audit.SigningKeySecretKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		},
	}, public
}

// newSink wires a sink at a running collector, trusting its certificate via the
// CA secret exactly as a deployment would.
func newSink(t *testing.T, server *httptest.Server, objects ...crclient.Object) (audit.Sink, crclient.Client) {
	t.Helper()

	scheme, err := coreclient.NewScheme()
	require.NoError(t, err)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "unikorn", Name: "collector-ca"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			// The CA bundle carries no private key, so tls.key is deliberately
			// empty.  See the chart values.
			corev1.TLSCertKey: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
			}),
			corev1.TLSPrivateKeyKey: {},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(append([]crclient.Object{caSecret}, objects...)...).Build()

	options := audit.NewOptions()
	flags := pflagSetForOptions(t, options)
	require.NoError(t, flags.Parse([]string{
		"--audit-host=" + server.URL,
		"--audit-ca-secret-namespace=unikorn",
		"--audit-ca-secret-name=collector-ca",
		"--audit-signing-key-secret-namespace=unikorn",
		"--audit-signing-key-secret-name=audit-signing-key",
		"--audit-timeout=2s",
	}))

	sink, err := audit.NewHTTPSink(t.Context(), client, options)
	require.NoError(t, err)

	return sink, client
}

func testRecord() *audit.Record {
	return &audit.Record{
		Component: &audit.Component{Name: "identity", Version: "v1.2.3"},
		Actor:     &audit.Actor{Subject: "someone@example.com"},
		Operation: &audit.Operation{Verb: "delete"},
		Scope:     &audit.Scope{OrganizationID: "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
		Resource:  &audit.Resource{Type: "projects", ID: "c9bf9e57-1685-4c89-bafb-ff5af830be8a"},
		Result:    &audit.Result{Status: http.StatusNoContent},
	}
}

// The signature is what proves to a third party that we produced this body, so
// it is verified here the way a collector would, rather than merely asserted to
// be present.
func TestHTTPSinkSignsTheRequestPerRFC9421(t *testing.T) {
	t.Parallel()

	received := &collector{}
	server := httptest.NewTLSServer(received)

	defer server.Close()

	secret, public := mustSigningSecret(t, "nscale-audit-1")

	sink, _ := newSink(t, server, secret)
	sink.Emit(t.Context(), testRecord())

	requests := received.all()
	require.Len(t, requests, 1)

	request := requests[0]

	// The body is the bare record.
	var decoded audit.Record

	require.NoError(t, json.Unmarshal(request.body, &decoded))
	require.Equal(t, "c9bf9e57-1685-4c89-bafb-ff5af830be8a", decoded.Resource.ID)
	require.Equal(t, "someone@example.com", decoded.Actor.Subject)

	// Content-Digest covers the exact bytes on the wire (RFC 9530).
	sum := sha256.Sum256(request.body)
	require.Equal(t,
		"sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":",
		request.headers.Get("Content-Digest"))

	// Signature-Input names the key and covers the digest.
	input := request.headers.Get("Signature-Input")
	require.Contains(t, input, `keyid="nscale-audit-1"`)
	require.Contains(t, input, `alg="ed25519"`)
	require.Contains(t, input, `"content-digest"`)
	require.Regexp(t, `nonce="[^"]+"`, input)

	// Verify the way the collector will: with a conforming RFC 9421
	// implementation, against the registered public key.  Checking our own
	// arithmetic against itself would prove nothing.
	verify, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, bytes.NewReader(request.body))
	require.NoError(t, err)

	for name, values := range request.headers {
		verify.Header[name] = values
	}

	verifier, err := httpsign.NewEd25519Verifier(public, httpsign.NewVerifyConfig(),
		httpsign.Headers(signedComponentsForTest()...))
	require.NoError(t, err)

	require.NoError(t, httpsign.VerifyRequest("sig1", *verifier, verify))
}

// Every request must carry a fresh nonce, or the collector records a replay.
func TestHTTPSinkUsesAFreshNoncePerRequest(t *testing.T) {
	t.Parallel()

	received := &collector{}
	server := httptest.NewTLSServer(received)

	defer server.Close()

	secret, _ := mustSigningSecret(t, "nscale-audit-1")

	sink, _ := newSink(t, server, secret)
	sink.Emit(t.Context(), testRecord())
	sink.Emit(t.Context(), testRecord())

	requests := received.all()
	require.Len(t, requests, 2)

	first := nonceOf(t, requests[0].headers.Get("Signature-Input"))
	second := nonceOf(t, requests[1].headers.Get("Signature-Input"))

	require.NotEqual(t, first, second)
}

// Rotation is an atomic write of the secret, and must take effect without a
// restart.  Caching the key at startup is what this forbids.
func TestHTTPSinkPicksUpARotatedSigningKey(t *testing.T) {
	t.Parallel()

	received := &collector{}
	server := httptest.NewTLSServer(received)

	defer server.Close()

	secret, _ := mustSigningSecret(t, "nscale-audit-1")

	sink, client := newSink(t, server, secret)
	sink.Emit(t.Context(), testRecord())

	rotated, rotatedPublic := mustSigningSecret(t, "nscale-audit-2")

	current := &corev1.Secret{}
	require.NoError(t, client.Get(t.Context(), crclient.ObjectKeyFromObject(rotated), current))
	current.Data = rotated.Data
	require.NoError(t, client.Update(t.Context(), current))

	sink.Emit(t.Context(), testRecord())

	requests := received.all()
	require.Len(t, requests, 2)

	require.Contains(t, requests[0].headers.Get("Signature-Input"), `keyid="nscale-audit-1"`)
	require.Contains(t, requests[1].headers.Get("Signature-Input"), `keyid="nscale-audit-2"`, "a rotated key must be used without a restart")

	// And the new signature really is from the new key, checked by a conforming
	// verifier rather than by our own arithmetic.
	verify, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, bytes.NewReader(requests[1].body))
	require.NoError(t, err)

	for name, values := range requests[1].headers {
		verify.Header[name] = values
	}

	verifier, err := httpsign.NewEd25519Verifier(rotatedPublic, httpsign.NewVerifyConfig(),
		httpsign.Headers(signedComponentsForTest()...))
	require.NoError(t, err)

	require.NoError(t, httpsign.VerifyRequest("sig1", *verifier, verify))
}

// A collector that refuses, or is unreachable, must never surface to the
// caller.  Emit has no error return precisely so this cannot be got wrong.
func TestHTTPSinkSwallowsCollectorFailure(t *testing.T) {
	t.Parallel()

	received := &collector{status: http.StatusInternalServerError}
	server := httptest.NewTLSServer(received)

	defer server.Close()

	secret, _ := mustSigningSecret(t, "nscale-audit-1")

	sink, _ := newSink(t, server, secret)

	require.NotPanics(t, func() {
		sink.Emit(t.Context(), testRecord())
	})

	require.Len(t, received.all(), 1)
}

// A missing signing key must fail at startup, not silently ship unsigned
// records for the life of the process.
func TestNewHTTPSinkFailsWhenTheSigningKeyIsAbsent(t *testing.T) {
	t.Parallel()

	received := &collector{}
	server := httptest.NewTLSServer(received)

	defer server.Close()

	scheme, err := coreclient.NewScheme()
	require.NoError(t, err)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	options := audit.NewOptions()
	flags := pflagSetForOptions(t, options)
	require.NoError(t, flags.Parse([]string{
		"--audit-host=" + server.URL,
		"--audit-signing-key-secret-namespace=unikorn",
		"--audit-signing-key-secret-name=missing",
	}))

	_, err = audit.NewHTTPSink(t.Context(), client, options)
	require.Error(t, err)
}

func pflagSetForOptions(t *testing.T, options *audit.Options) *pflag.FlagSet {
	t.Helper()

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options.AddFlags(flags)

	return flags
}

func nonceOf(t *testing.T, input string) string {
	t.Helper()

	matches := regexp.MustCompile(`nonce="([^"]+)"`).FindStringSubmatch(input)
	require.Len(t, matches, 2, "Signature-Input must carry a nonce")

	return matches[1]
}

// parseSignatureInput reads back what we sent, so the verification side of the
// test does not simply reuse the values the signer chose.

// signedComponentsForTest mirrors the components the sink signs, so the test
// verifies the same message the collector would.
func signedComponentsForTest() []string {
	return []string{"@method", "@authority", "@path", "content-digest"}
}
