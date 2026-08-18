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

package authorization

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/http"

	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/util"
)

type clientCertKeyType int

const (
	clientCertKey clientCertKeyType = iota
)

// NewContextWithClientCert is used to propagate the client certificate to other clients.
// The client certificate parameter is passed verbatim from the TLS termination header, so
// should be a url encoded string.
func NewContextWithClientCert(ctx context.Context, clientCert string) context.Context {
	return context.WithValue(ctx, clientCertKey, clientCert)
}

func ClientCertFromContext(ctx context.Context) (string, error) {
	if value := ctx.Value(clientCertKey); value != nil {
		if clientCert, ok := value.(string); ok {
			return clientCert, nil
		}
	}

	return "", fmt.Errorf("%w: client certificate is not defined", errors.ErrInvalidContext)
}

type provenanceKey struct{}

func withProvenance(ctx context.Context, provenance string) context.Context {
	return context.WithValue(ctx, provenanceKey{}, provenance)
}

// ProvenanceFromContext returns where this request's client certificate came from,
// or the empty string if there is none.
func ProvenanceFromContext(ctx context.Context) string {
	provenance, ok := ctx.Value(provenanceKey{}).(string)
	if !ok {
		return ""
	}

	return provenance
}

const (
	clientCertificateHeader = "Unikorn-Client-Certificate"
)

// Provenance records where a client certificate came from, because the three
// sources carry very different weight and a 200 does not say which was used.
const (
	// ProvenanceVerifiedPeer is a certificate from the TLS connection.  Possession of
	// the private key is proven by the handshake and it cannot be set by a caller.
	ProvenanceVerifiedPeer = "verified-peer"
	// ProvenanceRelayedHeader is Unikorn-Client-Certificate, set by an upstream
	// service to carry the identity that started the call chain.  Attacker-settable
	// from outside the cluster; see finding 13.
	ProvenanceRelayedHeader = "relayed-header"
	// ProvenanceTerminatedHeader is Ssl-Client-Cert, injected by the ingress after it
	// verified the certificate itself.
	ProvenanceTerminatedHeader = "terminated-header"
)

// ExtractClientCert propagates the client certificate for this request into the
// context.
//
// Precedence is verified TLS peer, then the relay header, then the header the
// ingress injected.  The peer comes first because it is the only one of the three a
// caller cannot choose: it is proven by the handshake.  The relay header keeps its
// precedence over Ssl-Client-Cert below that, so onward-hop token binding on the
// plaintext listener behaves exactly as it did — a request with no r.TLS never
// reaches the first branch.
func ExtractClientCert(ctx context.Context, r *http.Request) (context.Context, error) {
	if peer := util.GetVerifiedPeerCertificatePEM(r); peer != "" {
		return withProvenance(NewContextWithClientCert(ctx, peer), ProvenanceVerifiedPeer), nil
	}

	if clientCert := r.Header.Get(clientCertificateHeader); clientCert != "" {
		return withProvenance(NewContextWithClientCert(ctx, clientCert), ProvenanceRelayedHeader), nil
	}

	clientCert, err := util.GetClientCertificateHeader(r.Header)
	if err != nil {
		// Nothing there, don't propagate.
		if goerrors.Is(err, util.ErrClientCertificateNotPresent) {
			return ctx, nil
		}

		// Something went wrong e.g. validation error.
		return nil, err
	}

	return withProvenance(NewContextWithClientCert(ctx, clientCert), ProvenanceTerminatedHeader), nil
}

// InjectClientCert is called by clients to propagate the client certificate
// that started the call chain, and thus owns the access token, to the next server.
func InjectClientCert(ctx context.Context, header http.Header) {
	clientCert, err := ClientCertFromContext(ctx)
	if err == nil {
		header.Set(clientCertificateHeader, clientCert)
	}
}
