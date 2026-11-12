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
	"slices"

	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/util"
)

var (
	ErrRelayNotPermitted = goerrors.New("verified peer is not permitted to relay a client certificate")
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

const (
	clientCertificateHeader = "Unikorn-Client-Certificate"
)

// ExtractClientCert is called from the API to either propagate an existing
// certificate to the context, or to extract one from headers injected by TLS termination.
//
// Deprecated: use ExtractClientCertFromRequest, which also handles a verified TLS peer.
func ExtractClientCert(ctx context.Context, header http.Header) (context.Context, error) {
	if clientCert := header.Get(clientCertificateHeader); clientCert != "" {
		return NewContextWithClientCert(ctx, clientCert), nil
	}

	clientCert, err := util.GetClientCertificateHeader(header)
	if err != nil {
		// Nothing there, don't propagate.
		if goerrors.Is(err, util.ErrClientCertificateNotPresent) {
			return ctx, nil
		}

		// Something went wrong e.g. validation error.
		return nil, err
	}

	return NewContextWithClientCert(ctx, clientCert), nil
}

// ExtractClientCertFromRequest sets the client certificate in the context.  With a
// verified TLS peer, the peer is the certificate, and the ingress headers are never
// read.  The peer can relay another certificate only when its subject is one of
// relayers.  Without a verified peer, this is ExtractClientCert.
func ExtractClientCertFromRequest(ctx context.Context, r *http.Request, relayers []string) (context.Context, error) {
	if !util.HasVerifiedPeer(r) {
		return ExtractClientCert(ctx, r.Header)
	}

	peer, err := util.GetVerifiedPeerCertificate(r)
	if err != nil {
		return nil, err
	}

	relayed := r.Header.Get(clientCertificateHeader)
	if relayed == "" {
		return NewContextWithClientCert(ctx, peer), nil
	}

	subject, err := util.GetClientCertificateSubject(r.TLS.PeerCertificates[0])
	if err != nil || !slices.Contains(relayers, subject) {
		return nil, ErrRelayNotPermitted
	}

	return NewContextWithClientCert(ctx, relayed), nil
}

// InjectClientCert is called by clients to propagate the client certificate
// that started the call chain, and thus owns the access token, to the next server.
func InjectClientCert(ctx context.Context, header http.Header) {
	clientCert, err := ClientCertFromContext(ctx)
	if err == nil {
		header.Set(clientCertificateHeader, clientCert)
	}
}
