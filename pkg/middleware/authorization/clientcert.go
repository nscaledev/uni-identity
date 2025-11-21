/*
Copyright 2024-2025 the Unikorn Authors.

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

const clientCertKey clientCertKeyType = iota

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

const clientCertificateHeader = "Unikorn-Client-Certificate"

// ExtractClientCert is called from the API to either propagate an existing
// certificate to the context, or to extract one from headers injected by TLS termination.
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

// InjectClientCert is called by clients to propagate the client certificate
// that started the call chain, and thus owns the access token, to the next server.
func InjectClientCert(ctx context.Context, header http.Header) {
	clientCert, err := ClientCertFromContext(ctx)
	if err == nil {
		header.Set(clientCertificateHeader, clientCert)
	}
}
