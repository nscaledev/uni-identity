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

package client

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/principal"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The generated OpenAPI clients (e.g., in pkg/openapi/client.go in this repo) have options of the same shape,
// but with types local to their package. This interface lets us build a minimal adapter
// (e.g., pkg/openapi/builder.go) from types here to those local types.
type Builder[T any] interface {
	WithHTTPClient(client *http.Client)
	WithRequestEditorFn(fn func(context.Context, *http.Request) error)
	Client(hostname string) (*T, error)
}

// BaseClient wraps up the raw OpenAPI client with things to make it useable e.g.
// authorization and TLS.
type BaseClient struct {
	// client is a Kubenetes client.
	client client.Client
	// options allows setting of options from the CLI
	options *Options
	// clientOptions may be specified to inject client certificates etc.
	clientOptions *coreclient.HTTPClientOptions
}

// NewBaseClient creates a new client.
func NewBaseClient(client client.Client, options *Options, clientOptions *coreclient.HTTPClientOptions) *BaseClient {
	return &BaseClient{
		client:        client,
		options:       options,
		clientOptions: clientOptions,
	}
}

// HTTPClient returns a new http client that will handle TLS and mTLS only.
func (c *BaseClient) HTTPClient(ctx context.Context) (*http.Client, error) {
	// Handle non-system CA certificates for the OIDC discovery protocol
	// and oauth2 token refresh. This will return nil if none is specified
	// and default to the system roots.
	tlsClientConfig, err := coreclient.TLSClientConfig(ctx, c.client, c.options, c.clientOptions)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
	}

	return client, nil
}

// AccessTokenRequestMutator sets the authorization header for authenticated endpoints.
func AccessTokenRequestMutator(accessToken AccessTokenGetter) func(context.Context, *http.Request) error {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "bearer "+accessToken.Get())
		return nil
	}
}

// TraceContextRequestMutator sets the w3c trace context header for distributed tracing.
func TraceContextRequestMutator(ctx context.Context, req *http.Request) error {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	return nil
}

// CertificateRequestMutator sets the client certifcate header when bound to an
// access token.
func CertificateRequestMutator(ctx context.Context, req *http.Request) error {
	authorization.InjectClientCert(ctx, req.Header)
	return nil
}

// APIClient returns a new OpenAPI client that can be used to access the API from another API server.
func APIClient[T any](ctx context.Context, c *BaseClient, builder Builder[T], accessToken AccessTokenGetter) (*T, error) {
	httpClient, err := c.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	builder.WithHTTPClient(httpClient)
	builder.WithRequestEditorFn(AccessTokenRequestMutator(accessToken))
	builder.WithRequestEditorFn(TraceContextRequestMutator)
	builder.WithRequestEditorFn(CertificateRequestMutator)
	builder.WithRequestEditorFn(principal.Injector(c.client, c.clientOptions))

	client, err := builder.Client(c.options.Host())
	if err != nil {
		return nil, err
	}

	return client, nil
}

// ControllerClient returns a new OpenAPI client that can be used to access the API from another
// controller.  It requires a resource that stores the identity principal information.
func ControllerClient[T any](ctx context.Context, c *BaseClient, builder Builder[T], accessToken AccessTokenGetter, resource metav1.Object) (*T, error) {
	httpClient, err := c.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	builder.WithHTTPClient(httpClient)
	builder.WithRequestEditorFn(AccessTokenRequestMutator(accessToken))
	builder.WithRequestEditorFn(TraceContextRequestMutator)
	builder.WithRequestEditorFn(CertificateRequestMutator)
	builder.WithRequestEditorFn(principal.ControllerInjector(c.client, c.clientOptions, resource))

	client, err := builder.Client(c.options.Host())
	if err != nil {
		return nil, err
	}

	return client, nil
}
