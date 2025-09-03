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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.22.0"
	"go.opentelemetry.io/otel/trace"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/util"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrResponse = errors.New("unexpected http response")
)

// ServiceDescriptor is used to define tracing information.
type ServiceDescriptor struct {
	// ServiceName is the name of the service.
	ServiceName string
	// ServiceVersion is the version of the service.
	ServiceVersion string
}

type TokenIssuer struct {
	// client is a Kubernetes client.
	client client.Client
	// identityOptions allow the identity host and CA to be set.
	identityOptions *Options
	// clientOptions give access to client certificate information as
	// we need to talk to identity to get a token, and then to region
	// to ensure cloud identities and networks are provisioned, as well
	// as deptovisioning them.
	clientOptions *coreclient.HTTPClientOptions
	// serviceDescriptor defines application tracing information.
	serviceDescriptor util.ServiceDescriptor
}

func NewTokenIssuer(client client.Client, identityOptions *Options, clientOptions *coreclient.HTTPClientOptions, serviceDescriptor util.ServiceDescriptor) *TokenIssuer {
	return &TokenIssuer{
		client:            client,
		identityOptions:   identityOptions,
		clientOptions:     clientOptions,
		serviceDescriptor: serviceDescriptor,
	}
}

type StaticAccessTokenGetter struct {
	accessToken string
}

func (a *StaticAccessTokenGetter) Get() string {
	return a.accessToken
}

// Issue issues an access token for the non-user client/service.
func (i *TokenIssuer) Issue(ctx context.Context) (*StaticAccessTokenGetter, error) {
	identityClient := New(i.client, i.identityOptions, i.clientOptions)

	identityHTTPClient, err := identityClient.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	// Pass that to OIDC service discovery...
	ctx = oidc.ClientContext(ctx, identityHTTPClient)

	provider, err := oidc.NewProvider(ctx, i.identityOptions.Host())
	if err != nil {
		return nil, err
	}

	endpoint := provider.Endpoint()

	// Next we delve deeper into oauth2 to perform a TLS client auth grant...
	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.TokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Start a span that covers this client use.
	// NOTE: we do this every time around, and don't do any caching so this is safe
	// for now.  Caching the client leads to having to cache the access token somehow
	// and then token rotation when it expires, so don't be too tempted to change this.
	attr := []attribute.KeyValue{
		semconv.ServiceName(i.serviceDescriptor.Name),
		semconv.ServiceVersion(i.serviceDescriptor.Version),
	}

	tracer := otel.GetTracerProvider().Tracer("access token issuer")

	spanContext, span := tracer.Start(ctx, "issue-service-token", trace.WithSpanKind(trace.SpanKindInternal), trace.WithAttributes(attr...))
	defer span.End()

	ctx = spanContext

	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(request.Header))

	response, err := identityHTTPClient.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status code %d", ErrResponse, response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	token := &identityapi.Token{}

	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	getter := &StaticAccessTokenGetter{
		accessToken: token.AccessToken,
	}

	return getter, nil
}
