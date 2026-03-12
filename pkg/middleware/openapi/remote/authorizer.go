/*
Copyright 2022-2024 EscherCloud.
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

package authorizer

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ openapi.Authorizer = &Authorizer{}

// Authorizer provides OpenAPI based authorization middleware.
type Authorizer struct {
	extractor     *common.BearerTokenExtractor
	authenticator *Authenticator
	acl           *ACL
}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*Authorizer, error) {
	authenticator, err := NewAuthenticator(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	acl, err := NewACL(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	return &Authorizer{
		extractor:     &common.BearerTokenExtractor{},
		authenticator: authenticator,
		acl:           acl,
	}, nil
}

type requestMutatingTransport struct {
	base    http.RoundTripper
	mutator func(r *http.Request) error
}

func (t *requestMutatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.mutator(req); err != nil {
		return nil, err
	}

	return t.base.RoundTrip(req)
}

// getIdentityHTTPClient returns a raw HTTP client for the identity service
// that handles TLS, trace context and client certificate propagation.
func getIdentityHTTPClient(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*http.Client, error) {
	ctx := context.TODO()

	// The identity client neatly wraps up TLS...
	identity := identityclient.New(client, options, clientOptions)

	baseClient, err := identity.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	// We need to mutate the request to do trace context propagation and
	// client certificate propagation if it's a token bound to an X.509
	// certificate.
	mutator := func(req *http.Request) error {
		if err := identityclient.TraceContextRequestMutator(req.Context(), req); err != nil {
			return err
		}

		if err := identityclient.CertificateRequestMutator(req.Context(), req); err != nil {
			return err
		}

		return nil
	}

	// But it doesn't do request mutation, so we have to slightly hack it by
	// making a nested transport.
	httpClient := &http.Client{
		Transport: &requestMutatingTransport{
			base:    baseClient.Transport,
			mutator: mutator,
		},
	}

	return httpClient, nil
}

// authorizeOAuth2 checks APIs that require and oauth2 bearer token.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (*authorization.Info, error) {
	token, err := a.extractor.ExtractToken(r)
	if err != nil {
		return nil, err
	}

	return a.authenticator.Authenticate(r, token)
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	return nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}

// Authenticate validates the token and returns user information.
func (a *Authorizer) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	return a.authenticator.Authenticate(r, token)
}

// GetACL retrieves access control information from the subject identified
// by the Authorize call.
func (a *Authorizer) GetACL(ctx context.Context, organizationID string) (*identityapi.Acl, error) {
	return a.acl.GetACL(ctx, organizationID)
}
