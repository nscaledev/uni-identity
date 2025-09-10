/*
Copyright 2022-2024 EscherCloud.
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

package remote

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

// Authorizer provides OpenAPI based authorization middleware.
type Authorizer struct {
	extractor     *common.BearerTokenExtractor
	authenticator *RemoteAuthenticator
	client        client.Client
	options       *identityclient.Options
	clientOptions *coreclient.HTTPClientOptions
}

var _ openapi.Authorizer = &Authorizer{}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) *Authorizer {
	return &Authorizer{
		extractor:     &common.BearerTokenExtractor{},
		authenticator: NewRemoteAuthenticator(client, options, clientOptions),
		client:        client,
		options:       options,
		clientOptions: clientOptions,
	}
}

// authorizeOAuth2 checks APIs that require and oauth2 bearer token.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (*authorization.Info, error) {
	token, err := a.extractor.ExtractToken(r)
	if err != nil {
		return nil, err
	}

	return a.authenticator.Authenticate(r, token)
}

// ExtractToken extracts the bearer token from the request
func (a *Authorizer) ExtractToken(r *http.Request) (string, error) {
	return a.extractor.ExtractToken(r)
}

// Authenticate validates the token and returns user information
func (a *Authorizer) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	return a.authenticator.Authenticate(r, token)
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	return nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}

type Getter string

func (a Getter) Get() string {
	return string(a)
}

// GetACL retrieves access control information from the subject identified
// by the Authorize call.
func (a *Authorizer) GetACL(ctx context.Context, organizationID string) (*identityapi.Acl, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	client, err := identityclient.New(a.client, a.options, a.clientOptions).APIClient(ctx, Getter(info.Token))
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create identity client").WithError(err)
	}

	if organizationID == "" {
		response, err := client.GetApiV1AclWithResponse(ctx)
		if err != nil {
			return nil, errors.OAuth2ServerError("failed to perform ACL get call").WithError(err)
		}

		if response.StatusCode() != http.StatusOK {
			return nil, errors.OAuth2ServerError("ACL get call didn't succeed")
		}

		return response.JSON200, nil
	}

	response, err := client.GetApiV1OrganizationsOrganizationIDAclWithResponse(ctx, organizationID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to perform ACL get call").WithError(err)
	}

	if response.StatusCode() != http.StatusOK {
		return nil, errors.OAuth2ServerError("ACL get call didn't succeed")
	}

	return response.JSON200, nil
}
