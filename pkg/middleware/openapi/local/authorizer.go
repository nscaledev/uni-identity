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

package local

import (
	"context"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"

	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/util"
)

// Authorizer provides OpenAPI based authorization middleware.
type Authorizer struct {
	authenticator *oauth2.Authenticator
	rbac          *rbac.RBAC
}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(authenticator *oauth2.Authenticator, rbac *rbac.RBAC) *Authorizer {
	return &Authorizer{
		authenticator: authenticator,
		rbac:          rbac,
	}
}

// getHTTPAuthenticationScheme grabs the scheme and token from the HTTP
// Authorization header.
func getHTTPAuthenticationScheme(r *http.Request) (string, string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		err := errorsv2.NewInvalidRequestError().
			WithSimpleCause("missing Authorization header").
			WithErrorDescription("Missing Authorization header.").
			Prefixed()

		return "", "", err
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		err := errorsv2.NewInvalidRequestError().
			WithSimpleCause("malformed Authorization header").
			WithErrorDescription("The Authorization header is malformed.").
			Prefixed()

		return "", "", err
	}

	return parts[0], parts[1], nil
}

// authorizeOAuth2 checks APIs that require and oauth2 bearer token.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (*authorization.Info, error) {
	authorizationScheme, token, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		err = errorsv2.NewInvalidRequestError().
			WithSimpleCause("invalid authorization scheme").
			WithErrorDescription("The Authorization header is malformed. It must be provided using the Bearer scheme.").
			Prefixed()

		return nil, err
	}

	userinfo, claims, err := a.authenticator.GetUserinfo(r.Context(), token)
	if err != nil {
		return nil, err
	}

	info := &authorization.Info{
		Token:    token,
		Userinfo: userinfo,
	}

	switch claims.Type {
	case oauth2.TokenTypeFederated:
		info.ClientID = claims.Federated.ClientID
	case oauth2.TokenTypeServiceAccount:
		info.ServiceAccount = true
	case oauth2.TokenTypeService:
		// All API requests will ultimately end up here as service call back
		// into the identity service to validate the token presented to the API.
		// If the token is bound to a certificate, we also expect the client
		// certificate to be presented by the first client in the chain and
		// propagated here.
		certPEM, err := authorization.ClientCertFromContext(r.Context())
		if err != nil {
			err = errorsv2.NewInvalidClientError().
				WithCause(err).
				WithErrorDescription("The operation requires a client certificate for the associated token.").
				Prefixed()

			return nil, err
		}

		certificate, err := util.GetClientCertificate(certPEM)
		if err != nil {
			err = errorsv2.NewInvalidClientError().
				WithCause(err).
				WithErrorDescription("The client certificate presented could not be parsed.").
				Prefixed()

			return nil, err
		}

		thumbprint := util.GetClientCertifcateThumbprint(certificate)

		if thumbprint != claims.Service.X509Thumbprint {
			err = errorsv2.NewInvalidClientError().
				WithSimpleCause("client certificate does not match the token").
				WithErrorDescription("The client certificate provided does not match the one associated with this token.").
				Prefixed()

			return nil, err
		}

		info.SystemAccount = true
	}

	return info, nil
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	err := errorsv2.NewInvalidTokenError().
		WithSimpleCause("unsupported security scheme").
		Prefixed()

	return nil, err
}

// GetACL retrieves access control information from the subject identified
// by the Authorize call.
func (a *Authorizer) GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error) {
	acl, err := a.rbac.GetACL(ctx, organizationID)
	if err != nil {
		if rbac.IsNotFoundError(err) {
			err = errorsv2.NewInsufficientScopeError().WithCause(err).Prefixed()
			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve ACL: %w", err).
			Prefixed()

		return nil, err
	}

	return acl, nil
}
