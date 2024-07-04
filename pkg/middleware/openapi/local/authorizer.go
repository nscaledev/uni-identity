/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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

	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
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
		return "", "", errors.OAuth2InvalidRequest("authorization header missing")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", "", errors.OAuth2InvalidRequest("authorization header malformed")
	}

	return parts[0], parts[1], nil
}

// authorizeOAuth2 checks APIs that require and oauth2 bearer token.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (string, *userinfo.UserInfo, error) {
	authorizationScheme, token, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return "", nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return "", nil, errors.OAuth2InvalidRequest("authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	info := &oauth2.VerifyInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		Token:    token,
	}

	// Check the token is from us, for us, and in date.
	claims, err := a.authenticator.Verify(r.Context(), info)
	if err != nil {
		return "", nil, errors.OAuth2AccessDenied("token validation failed").WithError(err)
	}

	ui := userinfo.UserInfo(claims.Claims)

	return token, &ui, nil
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (string, *userinfo.UserInfo, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	return "", nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}

// GetACL retrieves access control information from the subject identified
// by the Authorize call.
func (a *Authorizer) GetACL(ctx context.Context, organizationID, subject string) (*openapi.Acl, error) {
	return a.rbac.GetACL(ctx, organizationID, subject)
}
