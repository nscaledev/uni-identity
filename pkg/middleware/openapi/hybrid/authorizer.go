/*
Copyright 2025 the Unikorn Authors.

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

package hybrid

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/common"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// HybridAuthorizer combines hybrid authentication with ACL authorization
type HybridAuthorizer struct {
	extractor     *common.BearerTokenExtractor
	authenticator *HybridAuthenticator
	aclProvider   openapi.ACLProvider
}

// NewHybridAuthorizer creates a new hybrid authorizer
func NewHybridAuthorizer(localAuth, remoteAuth openapi.Authenticator, aclProvider openapi.ACLProvider) *HybridAuthorizer {
	return &HybridAuthorizer{
		extractor:     &common.BearerTokenExtractor{},
		authenticator: NewHybridAuthenticator(localAuth, remoteAuth),
		aclProvider:   aclProvider,
	}
}

// ExtractToken extracts the bearer token from the request
func (h *HybridAuthorizer) ExtractToken(r *http.Request) (string, error) {
	return h.extractor.ExtractToken(r)
}

// Authenticate validates the token and returns user information
func (h *HybridAuthorizer) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	return h.authenticator.Authenticate(r, token)
}

// GetACL retrieves access control information
func (h *HybridAuthorizer) GetACL(ctx context.Context, organizationID string) (*identityapi.Acl, error) {
	return h.aclProvider.GetACL(ctx, organizationID)
}

// Authorize provides legacy OpenAPI3Filter compatibility
func (h *HybridAuthorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	if authentication.SecurityScheme.Type != "oauth2" {
		return nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
	}

	r := authentication.RequestValidationInput.Request

	token, err := h.ExtractToken(r)
	if err != nil {
		return nil, err
	}

	return h.Authenticate(r, token)
}