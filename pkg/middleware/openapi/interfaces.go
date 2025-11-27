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

package openapi

//go:generate mockgen -source=interfaces.go -destination=mock/interfaces.go -package mock

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// Authenticator handles token validation and user identity extraction. This interface is for
// using internally to compose implementations of authentication and ACLs into Authorizers.
type Authenticator interface {
	// Authenticate validates a token and returns user information
	Authenticate(r *http.Request, token string) (*authorization.Info, error)
}

// ACLProvider handles access control and permissions.
type ACLProvider interface {
	// GetACL retrieves access control information from authenticated user context
	GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error)
}

// Authorizer allows authorizers to be plugged in interchangeably.
// This interface combines authentication and authorization.
type Authorizer interface {
	// Authorize checks the request against the OpenAPI security scheme
	// and returns the access token.
	Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error)

	ACLProvider
}
