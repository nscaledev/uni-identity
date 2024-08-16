/*
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

package openapi

import (
	"context"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// Authorizer allows authorizers to be plugged in interchangeably.
type Authorizer interface {
	// Authorize checks the request against the OpenAPI security scheme
	// and returns the access token.
	Authorize(authentication *openapi3filter.AuthenticationInput) (string, *openapi.Userinfo, error)

	// GetACL retrieves access control information from the subject identified
	// by the Authorize call.
	GetACL(ctx context.Context, organizationID, subject string) (*openapi.Acl, error)
}
