/*
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
	"fmt"
	"net/http"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ACL implements ACLProvider by calling the identity service's ACL endpoints.
type ACL struct {
	client        client.Client
	options       *identityclient.Options
	clientOptions *coreclient.HTTPClientOptions
	httpClient    *http.Client
}

// NewACL creates a new remote ACL provider.
func NewACL(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*ACL, error) {
	httpClient, err := getIdentityHTTPClient(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	return &ACL{
		client:        client,
		options:       options,
		clientOptions: clientOptions,
		httpClient:    httpClient,
	}, nil
}

// GetACL retrieves access control information from the subject identified
// by the Authorize call.
func (a *ACL) GetACL(ctx context.Context, organizationID string) (*identityapi.Acl, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Trace context and TLS are handled by the cached client.
	options := []identityapi.ClientOption{
		identityapi.WithHTTPClient(a.httpClient),
		identityapi.WithRequestEditorFn(principal.Injector(a.client, a.clientOptions)),
	}

	if info.Token != "" {
		options = append(options, identityapi.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "bearer "+info.Token)

			return nil
		}))
	}

	client, err := identityapi.NewClientWithResponses(a.options.Host(), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create identity client", err)
	}

	if organizationID == "" {
		response, err := client.GetApiV1AclWithResponse(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to perform ACL get call", err)
		}

		if response.StatusCode() != http.StatusOK {
			return nil, errors.PropagateError(response.HTTPResponse, response)
		}

		return response.JSON200, nil
	}

	response, err := client.GetApiV1OrganizationsOrganizationIDAclWithResponse(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to perform ACL get call", err)
	}

	if response.StatusCode() != http.StatusOK {
		return nil, errors.PropagateError(response.HTTPResponse, response)
	}

	return response.JSON200, nil
}
