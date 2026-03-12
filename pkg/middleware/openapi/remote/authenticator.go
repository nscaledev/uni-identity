/*
Copyright 2025 the Unikorn Authors.
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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Authenticator handles authentication for OIDC tokens by calling /userinfo using HTTP(S).
type Authenticator struct {
	options    *identityclient.Options
	httpClient *http.Client
	// tokenCache is used to enhance interaction as the validation is a
	// very expensive operation.
	tokenCache *cache.LRUExpireCache
}

// NewAuthenticator creates a new remote authenticator.
func NewAuthenticator(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*Authenticator, error) {
	httpClient, err := getIdentityHTTPClient(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		options:    options,
		httpClient: httpClient,
		tokenCache: cache.NewLRUExpireCache(4096),
	}, nil
}

// Authenticate validates an external OIDC token and returns user information.
//
//nolint:cyclop
func (a *Authenticator) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	ctx := r.Context()

	// Check cache first
	if value, ok := a.tokenCache.Get(token); ok {
		claims, ok := value.(*identityapi.Userinfo)
		if !ok {
			return nil, fmt.Errorf("%w: invalid token cache data", coreerrors.ErrConsistency)
		}

		info := &authorization.Info{
			Token:    token,
			Userinfo: claims,
		}

		return info, nil
	}

	ctx = oidc.ClientContext(ctx, a.httpClient)

	// Perform userinfo call against the identity service that will validate the token
	// and also return some information about the user that we can use for audit logging.
	provider, err := oidc.NewProvider(ctx, a.options.Host())
	if err != nil {
		return nil, fmt.Errorf("%w: oidc service discovery failed", err)
	}

	// Do the call manually here to allow us to extract the correct error code and
	// headers, returned by identity.
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, provider.UserInfoEndpoint(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create userinfo request", err)
	}

	request.Header.Set("Authorization", "Bearer "+token)

	response, err := a.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to perform userinfo request", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read userinfo response body", err)
	}

	if response.StatusCode != http.StatusOK {
		// Do not propagate this error type, we need to set the WWW-Authenticate
		// header to point at this service's OIDC protected resource metadata page.
		if response.StatusCode == http.StatusUnauthorized {
			return nil, errors.AccessDenied(r, "token is invalid or has expired")
		}

		var apiErr coreapi.Error

		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("%w: failed to unmarshal userinfo error response", err)
		}

		return nil, errors.FromOpenAPIError(response.StatusCode, response.Header, &apiErr)
	}

	claims := &identityapi.Userinfo{}

	if err := json.Unmarshal(body, claims); err != nil {
		return nil, err
	}

	// The cache entry needs a timeout as a federated user may have had their rights
	// recinded and we don't know about it, and long lived tokens e.g. service accounts,
	// could still be valid for months.
	a.tokenCache.Add(token, claims, time.Hour)

	out := &authorization.Info{
		Token:    token,
		Userinfo: claims,
	}

	return out, nil
}
