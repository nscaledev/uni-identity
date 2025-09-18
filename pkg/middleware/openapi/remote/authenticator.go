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

package remote

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RemoteAuthenticator handles authentication for external OIDC tokens
type RemoteAuthenticator struct {
	client        client.Client
	options       *identityclient.Options
	clientOptions *coreclient.HTTPClientOptions
	// tokenCache is used to enhance interaction as the validation is a
	// very expensive operation.
	tokenCache *cache.LRUExpireCache
}

// NewRemoteAuthenticator creates a new remote authenticator
func NewRemoteAuthenticator(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) *RemoteAuthenticator {
	return &RemoteAuthenticator{
		client:        client,
		options:       options,
		clientOptions: clientOptions,
		tokenCache:    cache.NewLRUExpireCache(4096),
	}
}

// oidcErrorIsUnauthorized tries to convert the error returned by the OIDC library
// into a proper status code, as it doesn't wrap anything useful.
// The error looks like "{code} {text code}: {body}".
func oidcErrorIsUnauthorized(err error) bool {
	// Does it look like it contains the colon?
	fields := strings.Split(err.Error(), ":")
	if len(fields) < 2 {
		return false
	}

	// What about a number followed by a string?
	fields = strings.Split(fields[0], " ")
	if len(fields) < 2 {
		return false
	}

	code, err := strconv.Atoi(fields[0])
	if err != nil {
		return false
	}

	// Is the number a 403?
	return code == http.StatusUnauthorized
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
func (a *RemoteAuthenticator) getIdentityHTTPClient(ctx context.Context) (*http.Client, error) {
	// The identity client neatly wraps up TLS...
	identity := identityclient.New(a.client, a.options, a.clientOptions)

	client, err := identity.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	// We need to mutate the request to do trace context propagation and
	// client certificate propagation if it's a token bound to an X.509
	// certificate.
	mutator := func(req *http.Request) error {
		if err := identityclient.TraceContextRequestMutator(ctx, req); err != nil {
			return err
		}

		if err := identityclient.CertificateRequestMutator(ctx, req); err != nil {
			return err
		}

		return nil
	}

	// But it doesn't do request mutation, so we have to slightly hack it by
	// making a nested transport.
	client = &http.Client{
		Transport: &requestMutatingTransport{
			base:    client.Transport,
			mutator: mutator,
		},
	}

	return client, nil
}

// Authenticate validates an external OIDC token and returns user information
func (a *RemoteAuthenticator) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	ctx := r.Context()

	// Check cache first
	if value, ok := a.tokenCache.Get(token); ok {
		claims, ok := value.(*identityapi.Userinfo)
		if !ok {
			return nil, errors.OAuth2ServerError("invalid token cache data")
		}

		info := &authorization.Info{
			Token:    token,
			Userinfo: claims,
		}

		return info, nil
	}

	client, err := a.getIdentityHTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	ctx = oidc.ClientContext(ctx, client)

	// Perform userinfo call against the identity service that will validate the token
	// and also return some information about the user that we can use for audit logging.
	provider, err := oidc.NewProvider(ctx, a.options.Host())
	if err != nil {
		return nil, errors.OAuth2ServerError("oidc service discovery failed").WithError(err)
	}

	token2 := &oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
	}

	ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token2))
	if err != nil {
		if oidcErrorIsUnauthorized(err) {
			return nil, errors.OAuth2AccessDenied("token validation failed").WithError(err)
		}

		return nil, err
	}

	claims := &identityapi.Userinfo{}

	if err := ui.Claims(claims); err != nil {
		return nil, errors.OAuth2ServerError("failed to extract user information").WithError(err)
	}

	// The cache entry needs a timeout as a federated user may have had their rights
	// recinded and we don't know about it, and long lived tokens e.g. service accounts,
	// could still be valid for months...
	a.tokenCache.Add(token, claims, time.Hour)

	out := &authorization.Info{
		Token:    token,
		Userinfo: claims,
	}

	return out, nil
}
