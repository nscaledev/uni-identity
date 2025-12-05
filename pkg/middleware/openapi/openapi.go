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

package openapi

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrHeader = goerrors.New("header error")
)

// Validator provides Schema validation of request and response codes,
// media, and schema validation of payloads to ensure we are meeting the
// specification.
type Validator struct {
	// next defines the next HTTP handler in the chain.
	next http.Handler

	// authorizer provides security policy enforcement.
	authorizer Authorizer

	// openapi caches the Schema schema.
	openapi *openapi.Schema

	// info is the authorization info containing the token, any claims
	// and other available metadata.  It is only set for APIs that
	// are protected by oauth2.
	info *authorization.Info

	// acl is available when info is also set.
	acl *identityapi.Acl

	// err is used to indicate the actual openapi error.
	err error
}

// Ensure this implements the required interfaces.
var _ http.Handler = &Validator{}

// NewValidator returns an initialized validator middleware.
func NewValidator(authorizer Authorizer, next http.Handler, openapi *openapi.Schema) *Validator {
	return &Validator{
		authorizer: authorizer,
		next:       next,
		openapi:    openapi,
	}
}

func (v *Validator) validateRequest(r *http.Request, route *routers.Route, params map[string]string) (*openapi3filter.ResponseValidationInput, error) {
	// This authorization callback is fired if the API endpoint is marked as
	// requiring it.
	authorizationFunc := func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		// This call performs an OIDC userinfo call to authenticate the token
		// with identity and to extract auditing information.
		info, err := v.authorizer.Authorize(input)
		if err != nil {
			v.err = err
			return err
		}

		v.info = info

		// Add the principal to the context, the ACL call will use the internal
		// identity client, and that requires a principal to be present.
		ctx, err = v.extractOrGeneratePrincipal(ctx, r, params)
		if err != nil {
			v.err = errors.OAuth2InvalidRequest("principal propagation failure for authentication").WithError(err)
			return err
		}

		// Get the ACL associated with the actor.
		acl, err := v.authorizer.GetACL(authorization.NewContext(ctx, info), params["organizationID"])
		if err != nil {
			v.err = err
			return err
		}

		v.acl = acl

		return nil
	}

	options := &openapi3filter.Options{
		IncludeResponseStatus: true,
		AuthenticationFunc:    authorizationFunc,
	}

	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: params,
		Route:      route,
		Options:    options,
	}

	if err := openapi3filter.ValidateRequest(r.Context(), requestValidationInput); err != nil {
		return nil, errors.OAuth2InvalidRequest(err.Error())
	}

	responseValidationInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestValidationInput,
		Options:                options,
	}

	return responseValidationInput, nil
}

func (v *Validator) validateResponse(res *middleware.Capture, header http.Header, r *http.Request, responseValidationInput *openapi3filter.ResponseValidationInput) {
	responseValidationInput.Status = res.StatusCode()
	responseValidationInput.Header = header
	responseValidationInput.Body = io.NopCloser(res.Body())

	if err := openapi3filter.ValidateResponse(r.Context(), responseValidationInput); err != nil {
		log.FromContext(r.Context()).Error(err, "response openapi schema validation failure")
	}
}

// generatePrincipal is called by non-system API services e.g. CLI/UI, and creates
// principal information from the request itself.
func (v *Validator) generatePrincipal(ctx context.Context, params map[string]string) context.Context {
	p := &principal.Principal{
		OrganizationID: params["organizationID"],
		ProjectID:      params["projectID"],
		Actor:          v.info.Userinfo.Sub,
	}

	return principal.NewContext(ctx, p)
}

// extractPrincipal makes available the identity information for the user
// that actually insigated the request so it can be propagated to and used
// by any service.  This is called only by other system services as
// identified by the use of mTLS.
func extractPrincipal(ctx context.Context, r *http.Request) (context.Context, error) {
	data := r.Header.Get(principal.Header)
	if data == "" {
		return nil, fmt.Errorf("%w: principal header not present", ErrHeader)
	}

	// Use the certificate of the service that actually called us.
	// The one in the context is used to propagate token binding information.
	certRaw, err := util.GetClientCertificateHeader(r.Header)
	if err != nil {
		return nil, err
	}

	certificate, err := util.GetClientCertificate(certRaw)
	if err != nil {
		return nil, err
	}

	p := &principal.Principal{}

	if err := client.VerifyAndDecode(p, data, certificate); err != nil {
		return nil, err
	}

	return principal.NewContext(ctx, p), nil
}

// extractOrGeneratePrincipal extracts the principal if mTLS is in use, for service to service
// API calls, otherwise it generates it from the available information.
func (v *Validator) extractOrGeneratePrincipal(ctx context.Context, r *http.Request, params map[string]string) (context.Context, error) {
	if util.HasClientCertificateHeader(r.Header) {
		newCtx, err := extractPrincipal(ctx, r)
		if err != nil {
			return nil, err
		}

		return newCtx, nil
	}

	return v.generatePrincipal(ctx, params), nil
}

// validateAndAuthorize performs OpenAPI schema validation of the request, and also
// triggers an authentication callback when the APi is marked as requiring it.
// This will read the request body from the original and replace it with a buffer.
// As we are doing a shallow copy to inject authentication context information you
// must use the returned request for the HTTP handlers.
func (v *Validator) validateAndAuthorize(ctx context.Context, r *http.Request, route *routers.Route, params map[string]string) (*http.Request, *openapi3filter.ResponseValidationInput, error) {
	// If mTLS is in use, then the access token *may* be bound to the X.509 private key,
	// but only in the case where a service is using a client credentials grant.
	// As all services act on behalf of clients, we only want the client certificate to
	// be propagated to the identity service during authentication (userinfo call) and
	// authorization (ACL call), otherwise you risk it being injected where it's not
	// wanted.
	authorizationCtx, err := authorization.ExtractClientCert(ctx, r.Header)
	if err != nil {
		return nil, nil, errors.OAuth2ServerError("certificate propagation failure").WithError(err)
	}

	r = r.WithContext(authorizationCtx)

	responseValidationInput, err := v.validateRequest(r, route, params)
	if err != nil {
		// If the authenticator errored, override whatever openapi spits out.
		if v.err != nil {
			return nil, nil, v.err
		}

		return nil, nil, err
	}

	return r, responseValidationInput, nil
}

// Handle builds up any expected contextual information for the handlers and dispatches
// it.  Once complete this will also validate the OpenAPI response.
func (v *Validator) handle(ctx context.Context, w http.ResponseWriter, r *http.Request, responseValidationInput *openapi3filter.ResponseValidationInput, params map[string]string) error {
	// If any authentication was requested as part of the route, then update anything
	// that needs doing.
	if v.info != nil {
		// Propagate authentication/authorization info to the handlers
		// for the pursposes of auditing and RBAC.
		ctx = authorization.NewContext(ctx, v.info)
		ctx = rbac.NewContext(ctx, v.acl)

		// Trusted clients using mTLS must provide principal information in the headers.
		// Other clients (UI/CLI) generate principal information from token introspection
		// data.
		var err error

		ctx, err = v.extractOrGeneratePrincipal(ctx, r, params)
		if err != nil {
			return errors.OAuth2InvalidRequest("identity info propagation failure").WithError(err)
		}
	}

	// Replace the authorization context with the handler context.
	r = r.WithContext(ctx)

	response := middleware.CaptureResponse(w, r, v.next)
	v.validateResponse(response, w.Header(), r, responseValidationInput)

	return nil
}

// ServeHTTP implements the http.Handler interface.
func (v *Validator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, params, err := v.openapi.FindRoute(r)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("route lookup failure").WithError(err))
		return
	}

	validatedRequest, responseValidationInput, err := v.validateAndAuthorize(r.Context(), r, route, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := v.handle(r.Context(), w, validatedRequest, responseValidationInput, params); err != nil {
		errors.HandleError(w, r, err)
		return
	}
}

// Middleware returns a function that generates per-request
// middleware functions.
func Middleware(authorizer Authorizer, openapi *openapi.Schema) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return NewValidator(authorizer, next, openapi)
	}
}
