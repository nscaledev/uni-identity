/*
Copyright 2022-2024 EscherCloud.
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

package openapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/client"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	OperationIgnoreRequestBodyTag = "unikorn-cloud.org/ignore-request-body"
)

var (
	ErrHeader = goerrors.New("header error")
)

type Options struct {
	// runtimeSchemaValidation enables checking of (potentially large)
	// response bodies, which does have a sizable impact on handler
	// performance.  This is intended to be on during development
	// (the default) and then disabled in production unless needed.
	runtimeSchemaValidation bool

	// runtimeSchemaValidationPanic is a more violent way of handling
	// response validation errors to catch them in development rather than
	// silently ignoring log output.
	runtimeSchemaValidationPanic bool

	// ACLCacheSize defines the size of the ACL cache.
	ACLCacheSize int

	// ACLCacheTimeout defines how long to retain an ACL before refreshing.
	ACLCacheTimeout time.Duration
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.BoolVar(&o.runtimeSchemaValidation, "runtime-schema-validation", true, "Enables runtime OpenAPI schema response validation")
	f.BoolVar(&o.runtimeSchemaValidationPanic, "runtime-schema-validation-panic", true, "Enables a panic on OpenAPI schema response validation error")
	f.IntVar(&o.ACLCacheSize, "acl-cache-size", 1<<16, "Size of the ACL cache")
	f.DurationVar(&o.ACLCacheTimeout, "acl-cache-timeout", time.Minute, "Duration to cache ACLs for")
}

// authorizationInfo is request local storage to propagate authorization
// info from the OpenAPI validation.
type authorizationInfo struct {
	// info is the authorization info containing the token, any claims
	// and other available metadata.  It is only set for APIs that
	// are protected by oauth2.
	info *authorization.Info

	// acl is available when info is also set.
	acl *identityapi.Acl

	// err is used to indicate the actual openapi error.
	err error
}

type authorizationInfoKeyType int

const (
	authorizationInfoKey authorizationInfoKeyType = iota
)

func newContextWithAuthorizationInfo(ctx context.Context, info *authorizationInfo) context.Context {
	return context.WithValue(ctx, authorizationInfoKey, info)
}

func authorizationInfoFromContext(ctx context.Context) (*authorizationInfo, error) {
	v, ok := ctx.Value(authorizationInfoKey).(*authorizationInfo)
	if !ok {
		return nil, fmt.Errorf("%w: authorization into not in context", coreerrors.ErrKey)
	}

	return v, nil
}

// Validator provides Schema validation of request and response codes,
// media, and schema validation of payloads to ensure we are meeting the
// specification.
type Validator struct {
	// options define any runtime options.
	options *Options

	// authorizer provides security policy enforcement.
	authorizer Authorizer

	// scheam caches the OpenAPI schema.
	schema *openapi.Schema

	// acls caches ACLs and ensures they time out peridically.
	acls *cache.LRUExpireCache[string, *identityapi.Acl]
}

// NewValidator returns an initialized validator middleware.
func NewValidator(options *Options, authorizer Authorizer, schema *openapi.Schema) *Validator {
	return &Validator{
		options:    options,
		authorizer: authorizer,
		schema:     schema,
		acls:       cache.NewLRUExpireCache[string, *identityapi.Acl](options.ACLCacheSize),
	}
}

// hasHTTPAuthorization checks to see if an authorization header is present in
// the request.
func hasHTTPAuthorization(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}

// validateAuthentication is invoked on an oauth2 endpoint.  It is responsible for extracting
// and validating the bearer token provided by the client which is cryptographically secure.
// However, rather than have to worry about multiple different server ports, different
// middlewares and joining all that up across global rate limits (for now) we also multiplex
// plain mTLS authentication across the same handler.
func (v *Validator) validateAuthentication(ctx context.Context, input *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	request := input.RequestValidationInput.Request

	// Handle mTLS.
	// NOTE: Be VERY careful here, when service B is relaying service A's certificate to the
	// identity service, it does so via a custom header, and this can be spoofed very easily
	// by a mailicious actor.  We must ensure this was propagated over mTLS to establish trust
	// with the relaying party, as the ingress controller will not allow those headers to
	// be set by an end user.  Failure to do so will result in a privilege escalation.
	if !hasHTTPAuthorization(request) {
		// This ensures the connection is over MTLS.
		if _, err := util.GetClientCertificateHeader(request.Header); err != nil {
			return nil, errors.OAuth2AccessDenied("credentials must be provided").WithError(err)
		}

		// Grab the certificate that is actually making this request
		// and set the authorization context's subject directly from the
		// certificate's common name.
		certPEM, err := authorization.ClientCertFromContext(ctx)
		if err != nil {
			return nil, err
		}

		certificate, err := util.GetClientCertificate(certPEM)
		if err != nil {
			return nil, err
		}

		info := &authorization.Info{
			SystemAccount: true,
			Userinfo: &identityapi.Userinfo{
				Sub: certificate.Subject.CommonName,
			},
		}

		return info, nil
	}

	return v.authorizer.Authorize(input)
}

func (v *Validator) validateRequest(r *http.Request, route *routers.Route, params map[string]string) (*openapi3filter.ResponseValidationInput, error) {
	// This authorization callback is fired if the API endpoint is marked as
	// requiring it.
	authorizationFunc := func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		authInfo, err := authorizationInfoFromContext(ctx)
		if err != nil {
			return err
		}

		// This call performs an OIDC userinfo call to authenticate the token
		// with identity and to extract auditing information.
		info, err := v.validateAuthentication(ctx, input)
		if err != nil {
			authInfo.err = err
			return err
		}

		authInfo.info = info

		// Add the principal to the context, the ACL call will use the internal
		// identity client, and that requires a principal to be present.
		ctx, err = v.extractOrGeneratePrincipal(ctx, r, params, authInfo.info.Userinfo.Sub)
		if err != nil {
			authInfo.err = errors.OAuth2InvalidRequest("principal propagation failure for authentication").WithError(err)
			return err
		}

		// This happens every call, so do some caching to improve throughput.
		acl, ok := v.acls.Get(info.Userinfo.Sub)
		if !ok {
			// Get the ACL associated with the actor.
			acl, err = v.authorizer.GetACL(authorization.NewContext(ctx, info), params["organizationID"])
			if err != nil {
				authInfo.err = err
				return err
			}

			v.acls.Add(info.Userinfo.Sub, acl, v.options.ACLCacheTimeout)
		}

		authInfo.acl = acl

		return nil
	}

	ignoreRequestBody := slices.Contains(route.Operation.Tags, OperationIgnoreRequestBodyTag)
	body := r.Body

	if ignoreRequestBody {
		// Setting the option ExcludeRequestBody below will make the filter skip schema validation
		// of the request body. But it'll still unconditionally read the whole body in to pass to
		// security validation. So, to be sure it can't read it, we set the request body to nil,
		// and restore it afterward.
		r.Body = nil
	}

	options := &openapi3filter.Options{
		IncludeResponseStatus: true,
		AuthenticationFunc:    authorizationFunc,
		ExcludeRequestBody:    ignoreRequestBody,
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

	// Only restore it if we took it away. The validation filter will read r.Body into
	// with a buffer, so the likelihood is `body` would be exhausted if we left it there.
	if ignoreRequestBody {
		r.Body = body
	}

	responseValidationInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestValidationInput,
		Options:                options,
	}

	return responseValidationInput, nil
}

// generatePrincipal is called by non-system API services e.g. CLI/UI, and creates
// principal information from the request itself.
func (v *Validator) generatePrincipal(ctx context.Context, params map[string]string, subject string) context.Context {
	p := &principal.Principal{
		OrganizationID: params["organizationID"],
		ProjectID:      params["projectID"],
		Actor:          subject,
	}

	return principal.NewContext(ctx, p)
}

// extractPrincipal makes available the identity information for the user
// that actually insigated the request so it can be propagated to and used
// by any service.  This is called only by other system services as
// identified by the use of mTLS.
func extractPrincipal(ctx context.Context, r *http.Request) (context.Context, error) {
	header := r.Header.Get(principal.Header)
	if header == "" {
		return nil, fmt.Errorf("%w: principal header not present", ErrHeader)
	}

	data, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		// TODO: fallback, delete me... I am VERY slow.
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

		if err := client.VerifyAndDecode(p, header, certificate); err != nil {
			return nil, err
		}

		return principal.NewContext(ctx, p), nil
	}

	p := &principal.Principal{}

	if err := json.Unmarshal(data, p); err != nil {
		return nil, err
	}

	return principal.NewContext(ctx, p), nil
}

// extractOrGeneratePrincipal extracts the principal if mTLS is in use, for service to service
// API calls, otherwise it generates it from the available information.
func (v *Validator) extractOrGeneratePrincipal(ctx context.Context, r *http.Request, params map[string]string, subject string) (context.Context, error) {
	if util.HasClientCertificateHeader(r.Header) {
		newCtx, err := extractPrincipal(ctx, r)
		if err != nil {
			return nil, err
		}

		return newCtx, nil
	}

	return v.generatePrincipal(ctx, params, subject), nil
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
		return nil, nil, err
	}

	return r, responseValidationInput, nil
}

// Handle builds up any expected contextual information for the handlers and dispatches
// it.  Once complete this will also validate the OpenAPI response.
func (v *Validator) handle(ctx context.Context, w http.ResponseWriter, r *http.Request, responseValidationInput *openapi3filter.ResponseValidationInput, params map[string]string, next http.Handler) error {
	authInfo, err := authorizationInfoFromContext(ctx)
	if err != nil {
		return err
	}

	// If any authentication was requested as part of the route, then update anything
	// that needs doing.
	if authInfo.info != nil {
		// Propagate authentication/authorization info to the handlers
		// for the pursposes of auditing and RBAC.
		ctx = authorization.NewContext(ctx, authInfo.info)
		ctx = rbac.NewContext(ctx, authInfo.acl)

		// Trusted clients using mTLS must provide principal information in the headers.
		// Other clients (UI/CLI) generate principal information from token introspection
		// data.
		var err error

		ctx, err = v.extractOrGeneratePrincipal(ctx, r, params, authInfo.info.Userinfo.Sub)
		if err != nil {
			return errors.OAuth2InvalidRequest("identity info propagation failure").WithError(err)
		}
	}

	// Replace the authorization context with the handler context.
	r = r.WithContext(ctx)

	if v.options.runtimeSchemaValidation {
		response := middleware.CaptureResponse(w, r, next)

		responseValidationInput.Status = response.StatusCode()
		responseValidationInput.Header = w.Header()
		responseValidationInput.Body = io.NopCloser(response.Body())

		if err := openapi3filter.ValidateResponse(ctx, responseValidationInput); err != nil {
			if v.options.runtimeSchemaValidationPanic {
				panic(err)
			}

			log.FromContext(ctx).Error(err, "response openapi schema validation failure")
		}
	} else {
		next.ServeHTTP(w, r)
	}

	return nil
}

// handler implements the http.Handler interface.
func (v *Validator) handler(w http.ResponseWriter, r *http.Request, next http.Handler) {
	route, parameters, err := v.schema.FindRoute(r)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	authInfo := &authorizationInfo{}

	ctx := newContextWithAuthorizationInfo(r.Context(), authInfo)

	validatedRequest, responseValidationInput, err := v.validateAndAuthorize(ctx, r, route, parameters)
	if err != nil {
		if authInfo.err != nil {
			err = authInfo.err
		}

		errors.HandleError(w, r, err)

		return
	}

	if err := v.handle(ctx, w, validatedRequest, responseValidationInput, parameters, next); err != nil {
		errors.HandleError(w, r, err)
		return
	}
}

// Middleware returns a function that generates per-request
// middleware functions.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.handler(w, r, next)
	})
}
