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
	"crypto/tls"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
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

	// openapi caches the Schema schema.
	openapi *openapi.Schema

	// info is the authorization info containing the token, any claims
	// and other available metadata.  It is only set for APIs that
	// are protected by oauth2.
	info *authorization.Info

	// err is used to indicate the actual openapi error.
	err error
}

// Ensure this implements the required interfaces.
var _ http.Handler = &Validator{}

// NewValidator returns an initialized validator middleware.
func NewValidator(next http.Handler, openapi *openapi.Schema) *Validator {
	return &Validator{
		next:    next,
		openapi: openapi,
	}
}

// validateMTLS makes available the identity information for the user
// that actually insigated the request so it can be propagated to and used
// by any service.  This is called only by other system services as
// identified by the use of mTLS.
func (v *Validator) validateMTLS(r *http.Request) error {
	// Use the certificate of the service that actually called us.
	// The one in the context is used to propagate token binding information.
	certRaw, err := util.GetClientCertificateHeader(r.Header)
	if err != nil {
		return err
	}

	certificate, err := util.GetClientCertificate(certRaw)
	if err != nil {
		return err
	}

	data := r.Header.Get(principal.Header)
	if data == "" {
		return fmt.Errorf("%w: principal header not present", ErrHeader)
	}

	p := &principal.Principal{}

	if err := client.VerifyAndDecode(p, data, certificate); err != nil {
		return err
	}

	v.info = &authorization.Info{
		Actor:     certificate.Subject.CommonName,
		Principal: p,
	}

	return nil
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

// NOTE: Yay, this is much cleaner, mostly.
func (v *Validator) validateOAuth2(r *http.Request, params map[string]string) error {
	ctx := r.Context()

	authorizationScheme, rawToken, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return errors.OAuth2InvalidRequest("authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	// TODO: If we are talking to identity, in development, then you need
	// a provide a CA.  This used to just use the identity client, but that injected
	// client certs, which required principals and all kinds of other stuff that
	// just isn't required.  W3C trace context would still be handy though for
	// performance profiling.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	clientCtx := oidc.ClientContext(ctx, client)

	// Perform userinfo call against the identity service that will validate the token
	// and also return some information about the user that we can use for audit logging.
	// TODO: needs an --oidc-issuer flag or something.
	provider, err := oidc.NewProvider(clientCtx, "https://identity.spjmurray.co.uk")
	if err != nil {
		return errors.OAuth2ServerError("oidc service discovery failed").WithError(err)
	}

	token := &oauth2.Token{
		AccessToken: rawToken,
		TokenType:   authorizationScheme,
	}

	ui, err := provider.UserInfo(clientCtx, oauth2.StaticTokenSource(token))
	if err != nil {
		if oidcErrorIsUnauthorized(err) {
			return errors.OAuth2AccessDenied("token validation failed").WithError(err)
		}

		return err
	}

	claims := &identityapi.Userinfo{}

	if err := ui.Claims(claims); err != nil {
		return errors.OAuth2ServerError("failed to extrac user information").WithError(err)
	}

	if claims.Email == nil {
		return errors.OAuth2ServerError("userinfo contains no email")
	}

	p := &principal.Principal{
		OrganizationID: params["organizationID"],
		ProjectID:      params["projectID"],
		Actor:          *claims.Email,
	}

	v.info = &authorization.Info{
		Token:     rawToken,
		Actor:     *claims.Email,
		Principal: p,
	}

	return nil
}

func (v *Validator) validateRequest(r *http.Request, route *routers.Route, params map[string]string) (*openapi3filter.ResponseValidationInput, error) {
	// This authorization callback is fired if the API endpoint is marked as
	// requiring it.
	authorizationFunc := func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		// mTLS means it's a service to service call, the certificate must be valid,
		// the request must have an identity principal and the actor is derived from
		// the Common Name (and may in future be a SPIFFE ID).
		if util.HasClientCertificateHeader(r.Header) {
			if err := v.validateMTLS(r); err != nil {
				v.err = err
				return err
			}

			return nil
		}

		// Otherwise the request is from an actual end user with a token that needs to
		// be forwarded on to the IdP to derive the actor.
		if err := v.validateOAuth2(r, params); err != nil {
			v.err = err
			return err
		}

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
		return nil, errors.OAuth2InvalidRequest("request body invalid").WithError(err)
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

// ServeHTTP implements the http.Handler interface.
func (v *Validator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, params, err := v.openapi.FindRoute(r)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("route lookup failure").WithError(err))
		return
	}

	responseValidationInput, err := v.validateRequest(r, route, params)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Propagate authentication info to the handlers
	// for the pursposes of auditing and RBAC.
	ctx := r.Context()
	ctx = authorization.NewContext(ctx, v.info)

	r = r.WithContext(ctx)

	response := middleware.CaptureResponse(w, r, v.next)
	v.validateResponse(response, w.Header(), r, responseValidationInput)
}

// Middleware returns a function that generates per-request
// middleware functions.
func Middleware(openapi *openapi.Schema) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return NewValidator(next, openapi)
	}
}
