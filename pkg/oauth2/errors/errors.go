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

package errors

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Error struct {
	// status is the HTTP status code to return.
	status int
	// code is the oauth2 error type to return.
	code openapi.Oauth2ErrorError
	// description is a verbose description to return.
	description string
	// error is the underlying very verbose error to log.
	err error
}

// newError returns a new HTTP error.
func newError(status int, code openapi.Oauth2ErrorError, description string) *Error {
	return &Error{
		status:      status,
		code:        code,
		description: description,
	}
}

func (e *Error) WithError(err error) *Error {
	e.err = err
	return e
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.description
}

// Write returns the error code and description to the client.
func (e *Error) Write(w http.ResponseWriter, r *http.Request) {
	// Log out any detail from the error that shouldn't be
	// reported to the client.  Do it before things can error
	// and return.
	log := log.FromContext(r.Context())

	details := []any{
		"detail", e.description,
	}

	if e.err != nil {
		details = append(details, "error", e.err)
	}

	log.Info("error detail", details...)

	// Emit the response to the client.
	w.Header().Add("Cache-Control", "no-cache")
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(e.status)

	// Emit the response body.
	ge := &openapi.Oauth2Error{
		Error:            e.code,
		ErrorDescription: e.description,
	}

	body, err := json.Marshal(ge)
	if err != nil {
		log.Error(err, "failed to marshal error response")

		return
	}

	if _, err := w.Write(body); err != nil {
		log.Error(err, "failed to write error response")

		return
	}
}

// OAuth2InvalidRequest indicates a client error.
func OAuth2InvalidRequest(description string) *Error {
	return newError(http.StatusBadRequest, openapi.InvalidRequest, description)
}

// OAuth2UnauthorizedClient indicates the client is not authorized to perform the
// requested operation.
func OAuth2UnauthorizedClient(description string) *Error {
	return newError(http.StatusBadRequest, openapi.UnauthorizedClient, description)
}

// OAuth2UnsupportedGrantType is raised when the requested grant is not supported.
func OAuth2UnsupportedGrantType(description string) *Error {
	return newError(http.StatusBadRequest, openapi.UnsupportedGrantType, description)
}

// OAuth2InvalidGrant is raised when the requested grant is unknown.
func OAuth2InvalidGrant(description string) *Error {
	return newError(http.StatusBadRequest, openapi.InvalidGrant, description)
}

// OAuth2InvalidClient is raised when the client ID is not known.
func OAuth2InvalidClient(description string) *Error {
	return newError(http.StatusBadRequest, openapi.InvalidClient, description)
}

// OAuth2AccessDenied tells the client the authentication failed e.g.
// username/password are wrong, or a token has expired and needs reauthentication.
func OAuth2AccessDenied(description string) *Error {
	return newError(http.StatusUnauthorized, openapi.AccessDenied, description)
}

// OAuth2InvalidScope tells the client it doesn't have the necessary scope
// to access the resource.
func OAuth2InvalidScope(description string) *Error {
	return newError(http.StatusUnauthorized, openapi.InvalidScope, description)
}

// oAuth2ServerError tells the client we are at fault, this should never be seen
// in production.  If so then our testing needs to improve.
func oAuth2ServerError(description string) *Error {
	return newError(http.StatusInternalServerError, openapi.ServerError, description)
}

// toError is a handy unwrapper to get a HTTP error from a generic one.
func toError(err error) *Error {
	var httpErr *Error

	if !errors.As(err, &httpErr) {
		return nil
	}

	return httpErr
}

func HandleError(w http.ResponseWriter, r *http.Request, err error) {
	if httpError := toError(err); httpError != nil {
		httpError.Write(w, r)
		return
	}

	oAuth2ServerError("an internal error has occurred, please contact support").Write(w, r)
}
