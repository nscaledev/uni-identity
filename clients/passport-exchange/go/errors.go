/*
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

package passportexchange

import (
	"errors"
	"fmt"
)

var (
	ErrSourceTokenRequired             = errors.New("source token is required")
	ErrBaseURLRequired                 = errors.New("base URL is required")
	ErrExchangeResponseMissingPassport = errors.New("exchange response missing passport field")
	ErrBuildExchangeRequest            = errors.New("failed to build exchange request")
	ErrEditExchangeRequest             = errors.New("failed to edit exchange request")
)

// UnauthorizedError indicates exchange endpoint authentication failure.
type UnauthorizedError struct {
	StatusCode  int
	ErrorCode   string
	Description string
}

func (e *UnauthorizedError) Error() string {
	if e.Description == "" {
		return "passport exchange unauthorized"
	}

	return fmt.Sprintf("passport exchange unauthorized: %s", e.Description)
}

// HTTPStatusError indicates non-success HTTP status from exchange endpoint.
type HTTPStatusError struct {
	StatusCode  int
	ErrorCode   string
	Description string
}

func (e *HTTPStatusError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("passport exchange failed with status %d: %s", e.StatusCode, e.Description)
	}

	return fmt.Sprintf("passport exchange failed with status %d", e.StatusCode)
}

// TransportError indicates a network or transport-level error.
type TransportError struct {
	Cause error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("passport exchange transport failure: %v", e.Cause)
}

func (e *TransportError) Unwrap() error {
	return e.Cause
}
