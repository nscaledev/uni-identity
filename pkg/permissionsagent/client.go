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

// Package permissionsagent is a client for the nscale permissions agent.  The
// API contract is openapi/agent.spec.yaml.
package permissionsagent

//go:generate mockgen -source=client.go -destination=mock/agent.go -package mock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/permissionsagent/openapi"
)

const (
	// DefaultTimeout bounds one agent call when Options.Timeout is zero.
	DefaultTimeout = 250 * time.Millisecond

	// MaxBatchChecks is the most items one BatchCheck may send.
	MaxBatchChecks = 100
)

var (
	// ErrInvalidOptions means New was given options it cannot use.
	ErrInvalidOptions = errors.New("permissions agent: invalid options")
	// ErrInvalidInput means the call was refused locally, without calling the
	// agent: no subject, no batch items, or too many.
	ErrInvalidInput = errors.New("permissions agent: invalid input")
	// ErrBadRequest is a 400 from the agent, for example an unknown regionId.
	ErrBadRequest = errors.New("permissions agent: bad request")
	// ErrUnauthorized is a 401: the agent rejected the caller's own credentials.
	ErrUnauthorized = errors.New("permissions agent: unauthorized")
	// ErrForbidden is a 403.  Only status returns it; a denied check is not an
	// error.
	ErrForbidden = errors.New("permissions agent: forbidden")
	// ErrUnavailable means there is no answer: the agent could not be reached,
	// the call hit Options.Timeout, or the agent has no fresh copy (502, 503,
	// 504).  Treat it as a denial.
	ErrUnavailable = errors.New("permissions agent: unavailable")
	// ErrServer is any other error status.
	ErrServer = errors.New("permissions agent: server error")
	// ErrResponse means the agent's reply does not match the contract.
	ErrResponse = errors.New("permissions agent: malformed response")
	// ErrTrimmed means a trimmed list came back where an untrimmed one was asked
	// for.
	ErrTrimmed = errors.New("permissions agent: list is trimmed to a region")
)

// Error is an error status from the agent.  It matches one of the sentinel
// errors above with errors.Is.
type Error struct {
	StatusCode  int
	Code        string
	Description string
	TraceID     string

	kind error
}

func (e *Error) Error() string {
	if e.Description == "" {
		return fmt.Sprintf("%v: status %d", e.kind, e.StatusCode)
	}

	return fmt.Sprintf("%v: status %d: %s", e.kind, e.StatusCode, e.Description)
}

func (e *Error) Unwrap() error {
	return e.kind
}

// Agent is the permissions agent API.  Client implements it; tests can fake it.
type Agent interface {
	Check(ctx context.Context, request openapi.CheckRequest) (*openapi.CheckResult, error)
	BatchCheck(ctx context.Context, request openapi.BatchCheckRequest) (*openapi.BatchCheckResult, error)
	Permissions(ctx context.Context, params openapi.ListPermissionsParams) (*openapi.PermissionList, error)
	Status(ctx context.Context) (*openapi.Status, error)
}

// Options configure a Client.
type Options struct {
	// URL is the agent's base URL.
	URL string
	// Token is the calling service's own bearer token, sent on every call.
	// Empty sends no Authorization header, for callers that use mTLS only.
	Token string
	// Timeout bounds each call.  Zero means DefaultTimeout.
	Timeout time.Duration
	// HTTPClient sends the requests, for example one set up for mTLS.  Nil
	// means http.DefaultClient.
	HTTPClient *http.Client
}

// Client calls a permissions agent over HTTP.
type Client struct {
	api     openapi.ClientInterface
	timeout time.Duration
}

var _ Agent = (*Client)(nil)

// New returns a client for the agent at opts.URL.
func New(opts Options) (*Client, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("%w: agent URL is required", ErrInvalidOptions)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	clientOpts := []openapi.ClientOption{openapi.WithHTTPClient(httpClient)}

	if opts.Token != "" {
		clientOpts = append(clientOpts, openapi.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+opts.Token)
			return nil
		}))
	}

	api, err := openapi.NewClient(opts.URL, clientOpts...)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{api: api, timeout: timeout}, nil
}

// Check asks whether the subject may perform one item.
func (c *Client) Check(ctx context.Context, request openapi.CheckRequest) (*openapi.CheckResult, error) {
	if request.Subject == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrInvalidInput)
	}

	return call[openapi.CheckResult](ctx, c, func(ctx context.Context) (*http.Response, error) {
		return c.api.Check(ctx, request)
	})
}

// BatchCheck asks about up to MaxBatchChecks items in one call.  The results
// are in the order of request.Checks.
func (c *Client) BatchCheck(ctx context.Context, request openapi.BatchCheckRequest) (*openapi.BatchCheckResult, error) {
	switch {
	case request.Subject == "":
		return nil, fmt.Errorf("%w: subject is required", ErrInvalidInput)
	case len(request.Checks) == 0:
		return nil, fmt.Errorf("%w: no items to check", ErrInvalidInput)
	case len(request.Checks) > MaxBatchChecks:
		return nil, fmt.Errorf("%w: %d items, at most %d allowed", ErrInvalidInput, len(request.Checks), MaxBatchChecks)
	}

	out, err := call[openapi.BatchCheckResult](ctx, c, func(ctx context.Context) (*http.Response, error) {
		return c.api.BatchCheck(ctx, request)
	})
	if err != nil {
		return nil, err
	}

	// Results are matched to items by position, so a short or long reply
	// would grant or deny the wrong items.
	if len(out.Results) != len(request.Checks) {
		return nil, fmt.Errorf("%w: %d results for %d items", ErrResponse, len(out.Results), len(request.Checks))
	}

	return out, nil
}

// Permissions lists what the subject may do in one organization.  When params
// ask for untrimmed, any other form is refused with ErrTrimmed: a trimmed list
// would hide what the subject holds where other services run.
func (c *Client) Permissions(ctx context.Context, params openapi.ListPermissionsParams) (*openapi.PermissionList, error) {
	if params.Subject == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrInvalidInput)
	}

	list, err := call[openapi.PermissionList](ctx, c, func(ctx context.Context) (*http.Response, error) {
		return c.api.ListPermissions(ctx, &params)
	})
	if err != nil {
		return nil, err
	}

	if params.Untrimmed != nil && *params.Untrimmed && list.Form != openapi.Untrimmed {
		return nil, fmt.Errorf("%w: form %q", ErrTrimmed, list.Form)
	}

	return list, nil
}

// Status reads the agent's state.
func (c *Client) Status(ctx context.Context) (*openapi.Status, error) {
	return call[openapi.Status](ctx, c, func(ctx context.Context) (*http.Response, error) {
		return c.api.GetStatus(ctx)
	})
}

// call sends one request under the client timeout and decodes a 200 body, or
// returns a typed error.
func call[T any](ctx context.Context, c *Client, send func(context.Context) (*http.Response, error)) (*T, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("permissions agent: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := send(callCtx)
	if err != nil {
		return nil, transportError(ctx, err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, transportError(ctx, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, body)
	}

	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResponse, err)
	}

	return &out, nil
}

// transportError keeps the caller's own cancel or deadline apart from the
// agent being unavailable: the first is the caller's choice, not an outage.
func transportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("permissions agent: %w", ctxErr)
	}

	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func statusError(status int, body []byte) error {
	e := &Error{StatusCode: status, kind: kindOf(status)}

	// The body is best effort: a proxy in front of the agent may not send the
	// platform error shape.
	var payload coreopenapi.Error
	if json.Unmarshal(body, &payload) == nil {
		e.Code = string(payload.Error)
		e.Description = payload.ErrorDescription

		if payload.TraceId != nil {
			e.TraceID = *payload.TraceId
		}
	}

	return e
}

func kindOf(status int) error {
	switch status {
	case http.StatusBadRequest:
		return ErrBadRequest
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return ErrUnavailable
	default:
		return ErrServer
	}
}
