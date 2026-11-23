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
	"net/http"
	"time"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/permissionsagent/openapi"
)

// DefaultTimeout bounds one agent call when Options.Timeout is zero.
const DefaultTimeout = 250 * time.Millisecond

var (
	// ErrInvalidOptions means New was given options it cannot use.
	ErrInvalidOptions = errors.New("permissions agent: invalid options")
	// ErrBadRequest is a 400 from the agent, for example an unknown region_id.
	ErrBadRequest = errors.New("permissions agent: bad request")
	// ErrUnauthorized is a 401: the token was refused.
	ErrUnauthorized = errors.New("permissions agent: unauthorized")
	// ErrForbidden is a 403: the caller may not use the operation, for example
	// may not act on another subject's behalf.  A denied check is not an error.
	ErrForbidden = errors.New("permissions agent: forbidden")
	// ErrUnavailable means there is no answer: the agent could not be reached,
	// timed out, or has no fresh copy (502, 503, 504).  Treat it as a denial.
	ErrUnavailable = errors.New("permissions agent: unavailable")
	// ErrServer is any other error status.
	ErrServer = errors.New("permissions agent: server error")
	// ErrResponse means the agent's reply does not match the contract.
	ErrResponse = errors.New("permissions agent: malformed response")
	// ErrTrimmed means a trimmed list came back where an untrimmed one is needed.
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

// Caller is who a call is made for.
type Caller struct {
	// Token is the user's access token, sent as a bearer token.  The agent
	// answers for its subject.  Empty sends no Authorization header.
	Token string
	// Actor, when set, is the subject acting on the user's behalf.  An item is
	// then allowed only when both are allowed.  Used by checks only.
	Actor string
}

// Agent is the permissions agent API.  Client implements it; tests can fake it.
type Agent interface {
	Check(ctx context.Context, caller Caller, item openapi.CheckItem) (*openapi.CheckResult, error)
	BatchCheck(ctx context.Context, caller Caller, items []openapi.CheckItem) (*openapi.BatchCheckResult, error)
	Permissions(ctx context.Context, caller Caller, params openapi.ListPermissionsParams) (*openapi.PermissionList, error)
	Status(ctx context.Context, caller Caller) (*openapi.Status, error)
}

// Options configure a Client.
type Options struct {
	// URL is the agent's base URL.
	URL string
	// Timeout bounds each call.  Zero means DefaultTimeout.
	Timeout time.Duration
	// HTTPClient sends the requests, for example one set up for mTLS.  Nil
	// means http.DefaultClient.
	HTTPClient *http.Client
}

// Client calls a permissions agent over HTTP.
type Client struct {
	api     openapi.ClientWithResponsesInterface
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

	api, err := openapi.NewClientWithResponses(opts.URL, openapi.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{api: api, timeout: timeout}, nil
}

func bearer(caller Caller) openapi.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if caller.Token != "" {
			req.Header.Set("Authorization", "Bearer "+caller.Token)
		}

		return nil
	}
}

func actor(caller Caller) *string {
	if caller.Actor == "" {
		return nil
	}

	return &caller.Actor
}

// Check asks whether the caller may perform one item.
func (c *Client) Check(ctx context.Context, caller Caller, item openapi.CheckItem) (*openapi.CheckResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.api.CheckWithResponse(ctx, &openapi.CheckParams{XActor: actor(caller)}, item, bearer(caller))
	if err != nil {
		return nil, transportError(err)
	}

	return result(resp.HTTPResponse, resp.Body, resp.JSON200)
}

// BatchCheck asks about many items in one call.  The answers are in the
// order of items.
func (c *Client) BatchCheck(ctx context.Context, caller Caller, items []openapi.CheckItem) (*openapi.BatchCheckResult, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: no items to check", ErrBadRequest)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.api.BatchCheckWithResponse(ctx, &openapi.BatchCheckParams{XActor: actor(caller)}, openapi.BatchCheckRequest{Items: items}, bearer(caller))
	if err != nil {
		return nil, transportError(err)
	}

	out, err := result(resp.HTTPResponse, resp.Body, resp.JSON200)
	if err != nil {
		return nil, err
	}

	// Answers are matched to items by position, so a short or long reply
	// would grant or deny the wrong items.
	if len(out.Allowed) != len(items) {
		return nil, fmt.Errorf("%w: %d answers for %d items", ErrResponse, len(out.Allowed), len(items))
	}

	return out, nil
}

// Permissions lists what the caller may do in one organization.  Callers that
// need every service, whatever the region runs, use UntrimmedPermissions.
func (c *Client) Permissions(ctx context.Context, caller Caller, params openapi.ListPermissionsParams) (*openapi.PermissionList, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.api.ListPermissionsWithResponse(ctx, &params, bearer(caller))
	if err != nil {
		return nil, transportError(err)
	}

	return result(resp.HTTPResponse, resp.Body, resp.JSON200)
}

// Status reads the agent's state.
func (c *Client) Status(ctx context.Context, caller Caller) (*openapi.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.api.GetStatusWithResponse(ctx, bearer(caller))
	if err != nil {
		return nil, transportError(err)
	}

	return result(resp.HTTPResponse, resp.Body, resp.JSON200)
}

// UntrimmedPermissions lists every permission the caller holds in the
// organization, in every region, and refuses a list trimmed to a region.
// Role grants and comparisons with uni RBAC must use this form: a trimmed list
// would hide what the caller holds where other services run.
func UntrimmedPermissions(ctx context.Context, a Agent, caller Caller, organizationID string, projectIDs []string) (*openapi.PermissionList, error) {
	params := openapi.ListPermissionsParams{
		OrganizationId: organizationID,
		Untrimmed:      new(true),
	}

	if len(projectIDs) > 0 {
		params.ProjectId = &projectIDs
	}

	list, err := a.Permissions(ctx, caller, params)
	if err != nil {
		return nil, err
	}

	if list.Form != openapi.Untrimmed {
		return nil, fmt.Errorf("%w: form %q", ErrTrimmed, list.Form)
	}

	return list, nil
}

func transportError(err error) error {
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// result returns the decoded 200 body, or a typed error for any other status.
func result[T any](resp *http.Response, body []byte, ok *T) (*T, error) {
	if resp.StatusCode == http.StatusOK {
		if ok == nil {
			return nil, fmt.Errorf("%w: no JSON body", ErrResponse)
		}

		return ok, nil
	}

	e := &Error{StatusCode: resp.StatusCode, kind: kindOf(resp.StatusCode)}

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

	return nil, e
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
