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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/permissionsagent/openapi"
)

const (
	// DefaultTimeout bounds one agent call when Options.Timeout is zero.
	DefaultTimeout = 250 * time.Millisecond

	// MaxBatchChecks is the most items one BatchCheck may send.
	MaxBatchChecks = 100

	// MaxSubjectLength is the longest subject or actor, in bytes.
	MaxSubjectLength = 512

	// MaxResponseBytes is the largest reply body the client reads.
	MaxResponseBytes = 8 << 20

	// maxDescription caps the agent's error_description in Error().
	maxDescription = 256

	// maxIdleConnsPerHost keeps connections to the one agent host warm.
	maxIdleConnsPerHost = 32

	serviceAccountPrefix = "serviceaccount:"
	redacted             = "[redacted]"
)

var (
	// ErrInvalidOptions means New was given options it cannot use.
	ErrInvalidOptions = errors.New("permissions agent: invalid options")
	// ErrInvalidInput means the call was refused locally, without calling the
	// agent, for input the agent would answer with 400.
	ErrInvalidInput = errors.New("permissions agent: invalid input")
	// ErrBadRequest is a 400 from the agent, for example an unknown regionId.
	ErrBadRequest = errors.New("permissions agent: bad request")
	// ErrUnauthorized is a 401: no caller credentials, or bad ones.  It is
	// also returned, without calling the agent, when the token source gives an
	// empty token.
	ErrUnauthorized = errors.New("permissions agent: unauthorized")
	// ErrForbidden is a 403: the caller is authenticated but the agent does not
	// trust it.  A denied check is not an error.
	ErrForbidden = errors.New("permissions agent: forbidden")
	// ErrUnavailable means there is no answer: the agent could not be reached,
	// the call hit Options.Timeout, the token source failed, or the agent has
	// no fresh copy (502, 503, 504).  Treat it as a denial.
	ErrUnavailable = errors.New("permissions agent: unavailable")
	// ErrServer is any other error status.
	ErrServer = errors.New("permissions agent: server error")
	// ErrResponse means the agent's reply does not match the contract or the
	// request.
	ErrResponse = errors.New("permissions agent: malformed response")
	// ErrTrimmed means a trimmed list came back where an untrimmed one was asked
	// for.
	ErrTrimmed = errors.New("permissions agent: list is trimmed to a region")

	errUnknown = errors.New("permissions agent: error")
)

// Error is an error status from the agent.  It matches one of the sentinel
// errors above with errors.Is.  Description has the request's subject, actor
// and token replaced, in case the agent echoes them.
type Error struct {
	StatusCode  int
	Code        string
	Description string
	TraceID     string

	kind error
}

func (e *Error) Error() string {
	kind := e.kind
	if kind == nil {
		kind = errUnknown
	}

	description := clean(e.Description)
	if description == "" {
		return fmt.Sprintf("%v: status %d", kind, e.StatusCode)
	}

	return fmt.Sprintf("%v: status %d: %s", kind, e.StatusCode, description)
}

func (e *Error) Unwrap() error {
	return e.kind
}

// clean drops control characters and caps the text at maxDescription
// characters, so an agent or proxy cannot forge log lines.
func clean(s string) string {
	var b strings.Builder

	n := 0

	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}

		if n == maxDescription {
			break
		}

		b.WriteRune(r)

		n++
	}

	return b.String()
}

// Agent is the permissions agent API.  Client implements it; tests can fake it.
type Agent interface {
	Check(ctx context.Context, request openapi.CheckRequest) (*openapi.CheckResult, error)
	BatchCheck(ctx context.Context, request openapi.BatchCheckRequest) (*openapi.BatchCheckResult, error)
	Permissions(ctx context.Context, request openapi.PermissionsRequest) (*openapi.PermissionList, error)
	Status(ctx context.Context) (*openapi.Status, error)
}

// TokenSource returns the calling service's current bearer token.  It is
// called on every request, so it can refresh the token.
type TokenSource func(ctx context.Context) (string, error)

// StaticToken is a TokenSource for a fixed token.
func StaticToken(token string) TokenSource {
	return func(context.Context) (string, error) {
		return token, nil
	}
}

// Options configure a Client.
type Options struct {
	// URL is the agent's base URL, http or https.
	URL string
	// TokenSource gives the calling service's own bearer token, sent on every
	// call.  Nil sends no Authorization header, for callers that use mTLS
	// only.
	TokenSource TokenSource
	// AllowInsecureHTTP lets a TokenSource be used with an http URL.  Without
	// it New refuses, so the token is never sent in clear text by mistake.
	AllowInsecureHTTP bool
	// Timeout bounds each call.  Zero means DefaultTimeout.
	Timeout time.Duration
	// HTTPClient sends the requests, for example one set up for mTLS.  Nil
	// means a client of the package's own that does not follow redirects.
	HTTPClient *http.Client
}

// Client calls a permissions agent over HTTP.
type Client struct {
	api     openapi.ClientInterface
	timeout time.Duration
}

var _ Agent = (*Client)(nil)

// localError is an error made before the request was sent, returned as is.
type localError struct {
	err error
}

func (e *localError) Error() string { return e.err.Error() }
func (e *localError) Unwrap() error { return e.err }

// New returns a client for the agent at opts.URL.
func New(opts Options) (*Client, error) {
	if err := validURL(opts); err != nil {
		return nil, err
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}

	clientOpts := []openapi.ClientOption{openapi.WithHTTPClient(httpClient)}

	if opts.TokenSource != nil {
		clientOpts = append(clientOpts, openapi.WithRequestEditorFn(bearer(opts.TokenSource)))
	}

	api, err := openapi.NewClient(opts.URL, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &Client{api: api, timeout: timeout}, nil
}

// validURL checks the agent URL.  The URL is left out of errors: it may hold
// credentials.
func validURL(opts Options) error {
	if opts.URL == "" {
		return fmt.Errorf("%w: agent URL is required", ErrInvalidOptions)
	}

	agentURL, err := url.Parse(opts.URL)
	if err != nil {
		return fmt.Errorf("%w: agent URL does not parse", ErrInvalidOptions)
	}

	switch {
	case agentURL.Scheme != "http" && agentURL.Scheme != "https":
		return fmt.Errorf("%w: agent URL scheme must be http or https", ErrInvalidOptions)
	case agentURL.Host == "":
		return fmt.Errorf("%w: agent URL has no host", ErrInvalidOptions)
	case agentURL.Scheme == "http" && opts.TokenSource != nil && !opts.AllowInsecureHTTP:
		return fmt.Errorf("%w: a service token over http needs AllowInsecureHTTP", ErrInvalidOptions)
	}

	return nil
}

// defaultHTTPClient has its own transport, so other code changing
// http.DefaultTransport does not change it, and does not follow redirects, so
// the token is not sent on to another host.
func defaultHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}

	transport = transport.Clone()
	transport.MaxIdleConnsPerHost = maxIdleConnsPerHost

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// bearer sets the Authorization header from the token source.  Its errors
// carry no text from the source, which may hold secrets.
func bearer(source TokenSource) openapi.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		token, err := source(ctx)
		if err != nil {
			return &localError{err: fmt.Errorf("%w: service token source failed", ErrUnavailable)}
		}

		if token == "" {
			return &localError{err: fmt.Errorf("%w: service token source gave an empty token", ErrUnauthorized)}
		}

		req.Header.Set("Authorization", "Bearer "+token)

		return nil
	}
}

// Check asks whether the subject may perform one item.
func (c *Client) Check(ctx context.Context, request openapi.CheckRequest) (*openapi.CheckResult, error) {
	if err := validSubject(request.Subject, request.Actor); err != nil {
		return nil, err
	}

	if err := validItem(request.Check); err != nil {
		return nil, err
	}

	return call(ctx, c, redactor(request.Subject, request.Actor), func(ctx context.Context) (*http.Response, error) {
		return c.api.Check(ctx, request)
	}, func(body []byte, _ *openapi.CheckResult) error {
		var raw struct {
			Allowed *bool `json:"allowed"`
		}

		if err := json.Unmarshal(body, &raw); err != nil || raw.Allowed == nil {
			return fmt.Errorf("%w: no allowed field", ErrResponse)
		}

		return nil
	})
}

// BatchCheck asks about up to MaxBatchChecks items in one call.  The results
// are in the order of request.Checks.
func (c *Client) BatchCheck(ctx context.Context, request openapi.BatchCheckRequest) (*openapi.BatchCheckResult, error) {
	if err := validBatch(request); err != nil {
		return nil, err
	}

	return call(ctx, c, redactor(request.Subject, request.Actor), func(ctx context.Context) (*http.Response, error) {
		return c.api.BatchCheck(ctx, request)
	}, func(body []byte, out *openapi.BatchCheckResult) error {
		return verifyBatch(body, out, len(request.Checks))
	})
}

func validBatch(request openapi.BatchCheckRequest) error {
	if err := validSubject(request.Subject, request.Actor); err != nil {
		return err
	}

	switch {
	case len(request.Checks) == 0:
		return fmt.Errorf("%w: no items to check", ErrInvalidInput)
	case len(request.Checks) > MaxBatchChecks:
		return fmt.Errorf("%w: %d items, at most %d allowed", ErrInvalidInput, len(request.Checks), MaxBatchChecks)
	}

	for i := range request.Checks {
		if err := validItem(request.Checks[i]); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}

	return nil
}

func verifyBatch(body []byte, out *openapi.BatchCheckResult, items int) error {
	// Results are matched to items by position, so a short or long reply
	// would grant or deny the wrong items.
	if len(out.Results) != items {
		return fmt.Errorf("%w: %d results for %d items", ErrResponse, len(out.Results), items)
	}

	var raw struct {
		Results []*struct {
			Allowed *bool `json:"allowed"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("%w: body is not valid JSON", ErrResponse)
	}

	for i, result := range raw.Results {
		if result == nil || result.Allowed == nil {
			return fmt.Errorf("%w: result %d has no allowed field", ErrResponse, i)
		}
	}

	return nil
}

// Permissions lists what the subject may do in one organization.  When the
// request asks for untrimmed, any other form is refused with ErrTrimmed: a
// trimmed list would hide what the subject holds where other services run.
func (c *Client) Permissions(ctx context.Context, request openapi.PermissionsRequest) (*openapi.PermissionList, error) {
	if err := validSubject(request.Subject, request.Actor); err != nil {
		return nil, err
	}

	if request.OrganizationId == "" {
		return nil, fmt.Errorf("%w: organizationId is required", ErrInvalidInput)
	}

	return call(ctx, c, redactor(request.Subject, request.Actor), func(ctx context.Context) (*http.Response, error) {
		return c.api.ListPermissions(ctx, request)
	}, func(_ []byte, list *openapi.PermissionList) error {
		if list.OrganizationId != request.OrganizationId {
			return fmt.Errorf("%w: list is for another organization", ErrResponse)
		}

		for i, entry := range list.Permissions {
			if err := validEntry(entry); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
		}

		if request.Untrimmed != nil && *request.Untrimmed && list.Form != openapi.Untrimmed {
			return fmt.Errorf("%w: form %q", ErrTrimmed, clean(string(list.Form)))
		}

		return nil
	})
}

// Status reads the agent's state.
func (c *Client) Status(ctx context.Context) (*openapi.Status, error) {
	return call[openapi.Status](ctx, c, nil, func(ctx context.Context) (*http.Response, error) {
		return c.api.GetStatus(ctx)
	}, nil)
}

// validSubject refuses a subject or actor the agent would answer with 400.
// Errors never name the value: it names a person.
func validSubject(subject string, actor *string) error {
	if err := validPrincipal(subject); err != nil {
		return fmt.Errorf("%w: subject %w", ErrInvalidInput, err)
	}

	if actor != nil {
		if err := validPrincipal(*actor); err != nil {
			return fmt.Errorf("%w: actor %w", ErrInvalidInput, err)
		}
	}

	return nil
}

var (
	errEmpty          = errors.New("is empty")
	errTooLong        = fmt.Errorf("is over %d bytes", MaxSubjectLength)
	errNotUTF8        = errors.New("is not UTF-8")
	errControl        = errors.New("has a control character")
	errServiceAccount = errors.New("names a service account with no ID")
)

func validPrincipal(value string) error {
	switch {
	case strings.TrimSpace(value) == "":
		return errEmpty
	case len(value) > MaxSubjectLength:
		return errTooLong
	case !utf8.ValidString(value):
		return errNotUTF8
	case strings.ContainsFunc(value, unicode.IsControl):
		return errControl
	case strings.HasPrefix(value, serviceAccountPrefix) && strings.TrimSpace(value[len(serviceAccountPrefix):]) == "":
		return errServiceAccount
	}

	return nil
}

// validItem refuses an item the agent would answer with 400.
func validItem(item openapi.CheckItem) error {
	switch {
	case item.Kind == "":
		return fmt.Errorf("%w: kind is required", ErrInvalidInput)
	case item.Action == "":
		return fmt.Errorf("%w: action is required", ErrInvalidInput)
	case item.ProjectId != nil && (item.OrganizationId == nil || *item.OrganizationId == ""):
		return fmt.Errorf("%w: projectId requires organizationId", ErrInvalidInput)
	}

	return nil
}

// validEntry checks that a list entry's projectId matches its scope.
func validEntry(entry openapi.Permission) error {
	switch entry.Scope {
	case openapi.ScopeProject:
		if entry.ProjectId == nil || *entry.ProjectId == "" {
			return fmt.Errorf("%w: project entry has no projectId", ErrResponse)
		}
	case openapi.ScopeGlobal, openapi.ScopeOrganization:
		if entry.ProjectId != nil {
			return fmt.Errorf("%w: %s entry has a projectId", ErrResponse, entry.Scope)
		}
	default:
		return fmt.Errorf("%w: unknown scope", ErrResponse)
	}

	return nil
}

// redactor returns the values to keep out of agent error descriptions.
func redactor(subject string, actor *string) []string {
	out := []string{subject}
	if actor != nil {
		out = append(out, *actor)
	}

	return out
}

// call sends one request under the client timeout, decodes a 200 body and
// runs verify on it, or returns a typed error.
func call[T any](ctx context.Context, c *Client, secrets []string, send func(context.Context) (*http.Response, error), verify func([]byte, *T) error) (*T, error) {
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, transportError(ctx, err)
	}

	if len(body) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: body is over %d bytes", ErrResponse, MaxResponseBytes)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, body, secrets, resp.Request)
	}

	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return nil, fmt.Errorf("%w: body is null", ErrResponse)
	}

	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%w: body does not match the contract", ErrResponse)
	}

	if verify != nil {
		if err := verify(body, &out); err != nil {
			return nil, err
		}
	}

	return &out, nil
}

// transportError keeps the caller's own cancel or deadline apart from the
// agent being unavailable: the first is the caller's choice, not an outage.
func transportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("permissions agent: %w", ctxErr)
	}

	var local *localError
	if errors.As(err, &local) {
		return local.err
	}

	return fmt.Errorf("%w: %w", ErrUnavailable, sanitize(err))
}

// sanitize drops the query, fragment and user info from a *url.Error's URL.
func sanitize(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}

	clean := &url.Error{Op: urlErr.Op, Err: urlErr.Err}

	if u, perr := url.Parse(urlErr.URL); perr == nil {
		u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
		clean.URL = u.String()
	}

	return clean
}

func statusError(status int, body []byte, secrets []string, req *http.Request) error {
	e := &Error{StatusCode: status, kind: kindOf(status)}

	// The body is best effort: a proxy in front of the agent may not send the
	// platform error shape.
	var payload coreopenapi.Error
	if json.Unmarshal(body, &payload) == nil {
		e.Code = string(payload.Error)
		e.Description = redact(payload.ErrorDescription, secrets, req)

		if payload.TraceId != nil {
			e.TraceID = *payload.TraceId
		}
	}

	return e
}

// redact replaces the subject, actor and bearer token in text from the agent.
func redact(text string, secrets []string, req *http.Request) string {
	if req != nil {
		if token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer "); ok {
			secrets = append(secrets, token)
		}
	}

	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, redacted)
		}
	}

	return text
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
