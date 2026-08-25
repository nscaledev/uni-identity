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

package authorizer

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/http"

	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// Resource identifies what a decision is about, mirroring rbac.Resource.
// Scope is encoded by ABSENCE, never by empty values: leave OrganizationID
// empty for a global check; set OrganizationID only for an org check (the
// project attribute must stay empty — the no-flow-up invariant); set both for
// a project check.  A local DTO keeps this seam free of a pkg/rbac import in
// downstream consumers of this package.
type Resource struct {
	// Kind is the endpoint name, e.g. "identity:groups".
	Kind string

	// ID optionally identifies a specific resource instance.
	ID string

	// OrganizationID optionally scopes the check to an organization.
	OrganizationID string

	// ProjectID optionally scopes the check to a project; requires
	// OrganizationID.
	ProjectID string
}

// CheckRequest pairs a resource with the operation to authorize on it.
type CheckRequest struct {
	Resource Resource
	Action   identityapi.AclOperation
}

// CheckMany obtains authorization decisions from identity for a batch of
// checks: the generated typed client over the cached mTLS/trace-context HTTP
// client, with the X-Principal/X-Impersonate principal headers injected via
// principal.Injector.
//
// It deliberately does NOT forward a bearer.  The check endpoint is
// system-account-only and REJECTS any Authorization header
// (handler.PostApiV1AuthorizationCheck; TestRemoteAuthorizationCheckRejectsBearer):
// the CALLER is authenticated by the cached client's mTLS peer certificate CN,
// and the ACTING user is conveyed by X-Principal/X-Impersonate — not by a
// token.  Forwarding the request's user bearer here would 401 every check.
// This is the one place the wire pattern diverges from GetACL, which is not
// system-gated and forwards the bearer to name the user.
//
// FAIL-CLOSED: any transport or server error is returned and the caller MUST
// treat it as a deny for every check; a per-entry false is a policy deny.  The
// sentinel distinction is preserved as far as the wire allows — a 5xx (or a
// transport/decode failure) maps to ErrDecisionUnavailable, while a 401/other
// 4xx is propagated verbatim via errors.PropagateError.
//
// It also applies its own hard per-call deadline (checkTimeout, see
// WithCheckTimeout), independent of the caller's context: a slow identity
// must not be allowed to block a caller indefinitely.  A deadline exceeded
// surfaces through the same transport-error path above as
// ErrDecisionUnavailable.
//
// The round trip is additionally guarded by a circuit breaker (breaker, see
// NewAuthorizer/WithCircuitBreaker): once open it fails instantly with
// ErrDecisionUnavailable and makes NO HTTP round trip, protecting a
// struggling identity from further load until a cooldown elapses. It trips
// on CheckMany's own error return only — i.e. failure to obtain a verdict —
// and NEVER on a returned deny: a successful check that denies some or all
// entries is (allowed, nil), a success as far as the breaker is concerned. A
// nil breaker (WithCircuitBreaker(nil)) disables this guard entirely.
func (a *Authorizer) CheckMany(ctx context.Context, checks []CheckRequest) ([]bool, error) {
	if a.checkTimeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, a.checkTimeout)
		defer cancel()
	}

	if a.breaker == nil {
		return a.checkManyRequest(ctx, checks)
	}

	allowed, err := failsafe.With[[]bool](a.breaker).WithContext(ctx).Get(func() ([]bool, error) {
		return a.checkManyRequest(ctx, checks)
	})
	if err != nil {
		if goerrors.Is(err, circuitbreaker.ErrOpen) {
			return nil, fmt.Errorf("%w: circuit breaker open: %w", ErrDecisionUnavailable, err)
		}

		return nil, err
	}

	return allowed, nil
}

// checkManyRequest performs exactly one attempt at the round trip — build
// the client, issue the check call, map the response — with no retry of its
// own (bounded retry is a deliberate follow-up, see the package README).
// Split out of CheckMany so the circuit breaker guards precisely this call,
// never the timeout setup or the breaker plumbing around it.
func (a *Authorizer) checkManyRequest(ctx context.Context, checks []CheckRequest) ([]bool, error) {
	// Trace context and TLS (the system-account identity) ride the cached
	// client; the acting principal rides X-Principal via the injector.
	options := []identityapi.ClientOption{
		identityapi.WithHTTPClient(a.httpClient),
		identityapi.WithRequestEditorFn(principal.Injector(a.client, a.clientOptions)),
	}

	rawClient, err := identityapi.NewClientWithResponses(a.options.Host(), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create identity client", err)
	}

	response, err := rawClient.PostApiV1AuthorizationCheckWithResponse(ctx, checksToWire(checks))
	if err != nil {
		// Transport failure: fail closed, distinguishable as unavailable.
		return nil, fmt.Errorf("%w: failed to perform authorization check call: %w", ErrDecisionUnavailable, err)
	}

	return mapCheckResponse(response, len(checks))
}

// checksToWire maps the local DTO batch onto the generated request body,
// preserving absence semantics: a scope field is populated only when
// non-empty, so an org-level check never gains a project attribute (see the
// pointer/omitempty wire schema).
func checksToWire(checks []CheckRequest) identityapi.AuthorizationCheckRequest {
	body := identityapi.AuthorizationCheckRequest{Checks: make([]identityapi.AuthorizationCheck, len(checks))}

	for i, check := range checks {
		resource := identityapi.AuthorizationCheckResource{Kind: check.Resource.Kind}

		if check.Resource.ID != "" {
			resource.Id = &check.Resource.ID
		}

		if check.Resource.OrganizationID != "" {
			resource.OrganizationId = &check.Resource.OrganizationID
		}

		if check.Resource.ProjectID != "" {
			resource.ProjectId = &check.Resource.ProjectID
		}

		body.Checks[i] = identityapi.AuthorizationCheck{Resource: resource, Action: check.Action}
	}

	return body
}

// mapCheckResponse applies the fail-closed status mapping and maps the
// per-check results onto a positional bool slice: 5xx (and any unpopulated
// error body PropagateError cannot render) are unavailability, 401/other 4xx
// propagate verbatim, and a result-count mismatch is unavailability — never a
// guessed verdict.  The caller treats any returned error as a deny.
func mapCheckResponse(response *identityapi.PostApiV1AuthorizationCheckResponse, want int) ([]bool, error) {
	if response.StatusCode() != http.StatusOK {
		if response.StatusCode() >= http.StatusInternalServerError {
			return nil, fmt.Errorf("%w: identity returned status %d", ErrDecisionUnavailable, response.StatusCode())
		}

		return nil, errors.PropagateError(response.HTTPResponse, response)
	}

	if response.JSON200 == nil {
		return nil, fmt.Errorf("%w: identity returned a 200 with no decision body", ErrDecisionUnavailable)
	}

	results := response.JSON200.Results
	if len(results) != want {
		return nil, fmt.Errorf("%w: expected %d results, got %d", ErrDecisionUnavailable, want, len(results))
	}

	allowed := make([]bool, len(results))
	for i := range results {
		allowed[i] = results[i].Allowed
	}

	return allowed, nil
}
