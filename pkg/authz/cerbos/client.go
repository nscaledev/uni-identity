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

// Package cerbos provides a thin gRPC client for the Cerbos PDP that runs as
// a sidecar of the identity server (see charts/identity).  It owns connection
// construction, per-call deadlines and the fail-closed error contract, and
// nothing else: request construction (principals, resources, binding strings)
// is the request builder's job (request.go), and decision mapping, batching,
// and the decision audit logging and metrics all live in pkg/rbac
// (Check/CheckMany and decision_log.go) — the client itself stays log-free.
package cerbos

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
)

// ErrUnavailable wraps every failure to obtain a decision from the PDP:
// transport errors, per-call deadline expiry and server-side failures alike.
// The client NEVER fabricates an allow or deny; pkg/rbac's decision layer
// maps this sentinel to deny — fail closed — and its decision observability
// records every such deny (reason "unavailable" in the decision log and
// counter, with deadline expiries visible in the PDP latency histogram).
var ErrUnavailable = errors.New("cerbos PDP unavailable")

// ErrOptions is returned by New for invalid static configuration.  It is
// deliberately distinct from ErrUnavailable, which is runtime taxonomy for
// the fail-closed deny mapping; a configuration error must fail construction
// loudly instead.
var ErrOptions = errors.New("invalid cerbos client options")

// Client wraps the Cerbos SDK gRPC client with the sidecar's connection
// settings and a per-call timeout.
type Client struct {
	client  *sdk.GRPCClient
	timeout time.Duration
}

// New creates a PDP client.  The underlying gRPC channel is lazy: success
// here proves nothing about sidecar liveness (pod readiness gates on the
// sidecar's own health probe), it only validates the configuration.
func New(options *Options) (*Client, error) {
	if err := validateEndpoint(options.Endpoint); err != nil {
		return nil, err
	}

	// A non-positive timeout would give every call an already-expired
	// context, so every check would be insta-denied while the sidecar
	// looks perfectly healthy; refuse it at construction instead.
	if options.CheckTimeout <= 0 {
		return nil, fmt.Errorf("%w: check timeout %v is not positive", ErrOptions, options.CheckTimeout)
	}

	// WithPlaintext is mandatory: the SDK defaults to TLS and the sidecar
	// serves plaintext on localhost.
	client, err := sdk.New(options.Endpoint, sdk.WithPlaintext())
	if err != nil {
		return nil, fmt.Errorf("cerbos client construction failed: %w", err)
	}

	return &Client{client: client, timeout: options.CheckTimeout}, nil
}

// validateEndpoint refuses endpoints whose host is not loopback: the PDP is
// an unauthenticated, plaintext, same-pod sidecar by design, and dialing it
// across the network would bypass every transport protection.  A remote PDP
// (a separate, network-reachable deployment) would need mTLS and revisits this.
func validateEndpoint(endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("%w: endpoint %q: %w", ErrOptions, endpoint, err)
	}

	if host == "localhost" {
		return nil
	}

	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}

	return fmt.Errorf("%w: endpoint %q host is not loopback", ErrOptions, endpoint)
}

// CheckResources asks the PDP for a decision on a batch of resources.  It
// applies the configured per-call deadline and passes the SDK types through
// verbatim.  On ANY failure it returns (nil, error wrapping ErrUnavailable),
// never a fabricated decision.  On the response side the SDK's IsAllowed
// returns false for missing actions, missing resources and errored results,
// so an allow is only ever reachable through an explicit EFFECT_ALLOW.
func (c *Client) CheckResources(ctx context.Context, principal *sdk.Principal, resources *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	response, err := c.client.CheckResources(ctx, principal, resources)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	return response, nil
}

// Healthy performs a ServerInfo round-trip against the PDP — the cheapest
// connectivity probe the API offers (the SDK has no health helper) — bounded
// by the per-call timeout.  Failures wrap ErrUnavailable.
func (c *Client) Healthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if _, err := c.client.ServerInfo(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	return nil
}
