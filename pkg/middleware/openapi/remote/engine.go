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
	"fmt"

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// RemoteEngine adapts this package's remote decision call (CheckMany, over
// identity's POST /authorization/check) onto rbac.CoarseEngine: the "remote
// transport ABOVE rbac.decide()" that pkg/middleware/openapi/README.md flags
// as a designed follow-up to A8 (see "The Decision-Engine Crossing"). A
// downstream service without a local PDP client gets the same coarse
// Allow*/list-filtering decisions identity's own *RBAC serves in-process.
//
// Error sentinels are translated at this boundary, not just forwarded:
// CheckMany fails closed with THIS package's ErrDecisionUnavailable (or a
// propagated 4xx), never pkg/rbac's, because decision.go does not import
// pkg/rbac. AllowCoarseMany re-wraps any CheckMany error with
// rbac.ErrDecisionUnavailable (preserving the original via %w) so a caller
// checking errors.Is against rbac's sentinels gets the identical answer
// regardless of whether the local or remote CoarseEngine served the
// decision — the whole point of the seam.
type RemoteEngine struct {
	authorizer *Authorizer
}

var _ rbac.CoarseEngine = (*RemoteEngine)(nil)

// NewRemoteEngine wraps an Authorizer as a rbac.CoarseEngine.
func NewRemoteEngine(a *Authorizer) *RemoteEngine {
	return &RemoteEngine{authorizer: a}
}

// RemoteDecisionEngine exposes this Authorizer as a rbac.CoarseEngine.
func (a *Authorizer) RemoteDecisionEngine() rbac.CoarseEngine {
	return NewRemoteEngine(a)
}

// AllowCoarseMany is the batch primitive: one CheckMany round trip for N
// resources, returning per-resource verdicts in order.  A CheckMany failure
// is folded into rbac.ErrDecisionUnavailable (see the type doc) rather than
// forwarded as-is.
func (e *RemoteEngine) AllowCoarseMany(ctx context.Context, resources []rbac.Resource, action identityapi.AclOperation) ([]bool, error) {
	checks := make([]CheckRequest, len(resources))
	for i, resource := range resources {
		checks[i] = CheckRequest{Resource: Resource(resource), Action: action}
	}

	allowed, err := e.authorizer.CheckMany(ctx, checks)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", rbac.ErrDecisionUnavailable, err)
	}

	return allowed, nil
}

// AllowCoarse is the single-resource convenience the Allow* facade uses; nil
// == allow, else rbac.CoarseForbidden's HTTPForbidden shape wrapping
// ErrPolicyDenied or ErrDecisionUnavailable — identical to the local
// CoarseEngine's error shape.
func (e *RemoteEngine) AllowCoarse(ctx context.Context, resource rbac.Resource, action identityapi.AclOperation) error {
	allowed, err := e.AllowCoarseMany(ctx, []rbac.Resource{resource}, action)
	if err != nil {
		return rbac.CoarseForbidden(resource, action, err)
	}

	if !allowed[0] {
		return rbac.CoarseForbidden(resource, action, fmt.Errorf("%w: operation '%s' on '%s'", rbac.ErrPolicyDenied, action, resource.Kind))
	}

	return nil
}
