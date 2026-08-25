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

package rbac

import (
	"context"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// CoarseEngine is the coarse-decision seam Allow* dispatch and list filtering
// consume: the local *RBAC satisfies it directly (this file), and a remote
// adapter (calling identity's decision endpoint) satisfies it too, so callers
// do not need to know which is behind the interface.
type CoarseEngine interface {
	// AllowCoarseMany is the batch primitive: one PDP round-trip for N
	// resources (list filtering).  Returns per-resource verdicts in order;
	// a non-nil error is fail-closed (treat every entry as denied).
	AllowCoarseMany(ctx context.Context, resources []Resource, action openapi.AclOperation) ([]bool, error)
	// AllowCoarse is the single-resource convenience the Allow* facade uses;
	// nil == allow, else an HTTPForbidden wrapping ErrPolicyDenied /
	// ErrDecisionUnavailable.
	AllowCoarse(ctx context.Context, resource Resource, action openapi.AclOperation) error
}

// AllowCoarse serves one coarse decision through the coarse-decision cache.
func (r *RBAC) AllowCoarse(ctx context.Context, resource Resource, action openapi.AclOperation) error {
	return r.allowCoarse(ctx, resource, action)
}

// AllowCoarseMany serves a batch of coarse decisions in one PDP round-trip
// (uncached — mirrors CheckMany; used for list filtering).
func (r *RBAC) AllowCoarseMany(ctx context.Context, resources []Resource, action openapi.AclOperation) ([]bool, error) {
	checks := make([]CheckRequest, len(resources))
	for i, resource := range resources {
		checks[i] = CheckRequest{Resource: resource, Action: action}
	}

	return r.CheckMany(ctx, checks)
}
