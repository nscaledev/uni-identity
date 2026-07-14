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

// remoteShadowed is a Task 7 stub: it serves legacyErr UNCONDITIONALLY,
// exactly like shadow.go's local shadowed does today, but does not yet run any
// remote-vs-legacy comparison. Task 7 fills in the real comparator — running
// engine.AllowCoarse alongside the already-computed legacyErr and logging
// disagreement — while preserving this same zero-behaviour-change contract:
// the legacy verdict is always what's served.
func remoteShadowed(ctx context.Context, engine CoarseEngine, resource Resource, operation openapi.AclOperation, legacyErr error) error {
	return legacyErr
}
