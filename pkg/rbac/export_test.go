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

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// These export the remote shadow limits for remote_shadow_test.go (package
// rbac_test).
const (
	RemoteShadowRunLimitForTest   = remoteShadowRunLimit
	RemoteShadowQueueLimitForTest = remoteShadowQueueLimit
	RemoteShadowBackstopForTest   = remoteShadowBackstop
)

// RemoteShadowIdleForTest reports whether no compare holds an admission slot
// or a run slot.
func RemoteShadowIdleForTest() bool {
	if !remoteShadowAdmitted.TryAcquire(remoteShadowRunLimit + remoteShadowQueueLimit) {
		return false
	}

	remoteShadowAdmitted.Release(remoteShadowRunLimit + remoteShadowQueueLimit)

	if !remoteShadowRunning.TryAcquire(remoteShadowRunLimit) {
		return false
	}

	remoteShadowRunning.Release(remoteShadowRunLimit)

	return true
}

// RemoteShadowAdmitAndRunForTest takes an admission slot, as remoteShadowed
// does, and runs the compare with ctx on the caller's goroutine.
func RemoteShadowAdmitAndRunForTest(ctx context.Context, engine CoarseEngine) bool {
	if !remoteShadowAdmitted.TryAcquire(1) {
		return false
	}

	runRemoteShadowCompare(ctx, engine, Resource{Kind: "candy"}, openapi.Read, true)

	return true
}

// AccumulateGlobalReadPermissionsForTest exports accumulateGlobalReadPermissions for
// external tests in bindings_test.go (package rbac_test).
func AccumulateGlobalReadPermissionsForTest(acl *openapi.Acl, roleIDs []string, roles map[string]*unikornv1.Role) error {
	return accumulateGlobalReadPermissions(acl, roleIDs, roles)
}

// EffectiveGlobalRoleBindingsForTest exports effectiveGlobalRoleBindings for
// external tests in bindings_test.go (package rbac_test).
func EffectiveGlobalRoleBindingsForTest(o *Options) []GlobalRoleBinding {
	return effectiveGlobalRoleBindings(o)
}

// ResolveGlobalRoleBindingsForTest exports RBAC.resolveGlobalRoleBindings for
// external tests in bindings_test.go (package rbac_test).
func ResolveGlobalRoleBindingsForTest(bindings []GlobalRoleBinding, srcIss, subject string) []GlobalRoleBinding {
	r := &RBAC{bindings: bindings}

	return r.resolveGlobalRoleBindings(srcIss, subject)
}
