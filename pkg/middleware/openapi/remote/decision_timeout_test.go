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

package authorizer_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// TestRemoteCheckManyTimeout pins the first resilience guardrail on the
// remote decision call: a hard per-call deadline.  identity being slow to
// respond must not be allowed to block CheckMany indefinitely — the caller
// gets ErrDecisionUnavailable (and so fails closed) well within the deadline
// instead of waiting out the slow backend.
func TestRemoteCheckManyTimeout(t *testing.T) {
	t.Parallel()

	h := &checkHandler{
		delay:   500 * time.Millisecond,
		results: []identityapi.AuthorizationCheckResult{{Allowed: true}},
	}
	auth := newCheckAuthorizer(t, h, authorizer.WithCheckTimeout(50*time.Millisecond))

	ctx := checkAuthContext(t, "", false)

	start := time.Now()

	allowed, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
		{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
	})

	elapsed := time.Since(start)
	t.Logf("CheckMany returned in %s (backend delay 500ms, checkTimeout 50ms)", elapsed)

	require.Less(t, elapsed, 250*time.Millisecond, "CheckMany must return well before the slow backend responds")
	require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	require.Nil(t, allowed)
}
