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
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the remote CoarseEngine adapter: RemoteEngine wraps
// this package's CheckMany decision call so a caller of rbac.CoarseEngine
// cannot tell whether the local *RBAC or this remote adapter served the
// verdict — same allow/deny/unavailable sentinel shape either way.  They
// reuse the checkHandler/newCheckAuthorizer/checkAuthContext fixtures from
// decision_test.go, which already stand up a real *Authorizer against a
// stubbed identity decision endpoint.

// TestRemoteEngineAllowCoarse pins the single-resource convenience: an allow
// verdict is a nil error, a policy deny is errors.Is(err, rbac.ErrPolicyDenied),
// and a decision-endpoint failure is errors.Is(err, rbac.ErrDecisionUnavailable)
// — rbac's OWN sentinels, even though the failure travels here as this
// package's ErrDecisionUnavailable (decision.go's CheckMany never touches
// pkg/rbac).
func TestRemoteEngineAllowCoarse(t *testing.T) {
	t.Parallel()

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	t.Run("allow", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		err := engine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read)
		require.NoError(t, err)
	})

	t.Run("policy deny", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: false}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		err := engine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read)
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)
	})

	t.Run("decision unavailable", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{status: http.StatusInternalServerError}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		err := engine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read)
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
	})
}

func TestRemoteEngineAllowCoarseManyCallerForms(t *testing.T) {
	t.Parallel()

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	t.Run("bearer caller sends its passport", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		_, err := engine.AllowCoarseMany(checkSystemAccountAuthContext(t, false), []rbac.Resource{resource}, identityapi.Read)
		require.NoError(t, err)

		require.NotNil(t, h.gotBody.Passport, "a bearer caller must send its passport in the body")
		require.Equal(t, checkPassport, *h.gotBody.Passport)
		require.Empty(t, h.gotImpersonate, "a bearer caller must not be impersonated: identity refuses a passport with X-Impersonate")
		require.NotEmpty(t, h.gotPrincipal, "X-Principal is mandatory on every check")
	})

	t.Run("bearer caller with an impersonation marker in context", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		ctx := principal.NewImpersonateContext(checkSystemAccountAuthContext(t, false))

		_, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
		require.NoError(t, err)

		require.NotNil(t, h.gotBody.Passport)
		require.Empty(t, h.gotImpersonate, "the engine must clear the marker, or identity answers 400")
	})

	t.Run("system-account caller sends no passport and relays its certificate", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		p := &principal.Principal{Actor: "actor@example.com", Type: identityapi.User, OrganizationIDs: []string{"org-1"}}
		ctx := authorization.NewContext(principal.NewContext(t.Context(), p), &authorization.Info{SystemAccount: true, ClientCert: "relayed-certificate"})

		_, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
		require.NoError(t, err)

		require.Nil(t, h.gotBody.Passport, "a system-account caller must send no passport")
		require.Empty(t, h.gotImpersonate, "a system-account caller must stay attribution-only, never forced into impersonation")
		require.Equal(t, "relayed-certificate", h.gotClientCert, "a system-account caller is conveyed by the relayed certificate")
	})

	t.Run("system-account caller with inbound impersonate flows through", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		ctx := principal.NewImpersonateContext(checkSystemAccountAuthContext(t, true))

		_, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
		require.NoError(t, err)

		require.Nil(t, h.gotBody.Passport)
		require.Equal(t, "true", h.gotImpersonate, "an inbound X-Impersonate must flow through unchanged, never stripped for a system-account caller")
	})
}

func TestRemoteEngineBearerWithoutPassportFailsClosed(t *testing.T) {
	t.Parallel()

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	tests := map[string]func(*authorization.Info){
		"empty passport": func(info *authorization.Info) { info.Passport = "" },
		"no subject":     func(info *authorization.Info) { info.Userinfo.Sub = "" },
		"no userinfo":    func(info *authorization.Info) { info.Userinfo = nil },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
			engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

			info := &authorization.Info{Passport: checkPassport, Userinfo: &identityapi.Userinfo{Sub: checkActorSubject}}
			mutate(info)

			p := &principal.Principal{Actor: checkActorSubject, Type: identityapi.User}
			ctx := authorization.NewContext(principal.NewContext(t.Context(), p), info)

			allowed, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
			require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
			require.Nil(t, allowed)
			require.Zero(t, h.requests, "no check call may go out without a passport, and never an impersonated one")
		})
	}
}

func TestRemoteEngineWithoutAuthenticatedCallerFailsClosed(t *testing.T) {
	t.Parallel()

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	tests := map[string]func(context.Context) context.Context{
		"no authorization info":  func(ctx context.Context) context.Context { return ctx },
		"nil authorization info": func(ctx context.Context) context.Context { return authorization.NewContext(ctx, nil) },
	}

	for name, withInfo := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
			engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

			p := &principal.Principal{Actor: checkActorSubject, Type: identityapi.User}
			ctx := withInfo(principal.NewContext(t.Context(), p))

			allowed, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
			require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
			require.Nil(t, allowed)
			require.Zero(t, h.requests, "a check with no authenticated caller must not go out with this service's own rights")
		})
	}
}

// TestRemoteEngineAllowCoarseManyBatchOrder pins the batch primitive: verdicts
// come back positionally matched to the request order (mirroring CheckMany's
// own result-order contract, already pinned by
// TestRemoteCheckManyResultsInOrder in decision_test.go).
func TestRemoteEngineAllowCoarseManyBatchOrder(t *testing.T) {
	t.Parallel()

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}, {Allowed: false}}}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	allowed, err := engine.AllowCoarseMany(checkAuthContext(t, "", false), []rbac.Resource{
		{Kind: "identity:groups", OrganizationID: "org-1"},
		{Kind: "identity:roles", OrganizationID: "org-1"},
	}, identityapi.Read)

	require.NoError(t, err)
	require.Equal(t, []bool{true, false}, allowed)
}

// TestRemoteEngineAllowCoarseManyChunksAtWireCap pins the batch chunking: a
// batch larger than the wire cap (maxChecksPerRequest — 50, mirroring
// server.spec.yaml's authorizationCheckList maxItems and the PDP's own
// maxResourcesPerRequest) is split across several CheckMany round trips instead
// of being sent as one over-cap request identity would reject wholesale. Every
// verdict comes back, in order, across the chunk boundaries.
func TestRemoteEngineAllowCoarseManyChunksAtWireCap(t *testing.T) {
	t.Parallel()

	// One check per request is denied by organization id, placed in the SECOND
	// chunk, so a correct split-and-concatenate is provable per index.
	h := &checkHandler{echoPerCheck: true, denyOrganizationID: "deny-me"}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	const (
		resources   = 120 // 50 + 50 + 20 at a wire cap of 50
		deniedIndex = 75  // in the second chunk (indices 50..99)
	)

	batch := make([]rbac.Resource, resources)
	for i := range batch {
		batch[i] = rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}
	}

	batch[deniedIndex].OrganizationID = "deny-me"

	allowed, err := engine.AllowCoarseMany(checkAuthContext(t, "", false), batch, identityapi.Read)
	require.NoError(t, err)
	require.Len(t, allowed, resources, "every resource in an over-cap batch must get a verdict")
	require.Equal(t, []int{50, 50, 20}, h.batchSizes, "the batch must be split into wire-cap-sized chunks, not sent as one over-cap request")
	require.Equal(t, 3, h.passportRequests, "every chunk must carry the passport")
	require.Equal(t, checkPassport, *h.gotBody.Passport)

	for i, a := range allowed {
		require.Equal(t, i != deniedIndex, a, "verdict for index %d must survive the chunk split in order", i)
	}
}

func TestRemoteEngineBearerEchoMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	tests := map[string]*checkHandler{
		"different echo": {results: []identityapi.AuthorizationCheckResult{{Allowed: true}}, passportSubject: "someone-else@example.com"},
		"no echo":        {results: []identityapi.AuthorizationCheckResult{{Allowed: true}}, omitPassportSubject: true},
	}

	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

			allowed, err := engine.AllowCoarseMany(checkAuthContext(t, "", false), []rbac.Resource{resource}, identityapi.Read)
			require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
			require.Nil(t, allowed)

			err = engine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read)
			require.ErrorIs(t, err, rbac.ErrDecisionUnavailable, "the remote shadow comparator reads this as no verdict")
			require.ErrorIs(t, err, authorizer.ErrPassportSubjectUnconfirmed)
			require.NotErrorIs(t, err, rbac.ErrPolicyDenied, "an echo failure is not a policy deny")
		})
	}
}

func BenchmarkAllowCoarseManyBearer(b *testing.B) {
	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(b, h))
	ctx := checkAuthContext(b, "", false)
	resources := []rbac.Resource{{Kind: "identity:groups", OrganizationID: "org-1"}}

	info, err := authorization.FromContext(ctx)
	require.NoError(b, err)

	info.Passport = authorizer.LargeTestPassport(b)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		allowed, err := engine.AllowCoarseMany(ctx, resources, identityapi.Read)
		if err != nil || !allowed[0] {
			b.Fatalf("check did not allow: %v", err)
		}
	}

	b.StopTimer()

	if h.requests != b.N {
		b.Fatalf("stub saw %d requests, want %d", h.requests, b.N)
	}

	if h.passportRequests != b.N || *h.gotBody.Passport != info.Passport {
		b.Fatalf("stub saw the large passport on %d of %d requests", h.passportRequests, b.N)
	}
}
