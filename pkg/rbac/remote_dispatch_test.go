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

package rbac_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	openapiMock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the remote dispatch fork (dispatchCoarse, handler.go): the
// three Allow* scope forks now consult a remote CoarseEngine (the remote-engine
// context seam, NewRemoteEngineContext) ahead of today's local dispatch.  Under
// RemoteEnforce the remote engine is AUTHORITATIVE: its verdict is served with
// NO legacy fallback, fail-closed on unavailability — proven below over a
// GRANTING ACL, so a served deny can only be the remote engine's (a bug that
// fell through to the legacy walk would ALLOW). An unseeded context (every
// caller today) or an explicitly-off remote mode must dispatch exactly as
// before: the legacy ACL walk (no local Cerbos engine is seeded in these
// tests either, so there is no other path to fall to).
//
// RemoteShadow is the remote-shadow comparator (remoteShadowed); this task
// ships only a stub that unconditionally serves the legacy verdict, so shadow
// mode is deliberately not exercised here.

// fakeRemoteEngine is a minimal rbac.CoarseEngine double for the dispatch
// seam: it records how many times AllowCoarse was called and echoes a canned
// verdict, so a test can prove which side — remote or legacy — served a
// decision.
type fakeRemoteEngine struct {
	err       error
	calls     int
	resources []rbac.Resource
}

func (f *fakeRemoteEngine) AllowCoarse(_ context.Context, resource rbac.Resource, _ openapi.AclOperation) error {
	f.calls++
	f.resources = append(f.resources, resource)

	return f.err
}

func (f *fakeRemoteEngine) AllowCoarseMany(_ context.Context, _ []rbac.Resource, _ openapi.AclOperation) ([]bool, error) {
	return nil, nil
}

var _ rbac.CoarseEngine = (*fakeRemoteEngine)(nil)

func TestDispatchRemoteEnforceIsAuthoritative(t *testing.T) {
	t.Parallel()

	t.Run("a policy deny over a granting ACL is served, with no legacy fallback", func(t *testing.T) {
		t.Parallel()

		// The ACL grants read at global scope: if dispatchCoarse fell through
		// to the legacy walk (a bug), it would ALLOW. A served deny can
		// therefore only be the remote engine's verdict.
		fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, rbac.ErrPolicyDenied)}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Read)), fake, rbac.RemoteEnforce)

		err := rbac.AllowGlobalScope(ctx, "candy", openapi.Read)
		require.True(t, coreerrors.IsForbidden(err), "the remote engine's deny must be served, not the legacy allow")
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)
		require.Equal(t, 1, fake.calls)
	})

	t.Run("an unavailable remote engine fails closed with no legacy fallback", func(t *testing.T) {
		t.Parallel()

		fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, rbac.ErrDecisionUnavailable)}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Read)), fake, rbac.RemoteEnforce)

		err := rbac.AllowGlobalScope(ctx, "candy", openapi.Read)
		require.True(t, coreerrors.IsForbidden(err))
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable, "an unavailable remote engine must fail closed, never fall back to the legacy allow")
		require.Equal(t, 1, fake.calls)
	})

	t.Run("a remote allow is served over a legacy-denying ACL", func(t *testing.T) {
		t.Parallel()

		// The reverse direction, so the proof above isn't vacuously
		// always-deny: the ACL grants nothing (legacy would DENY) but the
		// remote engine allows.
		fake := &fakeRemoteEngine{}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), &openapi.Acl{}), fake, rbac.RemoteEnforce)

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "the remote engine's allow must be served, not the legacy deny")
		require.Equal(t, 1, fake.calls)
	})

	t.Run("AllowOrganizationScope and AllowProjectScope dispatch through the same seam", func(t *testing.T) {
		t.Parallel()

		fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, rbac.ErrPolicyDenied)}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Read)), fake, rbac.RemoteEnforce)

		err := rbac.AllowOrganizationScope(ctx, "candy", openapi.Read, organizationID)
		require.True(t, coreerrors.IsForbidden(err))
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)

		err = rbac.AllowProjectScope(ctx, "candy", openapi.Read, organizationID, projectID)
		require.True(t, coreerrors.IsForbidden(err))
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)

		require.Equal(t, 2, fake.calls, "both scope forks must reach the remote engine")
	})

	t.Run("AllowProjectScopeCreate serves a policy deny over a granting ACL", func(t *testing.T) {
		t.Parallel()

		fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Create, rbac.ErrPolicyDenied)}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Create)), fake, rbac.RemoteEnforce)

		err := rbac.AllowProjectScopeCreate(ctx, nil, "candy", openapi.Create, organizationID, projectID)
		require.True(t, coreerrors.IsForbidden(err), "the remote deny must not be overridden by the granting legacy ACL")
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)
		require.Equal(t, 1, fake.calls)
	})

	t.Run("AllowProjectScopeCreate fails closed when the remote engine is unavailable", func(t *testing.T) {
		t.Parallel()

		fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Create, rbac.ErrDecisionUnavailable)}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Create)), fake, rbac.RemoteEnforce)

		err := rbac.AllowProjectScopeCreate(ctx, nil, "candy", openapi.Create, organizationID, projectID)
		require.True(t, coreerrors.IsForbidden(err), "an outage must not fall back to the granting legacy ACL")
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
		require.Equal(t, 1, fake.calls)
	})

	t.Run("AllowProjectScopeCreate validates the project after a remote allow", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		client := openapiMock.NewMockClientWithResponsesInterface(ctrl)
		client.EXPECT().
			GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID)).
			Return(&openapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
				HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
			}, nil)

		fake := &fakeRemoteEngine{}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Create)), fake, rbac.RemoteEnforce)

		err := rbac.AllowProjectScopeCreate(ctx, client, "candy", openapi.Create, organizationID, projectID)
		require.True(t, coreerrors.IsHTTPNotFound(err), "a remote allow must not bypass live project validation")
		require.Equal(t, 1, fake.calls)
		require.Equal(t, []rbac.Resource{{Kind: "candy", OrganizationID: organizationID, ProjectID: projectID}}, fake.resources,
			"the authoritative check must include the caller-supplied tenancy before live validation")
	})
}

func TestDispatchRemoteOffIsUnchanged(t *testing.T) {
	t.Parallel()

	t.Run("an unseeded context takes today's legacy path", func(t *testing.T) {
		t.Parallel()

		ctx := rbac.NewContext(t.Context(), globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
		require.True(t, coreerrors.IsForbidden(err))
	})

	t.Run("an explicitly-off remote engine takes today's legacy path, never consulting the remote engine", func(t *testing.T) {
		t.Parallel()

		fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, rbac.ErrPolicyDenied)}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Read)), fake, rbac.RemoteOff)

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "RemoteOff must serve the legacy verdict even with a remote engine seeded")
		require.Zero(t, fake.calls, "RemoteOff must never consult the remote engine")
	})

	t.Run("AllowProjectScopeCreate retains its legacy shortcuts when explicitly off", func(t *testing.T) {
		t.Parallel()

		fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Create, rbac.ErrPolicyDenied)}
		ctx := rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Create)), fake, rbac.RemoteOff)

		require.NoError(t, rbac.AllowProjectScopeCreate(ctx, nil, "candy", openapi.Create, organizationID, projectID))
		require.Zero(t, fake.calls, "RemoteOff must retain the legacy global-scope shortcut without consulting the remote engine")
	})
}
