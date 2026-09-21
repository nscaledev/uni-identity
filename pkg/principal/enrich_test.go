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

package principal_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

const (
	enrichOrgID  = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	enrichProjID = "550e8400-e29b-41d4-a716-446655440000"
)

var errScope = errors.New("scope accessor failed")

// scopeStub stands in for a CRD that reports its scope via the ids scope-reader
// interfaces, returning fixed IDs (or an error).
type scopeStub struct {
	orgID  ids.OrganizationID
	projID ids.ProjectID
	err    error
}

func (s scopeStub) OrganizationID() (ids.OrganizationID, error) {
	return s.orgID, s.err
}

func (s scopeStub) OrganizationAndProjectID() (ids.OrganizationID, ids.ProjectID, error) {
	return s.orgID, s.projID, s.err
}

func TestEnrichUserPrincipalProjectScopeID(t *testing.T) {
	t.Parallel()

	orgID := ids.MustParseOrganizationID(enrichOrgID)
	projID := ids.MustParseProjectID(enrichProjID)

	t.Run("missing principal errors", func(t *testing.T) {
		t.Parallel()

		err := principal.EnrichUserPrincipalProjectScopeID(t.Context(), orgID, projID)
		require.Error(t, err)
	})

	t.Run("fills organization and project when unset", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{}
		ctx := principal.NewContext(t.Context(), p)

		require.NoError(t, principal.EnrichUserPrincipalProjectScopeID(ctx, orgID, projID))
		require.Equal(t, enrichOrgID, p.OrganizationID)
		require.Equal(t, enrichProjID, p.ProjectID)
	})

	t.Run("preserves existing attribution", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{OrganizationID: "existing-org", ProjectID: "existing-project"}
		ctx := principal.NewContext(t.Context(), p)

		require.NoError(t, principal.EnrichUserPrincipalProjectScopeID(ctx, orgID, projID))
		require.Equal(t, "existing-org", p.OrganizationID)
		require.Equal(t, "existing-project", p.ProjectID)
	})
}

func TestEnrichUserPrincipalOrganizationScopeID(t *testing.T) {
	t.Parallel()

	orgID := ids.MustParseOrganizationID(enrichOrgID)

	t.Run("missing principal errors", func(t *testing.T) {
		t.Parallel()

		err := principal.EnrichUserPrincipalOrganizationScopeID(t.Context(), orgID)
		require.Error(t, err)
	})

	t.Run("fills organization when unset", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{}
		ctx := principal.NewContext(t.Context(), p)

		require.NoError(t, principal.EnrichUserPrincipalOrganizationScopeID(ctx, orgID))
		require.Equal(t, enrichOrgID, p.OrganizationID)
	})

	t.Run("preserves existing attribution", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{OrganizationID: "existing-org"}
		ctx := principal.NewContext(t.Context(), p)

		require.NoError(t, principal.EnrichUserPrincipalOrganizationScopeID(ctx, orgID))
		require.Equal(t, "existing-org", p.OrganizationID)
	})
}

func TestEnrichUserPrincipalProjectScopeReader(t *testing.T) {
	t.Parallel()

	scope := scopeStub{
		orgID:  ids.MustParseOrganizationID(enrichOrgID),
		projID: ids.MustParseProjectID(enrichProjID),
	}

	t.Run("fills organization and project from the resource", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{}
		ctx := principal.NewContext(t.Context(), p)

		require.NoError(t, principal.EnrichUserPrincipalProjectScopeReader(ctx, scope))
		require.Equal(t, enrichOrgID, p.OrganizationID)
		require.Equal(t, enrichProjID, p.ProjectID)
	})

	t.Run("accessor error propagates", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{})

		err := principal.EnrichUserPrincipalProjectScopeReader(ctx, scopeStub{err: errScope})
		require.ErrorIs(t, err, errScope)
	})
}

func TestEnrichUserPrincipalOrganizationScopeReader(t *testing.T) {
	t.Parallel()

	scope := scopeStub{orgID: ids.MustParseOrganizationID(enrichOrgID)}

	t.Run("fills organization from the resource", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{}
		ctx := principal.NewContext(t.Context(), p)

		require.NoError(t, principal.EnrichUserPrincipalOrganizationScopeReader(ctx, scope))
		require.Equal(t, enrichOrgID, p.OrganizationID)
	})

	t.Run("accessor error propagates", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{})

		err := principal.EnrichUserPrincipalOrganizationScopeReader(ctx, scopeStub{err: errScope})
		require.ErrorIs(t, err, errScope)
	})
}
