/*
Copyright 2025 the Unikorn Authors.
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

package quotas

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common/fixtures"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestUpdateRendersRequestListAndGetNormalises(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}

	gpus := meta("gpus")
	gpus.Namespace = "identity"
	cpus := meta("cpus")
	cpus.Namespace = "identity"

	c := New(fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus, &cpus).Build(), "identity")

	// generate() stamps identity metadata from the principal in context.
	ctx := fixtures.HandlerContextFixture(t.Context(), 0)

	written, err := c.Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 4}}})
	require.NoError(t, err)
	require.Len(t, written.Quotas, 1)
	require.Equal(t, "gpus", written.Quotas[0].Kind)
	require.Equal(t, 4, written.Quotas[0].Quantity)

	read, err := c.Get(ctx, organizationID)
	require.NoError(t, err)
	require.Len(t, read.Quotas, 2)
	require.Equal(t, "cpus", read.Quotas[0].Kind)
	require.Equal(t, 1, read.Quotas[0].Quantity)
	require.Equal(t, "gpus", read.Quotas[1].Kind)
	require.Equal(t, 4, read.Quotas[1].Quantity)

	// Second write takes the patch path with the optimistic lock, which needs
	// GetQuota to keep the stored ObjectMeta.
	patched, err := c.Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 6}}})
	require.NoError(t, err)
	require.Len(t, patched.Quotas, 1)
	require.Equal(t, 6, patched.Quotas[0].Quantity)

	// Confirm the patch persisted, not just that Update's own response
	// rendered it.
	readAfterPatch, err := c.Get(ctx, organizationID)
	require.NoError(t, err)
	require.Len(t, readAfterPatch.Quotas, 2)
	require.Equal(t, "cpus", readAfterPatch.Quotas[0].Kind)
	require.Equal(t, 1, readAfterPatch.Quotas[0].Quantity)
	require.Equal(t, "gpus", readAfterPatch.Quotas[1].Kind)
	require.Equal(t, 6, readAfterPatch.Quotas[1].Quantity)
}
