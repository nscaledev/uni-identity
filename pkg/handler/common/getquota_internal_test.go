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

package common

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const orgA = "a1111111-1111-4111-8111-111111111111"

func qty(s string) *resource.Quantity {
	v := resource.MustParse(s)

	return &v
}

func metaObj(name, def string) unikornv1.QuotaMetadata {
	return unikornv1.QuotaMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "identity"},
		Spec:       unikornv1.QuotaMetadataSpec{DisplayName: name, Default: qty(def), Format: unikornv1.Decimal},
	}
}

func quotaObj(kinds ...unikornv1.ResourceQuota) *unikornv1.Quota {
	return &unikornv1.Quota{
		ObjectMeta: metav1.ObjectMeta{Name: "quota", Namespace: "org-a", Labels: map[string]string{constants.OrganizationLabel: orgA}},
		Spec:       unikornv1.QuotaSpec{Quotas: kinds},
	}
}

func newTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func kinds(quotas []unikornv1.ResourceQuota) []string {
	out := make([]string, 0, len(quotas))

	for i := range quotas {
		out = append(out, quotas[i].Kind)
	}

	return out
}

func TestGetQuotaStoredQuotaKeepsKnownKindsAndFillsMissing(t *testing.T) {
	t.Parallel()

	gpus := metaObj("gpus", "4")
	servers := metaObj("servers", "10")
	stored := quotaObj(unikornv1.ResourceQuota{Kind: "retired", Quantity: qty("1")}, unikornv1.ResourceQuota{Kind: "gpus", Quantity: qty("8")})

	c := New(newTestClient(t, &gpus, &servers, stored))

	organizationID, err := ids.ParseOrganizationID(orgA)
	require.NoError(t, err)

	quota, virtual, err := c.GetQuota(t.Context(), organizationID)
	require.NoError(t, err)
	require.False(t, virtual)
	require.ElementsMatch(t, []string{"gpus", "servers"}, kinds(quota.Spec.Quotas))
	require.Equal(t, int64(8), quota.Spec.Quotas[slices.Index(kinds(quota.Spec.Quotas), "gpus")].Quantity.Value())
	require.Equal(t, int64(10), quota.Spec.Quotas[slices.Index(kinds(quota.Spec.Quotas), "servers")].Quantity.Value())
	require.Equal(t, "quota", quota.Name, "the stored object metadata is kept for patching")
}

func TestGetQuotaVirtualQuotaUsesDefaults(t *testing.T) {
	t.Parallel()

	gpus := metaObj("gpus", "4")

	c := New(newTestClient(t, &gpus))

	organizationID, err := ids.ParseOrganizationID(orgA)
	require.NoError(t, err)

	quota, virtual, err := c.GetQuota(t.Context(), organizationID)
	require.NoError(t, err)
	require.True(t, virtual)
	require.Equal(t, []string{"gpus"}, kinds(quota.Spec.Quotas))
	require.Equal(t, int64(4), quota.Spec.Quotas[0].Quantity.Value())
}
