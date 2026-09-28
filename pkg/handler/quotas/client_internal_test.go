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

package quotas

import (
	"testing"

	"github.com/stretchr/testify/require"

	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common/fixtures"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestUpdateRejectsUnknownKindBeforeWriting(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}

	def := resource.MustParse("1")
	gpus := &unikornv1.QuotaMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: "gpus", Namespace: "identity"},
		Spec:       unikornv1.QuotaMetadataSpec{DisplayName: "GPUs", Default: &def, Format: unikornv1.Decimal},
	}

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, gpus).Build()

	ctx := fixtures.HandlerContextFixture(t.Context(), 0)

	_, err := New(k8s, "identity").Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}, {Kind: "bogus", Quantity: 1}}})
	require.True(t, servererrors.IsBadRequest(err), "an unknown kind is a bad request, got %v", err)

	var stored unikornv1.QuotaList

	require.NoError(t, k8s.List(ctx, &stored))
	require.Empty(t, stored.Items, "the rejected request writes nothing")
}
