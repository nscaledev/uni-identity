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

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func q(s string) *resource.Quantity { v := resource.MustParse(s); return &v }

func meta(kind string) unikornv1.QuotaMetadata {
	return unikornv1.QuotaMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: kind},
		Spec:       unikornv1.QuotaMetadataSpec{DisplayName: kind, Default: q("1"), Format: unikornv1.Decimal},
	}
}

func alloc(kind, committed, reserved string) *unikornv1.Allocation {
	return &unikornv1.Allocation{Spec: unikornv1.AllocationSpec{Allocations: []unikornv1.ResourceAllocation{{Kind: kind, Committed: q(committed), Reserved: q(reserved)}}}}
}

func TestConvertSumsSortsAndSkipsUnknownKinds(t *testing.T) {
	t.Parallel()

	quotas := []unikornv1.ResourceQuota{{Kind: "gpus", Quantity: q("10")}, {Kind: "cpus", Quantity: q("100")}, {Kind: "unknown", Quantity: q("1")}}
	metadata := []unikornv1.QuotaMetadata{meta("gpus"), meta("cpus")}
	allocations := []*unikornv1.Allocation{alloc("gpus", "2", "1"), alloc("gpus", "3", "0")}

	out, err := Convert(quotas, metadata, allocations)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, "cpus", out[0].Kind)
	require.Equal(t, "gpus", out[1].Kind)
	require.Equal(t, 6, out[1].Used)
	require.Equal(t, 5, out[1].Committed)
	require.Equal(t, 1, out[1].Reserved)
	require.Equal(t, 4, out[1].Free)
}

func TestConvertRejectsNilQuantities(t *testing.T) {
	t.Parallel()

	_, err := Convert([]unikornv1.ResourceQuota{{Kind: "gpus"}}, []unikornv1.QuotaMetadata{meta("gpus")}, nil)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)

	bad := &unikornv1.Allocation{Spec: unikornv1.AllocationSpec{Allocations: []unikornv1.ResourceAllocation{{Kind: "gpus", Committed: q("1")}}}}

	_, err = Convert([]unikornv1.ResourceQuota{{Kind: "gpus", Quantity: q("1")}}, []unikornv1.QuotaMetadata{meta("gpus")}, []*unikornv1.Allocation{bad})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestConvertRejectsNilMetadataDefault(t *testing.T) {
	t.Parallel()

	noDefault := meta("gpus")
	noDefault.Spec.Default = nil

	_, err := Convert([]unikornv1.ResourceQuota{{Kind: "gpus", Quantity: q("10")}}, []unikornv1.QuotaMetadata{noDefault}, nil)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}
