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

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

func TestConvertSumsAllocationsAndSortsByKind(t *testing.T) {
	t.Parallel()

	metadata := []unikornv1.QuotaMetadata{metaObj("servers", "10"), metaObj("gpus", "4")}
	quotas := []unikornv1.ResourceQuota{{Kind: "servers", Quantity: qty("20")}, {Kind: "gpus", Quantity: qty("8")}}
	allocations := []unikornv1.Allocation{allocationObj("gpus", "3", "1"), allocationObj("gpus", "2", "0")}

	before := make([]unikornv1.ResourceQuota, 0, len(quotas))

	for i := range quotas {
		before = append(before, *quotas[i].DeepCopy())
	}

	beforeMetadata := make([]unikornv1.QuotaMetadata, 0, len(metadata))
	for i := range metadata {
		beforeMetadata = append(beforeMetadata, *metadata[i].DeepCopy())
	}

	beforeAllocations := make([]unikornv1.Allocation, 0, len(allocations))
	for i := range allocations {
		beforeAllocations = append(beforeAllocations, *allocations[i].DeepCopy())
	}

	out, err := Convert(quotas, metadata, allocations)
	require.NoError(t, err)
	require.Equal(t, before, quotas, "Convert must not write to its inputs")
	require.Equal(t, beforeMetadata, metadata, "Convert must not write to its metadata input")
	require.Equal(t, beforeAllocations, allocations, "Convert must not write to its allocations input")
	require.Len(t, out, 2)
	require.Equal(t, "gpus", out[0].Kind)
	require.Equal(t, 8, out[0].Quantity)
	require.Equal(t, 5, out[0].Committed)
	require.Equal(t, 1, out[0].Reserved)
	require.Equal(t, 6, out[0].Used)
	require.Equal(t, 2, out[0].Free)
	require.Equal(t, "Display gpus", out[0].DisplayName)
	require.Equal(t, 4, out[0].Default)
	require.Equal(t, "servers", out[1].Kind)
	require.Equal(t, 20, out[1].Free)
}

func TestConvertUnknownKindIsAFault(t *testing.T) {
	t.Parallel()

	_, err := Convert([]unikornv1.ResourceQuota{{Kind: "unknown", Quantity: qty("1")}}, []unikornv1.QuotaMetadata{metaObj("gpus", "4")}, nil)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestConvertNilQuantitiesAreFaults(t *testing.T) {
	t.Parallel()

	metadata := []unikornv1.QuotaMetadata{metaObj("gpus", "4")}

	_, err := Convert([]unikornv1.ResourceQuota{{Kind: "gpus"}}, metadata, nil)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)

	broken := unikornv1.Allocation{Spec: unikornv1.AllocationSpec{Allocations: []unikornv1.ResourceAllocation{{Kind: "gpus"}}}}

	_, err = Convert([]unikornv1.ResourceQuota{{Kind: "gpus", Quantity: qty("4")}}, metadata, []unikornv1.Allocation{broken})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestConvertNilMetadataDefaultIsAFault(t *testing.T) {
	t.Parallel()

	meta := metaObj("gpus", "4")
	meta.Spec.Default = nil

	metadata := []unikornv1.QuotaMetadata{meta}
	quotas := []unikornv1.ResourceQuota{{Kind: "gpus", Quantity: qty("1")}}

	_, err := Convert(quotas, metadata, nil)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}
