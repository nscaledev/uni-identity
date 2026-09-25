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
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

func TestNormaliseVirtualQuotaUsesDefaults(t *testing.T) {
	t.Parallel()

	metadata := []unikornv1.QuotaMetadata{metaObj("gpus", "4"), metaObj("servers", "10")}

	out, err := Normalise(nil, metadata)
	require.NoError(t, err)
	require.Equal(t, []unikornv1.ResourceQuota{
		{Kind: "gpus", Quantity: metadata[0].Spec.Default},
		{Kind: "servers", Quantity: metadata[1].Spec.Default},
	}, out)
}

func TestNormaliseDropsRetiredKindsAndKeepsInputs(t *testing.T) {
	t.Parallel()

	metadata := []unikornv1.QuotaMetadata{metaObj("gpus", "4")}
	quota := quotaObj()
	quota.Spec.Quotas = make([]unikornv1.ResourceQuota, 0, 4)
	quota.Spec.Quotas = append(quota.Spec.Quotas, unikornv1.ResourceQuota{Kind: "retired", Quantity: qty("1")}, unikornv1.ResourceQuota{Kind: "gpus", Quantity: qty("8")})

	before := make([]unikornv1.ResourceQuota, 0, len(quota.Spec.Quotas))

	for i := range quota.Spec.Quotas {
		before = append(before, *quota.Spec.Quotas[i].DeepCopy())
	}

	beforeMetadata := make([]unikornv1.QuotaMetadata, 0, len(metadata))

	for i := range metadata {
		beforeMetadata = append(beforeMetadata, *metadata[i].DeepCopy())
	}

	out, err := Normalise(quota, metadata)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "gpus", out[0].Kind)
	require.Equal(t, int64(8), out[0].Quantity.Value())
	require.Equal(t, before, quota.Spec.Quotas, "Normalise must not write to its quota input")
	require.Equal(t, beforeMetadata, metadata, "Normalise must not write to its metadata input")
}

func TestNormaliseNilQuantityIsAFault(t *testing.T) {
	t.Parallel()

	_, err := Normalise(quotaObj(unikornv1.ResourceQuota{Kind: "gpus"}), []unikornv1.QuotaMetadata{metaObj("gpus", "4")})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestNormaliseTakesLastDuplicateKind(t *testing.T) {
	t.Parallel()

	metadata := []unikornv1.QuotaMetadata{metaObj("gpus", "8")}
	quota := quotaObj(unikornv1.ResourceQuota{Kind: "gpus", Quantity: qty("2")}, unikornv1.ResourceQuota{Kind: "gpus", Quantity: qty("5")})

	out, err := Normalise(quota, metadata)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "gpus", out[0].Kind)
	require.Equal(t, int64(5), out[0].Quantity.Value())
}

func TestNormaliseFollowsMetadataOrder(t *testing.T) {
	t.Parallel()

	metadata := []unikornv1.QuotaMetadata{metaObj("gpus", "8"), metaObj("servers", "20")}
	quota := quotaObj(unikornv1.ResourceQuota{Kind: "servers", Quantity: qty("20")}, unikornv1.ResourceQuota{Kind: "gpus", Quantity: qty("8")})

	out, err := Normalise(quota, metadata)
	require.NoError(t, err)
	require.Equal(t, []string{"gpus", "servers"}, kinds(out))
	require.Equal(t, int64(8), out[0].Quantity.Value())
	require.Equal(t, int64(20), out[1].Quantity.Value())
}
