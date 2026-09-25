/*
Copyright 2024-2025 the Unikorn Authors.
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

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func meta(kind, def string) unikornv1.QuotaMetadata {
	q := resource.MustParse(def)

	return unikornv1.QuotaMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: kind},
		Spec:       unikornv1.QuotaMetadataSpec{Default: &q},
	}
}

func TestNormaliseVirtualQuotaUsesDefaults(t *testing.T) {
	t.Parallel()

	out, err := Normalise(nil, []unikornv1.QuotaMetadata{meta("gpus", "8"), meta("cpus", "64")})
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, "gpus", out[0].Kind)
	require.Equal(t, int64(8), out[0].Quantity.Value())
}

func TestNormaliseKeepsQuotaDropsRetiredCopiesQuantities(t *testing.T) {
	t.Parallel()

	gpus := resource.MustParse("2")
	old := resource.MustParse("1")
	quota := &unikornv1.Quota{Spec: unikornv1.QuotaSpec{Quotas: make([]unikornv1.ResourceQuota, 0, 4)}}
	quota.Spec.Quotas = append(quota.Spec.Quotas, unikornv1.ResourceQuota{Kind: "gpus", Quantity: &gpus}, unikornv1.ResourceQuota{Kind: "retired", Quantity: &old})
	metadata := []unikornv1.QuotaMetadata{meta("gpus", "8"), meta("cpus", "64")}

	out, err := Normalise(quota, metadata)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, int64(2), out[0].Quantity.Value())
	require.NotSame(t, &gpus, out[0].Quantity)
	require.NotSame(t, metadata[1].Spec.Default, out[1].Quantity)

	// Input untouched: same length, same kinds, spare capacity not written.
	require.Len(t, quota.Spec.Quotas, 2)
	require.Equal(t, "retired", quota.Spec.Quotas[1].Kind)

	full := quota.Spec.Quotas[:cap(quota.Spec.Quotas)]
	require.Equal(t, unikornv1.ResourceQuota{}, full[2])
	require.Equal(t, unikornv1.ResourceQuota{}, full[3])
}

func TestNormaliseRejectsNilQuantity(t *testing.T) {
	t.Parallel()

	quota := &unikornv1.Quota{Spec: unikornv1.QuotaSpec{Quotas: []unikornv1.ResourceQuota{{Kind: "gpus"}}}}

	_, err := Normalise(quota, []unikornv1.QuotaMetadata{meta("gpus", "8")})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)

	broken := unikornv1.QuotaMetadata{ObjectMeta: metav1.ObjectMeta{Name: "cpus"}}

	_, err = Normalise(nil, []unikornv1.QuotaMetadata{broken})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}
