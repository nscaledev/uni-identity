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
	"fmt"
	"slices"
	"strings"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

type usage struct {
	committed int64
	reserved  int64
}

// sumAllocations totals committed and reserved quantities per kind.
func sumAllocations(allocations []*unikornv1.Allocation) (map[string]usage, error) {
	totals := map[string]usage{}

	for _, allocation := range allocations {
		for i := range allocation.Spec.Allocations {
			resource := &allocation.Spec.Allocations[i]

			if resource.Committed == nil || resource.Reserved == nil {
				return nil, fmt.Errorf("%w: allocation entry has no quantity", coreerrors.ErrConsistency)
			}

			total := totals[resource.Kind]
			total.committed += resource.Committed.Value()
			total.reserved += resource.Reserved.Value()
			totals[resource.Kind] = total
		}
	}

	return totals, nil
}

// Convert renders quotas with usage summed from allocations, sorted by
// Kind.  It skips a kind without metadata.  Three cases are data faults: a
// nil quota quantity, a nil QuotaMetadata default, and a nil committed or
// reserved allocation quantity.  Convert does not change its inputs.  The
// informer cache may share them.
func Convert(quotas []unikornv1.ResourceQuota, metadata []unikornv1.QuotaMetadata, allocations []*unikornv1.Allocation) (openapi.QuotaReadList, error) {
	totals, err := sumAllocations(allocations)
	if err != nil {
		return nil, err
	}

	out := make(openapi.QuotaReadList, 0, len(quotas))

	for i := range quotas {
		quota := &quotas[i]

		index := slices.IndexFunc(metadata, func(m unikornv1.QuotaMetadata) bool { return m.Name == quota.Kind })
		if index < 0 {
			continue
		}

		meta := &metadata[index]

		if quota.Quantity == nil {
			return nil, fmt.Errorf("%w: quota entry has no quantity", coreerrors.ErrConsistency)
		}

		if meta.Spec.Default == nil {
			return nil, fmt.Errorf("%w: quota metadata has no default", coreerrors.ErrConsistency)
		}

		used := totals[quota.Kind].committed + totals[quota.Kind].reserved

		out = append(out, openapi.QuotaRead{
			Kind:        quota.Kind,
			Quantity:    int(quota.Quantity.Value()),
			Used:        int(used),
			Free:        int(quota.Quantity.Value() - used),
			Committed:   int(totals[quota.Kind].committed),
			Reserved:    int(totals[quota.Kind].reserved),
			DisplayName: meta.Spec.DisplayName,
			Description: meta.Spec.Description,
			Default:     int(meta.Spec.Default.Value()),
			Format:      openapi.QuotaReadFormat(meta.Spec.Format),
		})
	}

	slices.SortStableFunc(out, func(a, b openapi.QuotaRead) int {
		return strings.Compare(a.Kind, b.Kind)
	})

	return out, nil
}
