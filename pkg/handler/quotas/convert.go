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
	"fmt"
	"slices"
	"strings"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// allocation totals the committed and reserved amounts of one kind.
type allocation struct {
	committed int64
	reserved  int64
}

// sumAllocations totals allocations per kind. A nil quantity is a data
// fault and returns an error.
func sumAllocations(allocations []unikornv1.Allocation) (map[string]allocation, error) {
	totals := map[string]allocation{}

	for i := range allocations {
		for j := range allocations[i].Spec.Allocations {
			resource := &allocations[i].Spec.Allocations[j]

			if resource.Committed == nil || resource.Reserved == nil {
				return nil, fmt.Errorf("%w: allocation %s kind %s has no quantity", coreerrors.ErrConsistency, allocations[i].Name, resource.Kind)
			}

			total := totals[resource.Kind]
			total.committed += resource.Committed.Value()
			total.reserved += resource.Reserved.Value()

			totals[resource.Kind] = total
		}
	}

	return totals, nil
}

// checkQuotaAndMetadata reports whether the quota quantity or the metadata
// default is missing. The two are different data faults, so each gets its own
// message.
func checkQuotaAndMetadata(quota *unikornv1.ResourceQuota, meta *unikornv1.QuotaMetadata) error {
	if quota.Quantity == nil {
		return fmt.Errorf("%w: quota kind %s has no quantity", coreerrors.ErrConsistency, quota.Kind)
	}

	if meta.Spec.Default == nil {
		return fmt.Errorf("%w: quota metadata %s has no default", coreerrors.ErrConsistency, quota.Kind)
	}

	return nil
}

// Convert renders quotas with usage summed from allocations, sorted by Kind.
// A kind with no metadata, or a nil quantity, is a data fault and returns an
// error. Convert reads quantities only with Value and never writes to them.
// Its inputs can therefore come from the informer cache without a copy.
func Convert(quotas []unikornv1.ResourceQuota, metadata []unikornv1.QuotaMetadata, allocations []unikornv1.Allocation) (openapi.QuotaReadList, error) {
	totals, err := sumAllocations(allocations)
	if err != nil {
		return nil, err
	}

	out := make(openapi.QuotaReadList, 0, len(quotas))

	for i := range quotas {
		quota := &quotas[i]

		index := slices.IndexFunc(metadata, func(m unikornv1.QuotaMetadata) bool { return m.Name == quota.Kind })
		if index < 0 {
			return nil, fmt.Errorf("%w: quota kind %s has no metadata", coreerrors.ErrConsistency, quota.Kind)
		}

		meta := &metadata[index]

		if err := checkQuotaAndMetadata(quota, meta); err != nil {
			return nil, err
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
