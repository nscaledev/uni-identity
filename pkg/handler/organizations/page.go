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

package organizations

import (
	"cmp"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// pageKey is the sort key of one organization: folded display name label,
// display name label, then ID.  Sorting keys instead of organizations keeps
// swaps small and label lookups out of the comparator.
type pageKey struct {
	folded string
	name   string
	id     string
	index  int
}

// newPageKey makes the key of one organization.  Display names are label
// values, and label values are ASCII, so strings.ToLower folds case exactly.
func newPageKey(name, id string, index int) pageKey {
	return pageKey{folded: strings.ToLower(name), name: name, id: id, index: index}
}

// normalizeFilter folds a display name filter to the case of the folded sort
// key.  The name parameter and a cursor filter are both label-value
// characters, which are ASCII, so strings.ToLower folds case exactly.
func normalizeFilter(s string) string {
	return strings.ToLower(s)
}

// pageRequest selects one page.  paginate treats a limit less than 1 as 1.
type pageRequest struct {
	filter string
	after  *pageKey
	limit  int
}

// compareKeys orders by display name without regard to case.  The exact
// display name, then the ID, break ties, so the order is total.
func compareKeys(a, b pageKey) int {
	return cmp.Or(strings.Compare(a.folded, b.folded), strings.Compare(a.name, b.name), strings.Compare(a.id, b.id))
}

// paginate filters, orders and slices items.  It returns pointers into items
// and the key of the last item on the page when more items follow.  A limit
// less than 1 counts as 1, so a non-empty page always has a last item.
func paginate(items []unikornv1.Organization, req pageRequest) ([]*unikornv1.Organization, *pageKey) {
	filter := normalizeFilter(req.filter)
	limit := max(req.limit, 1)

	keys := make([]pageKey, 0, len(items))

	for i := range items {
		key := newPageKey(items[i].Labels[constants.NameLabel], items[i].Name, i)

		if filter != "" && !strings.Contains(key.folded, filter) {
			continue
		}

		keys = append(keys, key)
	}

	slices.SortFunc(keys, compareKeys)

	start := 0

	if req.after != nil {
		pos, found := slices.BinarySearchFunc(keys, *req.after, compareKeys)

		start = pos

		if found {
			start++
		}
	}

	end := len(keys)

	// Compare against the remainder: start+limit can overflow.
	if limit < end-start {
		end = start + limit
	}

	page := make([]*unikornv1.Organization, 0, end-start)

	for _, key := range keys[start:end] {
		page = append(page, &items[key.index])
	}

	if end < len(keys) {
		return page, &keys[end-1]
	}

	return page, nil
}
