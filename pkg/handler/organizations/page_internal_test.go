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
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func org(name, id string) unikornv1.Organization {
	return unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:   id,
			Labels: map[string]string{constants.NameLabel: name},
		},
	}
}

func pageIDs(page []*unikornv1.Organization) []string {
	out := make([]string, len(page))

	for i, item := range page {
		out[i] = item.Name
	}

	return out
}

func TestPaginateOrdersByNameThenID(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("beta", "2"), org("alpha", "9"), org("alpha", "1"), org("Zeta", "5")}

	page, next := paginate(items, pageRequest{limit: 10})

	require.Nil(t, next)
	require.Equal(t, []string{"1", "9", "2", "5"}, pageIDs(page))
	require.Same(t, &items[3], page[3])
}

func TestPaginateBreaksCaseTiesByName(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("acme", "1"), org("Bravo", "3"), org("Acme", "2")}

	page, _ := paginate(items, pageRequest{limit: 10})

	require.Equal(t, []string{"2", "1", "3"}, pageIDs(page))
}

func TestPaginateFiltersCaseInsensitively(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("Acme", "1"), org("acme-two", "2"), org("other", "3")}

	page, _ := paginate(items, pageRequest{filter: normalizeFilter("ACME"), limit: 10})

	require.Equal(t, []string{"1", "2"}, pageIDs(page))
}

func TestPaginateLimitsAndContinues(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("a", "1"), org("b", "2"), org("c", "3")}

	page, next := paginate(items, pageRequest{limit: 2})
	require.Equal(t, []string{"1", "2"}, pageIDs(page))
	require.NotNil(t, next)
	require.Equal(t, newPageKey("b", "2", 1), *next)

	page, next = paginate(items, pageRequest{limit: 2, after: next})
	require.Equal(t, []string{"3"}, pageIDs(page))
	require.Nil(t, next)
}

func TestPaginateExactLimitRemainingHasNoNext(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("a", "1"), org("b", "2")}

	page, next := paginate(items, pageRequest{limit: 2})

	require.Len(t, page, 2)
	require.Nil(t, next)
}

func TestPaginateSeeksPastDeletedKey(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("a", "1"), org("c", "3")}

	after := newPageKey("b", "2", 0)

	page, _ := paginate(items, pageRequest{after: &after, limit: 10})

	require.Equal(t, []string{"3"}, pageIDs(page))
}

func TestPaginateSeeksPastMixedCaseKey(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("acme", "1"), org("Bravo", "3"), org("Acme", "2")}

	after := newPageKey("acme", "1", 0)

	page, _ := paginate(items, pageRequest{after: &after, limit: 10})

	require.Equal(t, []string{"3"}, pageIDs(page))
}

func TestPaginateLargeLimitDoesNotOverflow(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("a", "1"), org("b", "2"), org("c", "3")}
	after := newPageKey("a", "1", 0)

	page, next := paginate(items, pageRequest{limit: math.MaxInt, after: &after})

	require.Equal(t, []string{"2", "3"}, pageIDs(page))
	require.Nil(t, next)
}

func TestPaginateEmpty(t *testing.T) {
	t.Parallel()

	page, next := paginate(nil, pageRequest{limit: 5})

	require.Empty(t, page)
	require.Nil(t, next)
}

func TestPaginateLimitBelowOneReturnsOneItem(t *testing.T) {
	t.Parallel()

	items := []unikornv1.Organization{org("a", "1"), org("b", "2")}

	page, next := paginate(items, pageRequest{limit: 0})

	require.Equal(t, []string{"1"}, pageIDs(page))
	require.NotNil(t, next)
	require.Equal(t, newPageKey("a", "1", 0), *next)
}
