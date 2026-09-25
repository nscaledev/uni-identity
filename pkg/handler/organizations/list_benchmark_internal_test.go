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

package organizations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// benchFixtureSize is the organization count the benchmarks measure against.
const benchFixtureSize = 11000

// benchFilterMatchModulus makes benchOrgName tag every tenth organization
// with the substring benchFilterTerm, a realistic ~10% filter match rate.
const benchFilterMatchModulus = 10

// benchFilterTerm is the substring BenchmarkListPageV2FilteredLimit50
// filters on.
const benchFilterTerm = "target"

// benchOrgName returns a realistic, varied-case display name.  Every tenth
// name carries benchFilterTerm, and every third name is upper-cased, so
// filtering and case folding both do real work.
func benchOrgName(i int) string {
	name := fmt.Sprintf("org-%05d", i)

	if i%benchFilterMatchModulus == 0 {
		name = benchFilterTerm + "-" + name
	}

	if i%3 == 0 {
		name = strings.ToUpper(name)
	}

	return name
}

// benchOrg returns one organization with a realistic spread of the fields
// that convert reads.  These are a description annotation, tags and, for one
// in ten, a domain mapping with provider IDs.
func benchOrg(i int) *unikornv1.Organization {
	id := fmt.Sprintf("org-%05d", i)

	o := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clientTestNamespace,
			Name:      id,
			Labels: map[string]string{
				constants.NameLabel: benchOrgName(i),
			},
			Annotations: map[string]string{
				constants.DescriptionAnnotation: fmt.Sprintf("benchmark organization %d", i),
			},
		},
		Spec: unikornv1.OrganizationSpec{
			Tags: unikornv1core.TagList{
				{Name: "environment", Value: "benchmark"},
				{Name: "team", Value: fmt.Sprintf("team-%d", i%20)},
			},
		},
		Status: unikornv1.OrganizationStatus{
			Namespace: "org-" + id,
			Conditions: []metav1.Condition{
				{Type: "Available", Status: metav1.ConditionTrue, Reason: "Provisioned", Message: "provisioned"},
			},
		},
	}

	if i%benchFilterMatchModulus == 1 {
		o.Spec.Domain = ptr.To(fmt.Sprintf("example-%d.test", i))
		o.Spec.ProviderScope = ptr.To(unikornv1.ProviderScopeGlobal)
		o.Spec.ProviderID = ptr.To(fmt.Sprintf("provider-%d", i%5))
	}

	return o
}

// benchFixtureObjects returns n benchmark organizations as client.Objects.
func benchFixtureObjects(n int) []client.Object {
	objects := make([]client.Object, n)

	for i := range n {
		objects[i] = benchOrg(i)
	}

	return objects
}

// benchFixtureItems returns n benchmark organizations by value, for
// BenchmarkPaginateKeys11k, which calls paginate directly.
func benchFixtureItems(n int) []unikornv1.Organization {
	items := make([]unikornv1.Organization, n)

	for i := range n {
		items[i] = *benchOrg(i)
	}

	return items
}

// setupBenchClient builds the fixture and store once, before the benchmark
// loop starts, and returns a principal context with global organization
// read.  The store does not shuffle or record options, so the loop times
// only the code under test.
func setupBenchClient(b *testing.B) (context.Context, *Client) {
	b.Helper()

	store := newStore(b, benchFixtureObjects(benchFixtureSize)...).ForBenchmark()

	return globalReadContext(b), New(store.Client(), clientTestNamespace)
}

// encode drains v into io.Discard as JSON, so the benchmark counts
// serialisation cost the way the real handler pays it.
func encode(b *testing.B, v any) {
	b.Helper()

	if err := json.NewEncoder(io.Discard).Encode(v); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkListV1Unlimited measures the deprecated v1 endpoint: a full list,
// sort and JSON encode of every organization, uncapped.
func BenchmarkListV1Unlimited(b *testing.B) {
	ctx, c := setupBenchClient(b)
	b.ReportAllocs()

	for b.Loop() {
		list, err := c.List(ctx, nil, nil, 0)
		if err != nil {
			b.Fatal(err)
		}

		encode(b, list)
	}
}

// BenchmarkListPageV2Limit50 measures one unfiltered v2 page of 50.
func BenchmarkListPageV2Limit50(b *testing.B) {
	ctx, c := setupBenchClient(b)
	b.ReportAllocs()

	for b.Loop() {
		page, err := c.ListPage(ctx, nil, &Walk{Limit: 50})
		if err != nil {
			b.Fatal(err)
		}

		encode(b, page)
	}
}

// BenchmarkListPageV2Limit1 measures one unfiltered v2 page of 1, the
// narrowest page the sort-per-page cost still pays in full.
func BenchmarkListPageV2Limit1(b *testing.B) {
	ctx, c := setupBenchClient(b)
	b.ReportAllocs()

	for b.Loop() {
		page, err := c.ListPage(ctx, nil, &Walk{Limit: 1})
		if err != nil {
			b.Fatal(err)
		}

		encode(b, page)
	}
}

// BenchmarkListPageV2FilteredLimit50 measures one v2 page of 50 filtered to
// about 10% of the fixture.
func BenchmarkListPageV2FilteredLimit50(b *testing.B) {
	ctx, c := setupBenchClient(b)
	b.ReportAllocs()

	for b.Loop() {
		page, err := c.ListPage(ctx, nil, &Walk{Filter: benchFilterTerm, Limit: 50})
		if err != nil {
			b.Fatal(err)
		}

		encode(b, page)
	}
}

// BenchmarkPaginateKeys11k measures paginate alone, isolating the sort from
// the list and convert cost the other benchmarks also pay.
func BenchmarkPaginateKeys11k(b *testing.B) {
	items := benchFixtureItems(benchFixtureSize)

	b.ReportAllocs()

	for b.Loop() {
		page, _ := paginate(items, pageRequest{limit: len(items)})

		if len(page) != len(items) {
			b.Fatalf("got %d items, want %d", len(page), len(items))
		}
	}
}
