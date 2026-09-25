/*
Copyright 2022-2024 EscherCloud.
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

package handler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cachetest"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	orgA = "a1111111-1111-4111-8111-111111111111"
	orgB = "b2222222-2222-4222-8222-222222222222"
	p1   = "c1111111-1111-4111-8111-111111111111"
	p2   = "c2222222-2222-4222-8222-222222222222"
	p3   = "c3333333-3333-4333-8333-333333333333"
	p4   = "c4444444-4444-4444-8444-444444444444"
	ns   = "identity"
)

func allIncludes() []string { return []string{"quotas", "projects", "projectsCount"} }

func qty(s string) *resource.Quantity {
	v := resource.MustParse(s)

	return &v
}

func orgLabels(id string) map[string]string {
	return map[string]string{constants.OrganizationLabel: id}
}

// Organization-owned fixtures live in an organization namespace, not the
// identity namespace, so a list that wrongly scans the identity namespace
// without a selector cannot find them.
const orgNS = "org-ns"

func quotaObj(name, org, quantity string) *unikornv1.Quota {
	return &unikornv1.Quota{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: orgNS, Labels: orgLabels(org)},
		Spec:       unikornv1.QuotaSpec{Quotas: []unikornv1.ResourceQuota{{Kind: "gpus", Quantity: qty(quantity)}}},
	}
}

// quotaObjNilQuantity builds a Quota whose "gpus" entry has no quantity, a
// data fault.
func quotaObjNilQuantity(name, org string) *unikornv1.Quota {
	return &unikornv1.Quota{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: orgNS, Labels: orgLabels(org)},
		Spec:       unikornv1.QuotaSpec{Quotas: []unikornv1.ResourceQuota{{Kind: "gpus"}}},
	}
}

func allocationObj(name, org, committed, reserved string) *unikornv1.Allocation {
	return &unikornv1.Allocation{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: orgNS, Labels: orgLabels(org)},
		Spec:       unikornv1.AllocationSpec{Allocations: []unikornv1.ResourceAllocation{{Kind: "gpus", Committed: qty(committed), Reserved: qty(reserved)}}},
	}
}

// allocationObjNilQuantity builds an Allocation whose "gpus" entry has no
// committed or reserved quantity, a data fault.
func allocationObjNilQuantity(name, org string) *unikornv1.Allocation {
	return &unikornv1.Allocation{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: orgNS, Labels: orgLabels(org)},
		Spec:       unikornv1.AllocationSpec{Allocations: []unikornv1.ResourceAllocation{{Kind: "gpus"}}},
	}
}

func projectObj(name, org string) *unikornv1.Project {
	return &unikornv1.Project{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: orgNS, Labels: orgLabels(org)}}
}

func metaObj() *unikornv1.QuotaMetadata {
	return &unikornv1.QuotaMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: "gpus", Namespace: ns},
		Spec:       unikornv1.QuotaMetadataSpec{DisplayName: "gpus", Default: qty("1"), Format: unikornv1.Decimal},
	}
}

// newHandler serves objects the way the informer cache does, so the tests
// can assert the read-only, no-deep-copy contract and not only the results.
func newHandler(t *testing.T, objects ...client.Object) (*Handler, *cachetest.Store) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	store := cachetest.New(t, scheme, objects...)

	return &Handler{client: store.Client(), namespace: ns}, store
}

// requireNoCopyLists asserts every selected list disabled deep copies. It
// allows at most one unselected list, which must read the identity
// namespace. It also asserts that no backing object changed.
func requireNoCopyLists(t *testing.T, store *cachetest.Store) {
	t.Helper()

	unselected := 0

	for _, options := range store.ListOptions() {
		if options.LabelSelector == nil {
			// Only the QuotaMetadata list reads a namespace without a selector.
			require.Equal(t, ns, options.Namespace)

			unselected++

			continue
		}

		require.NotNil(t, options.UnsafeDisableDeepCopy)
		require.True(t, *options.UnsafeDisableDeepCopy)
	}

	require.LessOrEqual(t, unselected, 1)
	store.RequireUnchanged(t)
}

func items(ids ...string) []openapi.OrganizationListItem {
	out := make([]openapi.OrganizationListItem, len(ids))

	for i, id := range ids {
		out[i].Metadata.Id = id
	}

	return out
}

func read(endpoint string) openapi.AclEndpoint {
	return openapi.AclEndpoint{Name: endpoint, Operations: openapi.AclOperations{openapi.Read}}
}

func orgScopedACL(endpoints ...string) *openapi.Acl {
	e := make(openapi.AclEndpoints, 0, len(endpoints))

	for _, endpoint := range endpoints {
		e = append(e, read(endpoint))
	}

	return &openapi.Acl{Organizations: &openapi.AclOrganizationList{{Id: orgA, Endpoints: &e}}}
}

func projectScopedACL(project string) *openapi.Acl {
	return &openapi.Acl{Organizations: &openapi.AclOrganizationList{{
		Id:       orgA,
		Projects: &openapi.AclProjectList{{Id: project, Endpoints: openapi.AclEndpoints{read("identity:projects")}}},
	}}}
}

func TestIncludeGlobalReaderSeesEverything(t *testing.T) {
	t.Parallel()

	unlabelled := &unikornv1.Project{ObjectMeta: metav1.ObjectMeta{Name: p4, Namespace: orgNS}}
	h, store := newHandler(t, metaObj(), quotaObj("qa", orgA, "4"),
		allocationObj("alloc-a1", orgA, "2", "1"), allocationObj("alloc-a2", orgA, "1", "0"), allocationObj("alloc-b", orgB, "1", "0"),
		projectObj(p1, orgA), projectObj(p2, orgA), projectObj(p3, orgB), unlabelled)
	ctx := rbac.NewContext(t.Context(), &openapi.Acl{Global: &openapi.AclEndpoints{read("identity:quotas"), read("identity:projects")}})
	page := items(orgA, orgB)

	require.NoError(t, h.includeOrganizationExtras(ctx, page, allIncludes()))
	requireNoCopyLists(t, store)

	// Each organization sums usage from its own allocations only: orgA has
	// two allocations, and orgB has one against the default quota.
	require.Equal(t, 3, (*page[0].Quotas)[0].Committed)
	require.Equal(t, 1, (*page[0].Quotas)[0].Reserved)
	require.Equal(t, 4, (*page[0].Quotas)[0].Used)
	require.Equal(t, 1, (*page[1].Quotas)[0].Used)

	// Every selector names exactly the page's organizations.
	for _, options := range store.ListOptions() {
		if options.LabelSelector == nil {
			continue
		}

		requirements, _ := options.LabelSelector.Requirements()
		require.Len(t, requirements, 1)
		require.ElementsMatch(t, []string{orgA, orgB}, requirements[0].Values().UnsortedList())
	}

	require.NotNil(t, page[0].Quotas)
	require.Equal(t, 4, (*page[0].Quotas)[0].Quantity)
	require.Equal(t, 0, (*page[0].Quotas)[0].Free)
	require.Len(t, *page[0].Projects, 2)
	// The selector excludes the unlabelled project p4.  Only p1 and p2 remain.
	require.ElementsMatch(t, []string{p1, p2}, []string{(*page[0].Projects)[0].Metadata.Id, (*page[0].Projects)[1].Metadata.Id})
	require.Equal(t, 2, *page[0].ProjectsCount)
	// Organization B has no Quota object: the virtual default renders.
	require.Equal(t, 1, (*page[1].Quotas)[0].Quantity)
	require.Equal(t, 1, *page[1].ProjectsCount)
}

func TestIncludeOmitsWhatTheCallerMayNotSee(t *testing.T) {
	t.Parallel()

	h, store := newHandler(t, metaObj(), projectObj(p1, orgA), projectObj(p2, orgA), projectObj(p3, orgB))
	page := items(orgA, orgB)

	// Project-scope read on one project of A only: projects present with one entry, quotas absent.
	require.NoError(t, h.includeOrganizationExtras(rbac.NewContext(t.Context(), projectScopedACL(p2)), page, allIncludes()))
	requireNoCopyLists(t, store)
	require.Nil(t, page[0].Quotas)
	require.Len(t, *page[0].Projects, 1)
	require.Equal(t, p2, (*page[0].Projects)[0].Metadata.Id)
	require.Equal(t, 1, *page[0].ProjectsCount)
	require.Nil(t, page[1].Quotas)
	require.Nil(t, page[1].Projects)
	require.Nil(t, page[1].ProjectsCount)

	// Organization-scope projects read on A, no quota read: projects present (all), quotas absent.
	page = items(orgA)

	require.NoError(t, h.includeOrganizationExtras(rbac.NewContext(t.Context(), orgScopedACL("identity:projects")), page, allIncludes()))
	require.Nil(t, page[0].Quotas)
	require.Len(t, *page[0].Projects, 2)
}

func TestIncludeRequestedSubsetAndEmptyPage(t *testing.T) {
	t.Parallel()

	h, _ := newHandler(t, metaObj(), projectObj(p1, orgA))
	ctx := rbac.NewContext(t.Context(), orgScopedACL("identity:quotas", "identity:projects"))
	page := items(orgA)

	require.NoError(t, h.includeOrganizationExtras(ctx, page, []string{"projectsCount"}))
	require.Nil(t, page[0].Quotas)
	require.Nil(t, page[0].Projects)
	require.Equal(t, 1, *page[0].ProjectsCount)

	// Organization-scope read on both endpoints: every extra is present.
	page = items(orgA)

	require.NoError(t, h.includeOrganizationExtras(ctx, page, allIncludes()))
	require.NotNil(t, page[0].Quotas)
	require.Len(t, *page[0].Projects, 1)
	require.Equal(t, 1, *page[0].ProjectsCount)

	// An empty page or an empty include issues no list at all.
	idle, idleStore := newHandler(t, metaObj())

	require.NoError(t, idle.includeOrganizationExtras(ctx, nil, allIncludes()))
	require.NoError(t, idle.includeOrganizationExtras(ctx, items(orgA), nil))
	require.Empty(t, idleStore.ListOptions())
}

func TestIncludeFaultsFailOnlyPermittedRequestedRows(t *testing.T) {
	t.Parallel()

	h, _ := newHandler(t, metaObj(), quotaObj("q1", orgA, "4"), quotaObj("q2", orgA, "5"))
	permitted := rbac.NewContext(t.Context(), orgScopedACL("identity:quotas", "identity:projects"))

	err := h.includeOrganizationExtras(permitted, items(orgA), []string{"quotas"})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)

	require.NoError(t, h.includeOrganizationExtras(permitted, items(orgA), []string{"projects"}))

	unpermitted := rbac.NewContext(t.Context(), orgScopedACL("identity:projects"))
	require.NoError(t, h.includeOrganizationExtras(unpermitted, items(orgA), []string{"quotas"}))
}

func TestIncludeFaultsOnNilQuantity(t *testing.T) {
	t.Parallel()

	permitted := rbac.NewContext(t.Context(), orgScopedACL("identity:quotas", "identity:projects"))
	unpermitted := rbac.NewContext(t.Context(), orgScopedACL("identity:projects"))

	// A Quota with no quantity for its "gpus" kind is a data fault.
	quotaHandler, _ := newHandler(t, metaObj(), quotaObjNilQuantity("q1", orgA))

	err := quotaHandler.includeOrganizationExtras(permitted, items(orgA), []string{"quotas"})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
	require.NoError(t, quotaHandler.includeOrganizationExtras(unpermitted, items(orgA), []string{"quotas"}))

	// An Allocation with no committed or reserved quantity is a data fault.
	allocationHandler, _ := newHandler(t, metaObj(), allocationObjNilQuantity("alloc-a", orgA))

	err = allocationHandler.includeOrganizationExtras(permitted, items(orgA), []string{"quotas"})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
	require.NoError(t, allocationHandler.includeOrganizationExtras(unpermitted, items(orgA), []string{"quotas"}))
}
