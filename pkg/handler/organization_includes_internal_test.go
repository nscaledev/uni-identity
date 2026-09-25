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

package handler

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

// listCall holds the kind and options of one recorded cache list.
type listCall struct {
	kind    string
	options client.ListOptions
}

// recorder records the kind and options of each cache list that the code
// under test makes.
type recorder struct {
	lists []listCall
}

func (r *recorder) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			options := client.ListOptions{}
			options.ApplyOptions(opts)

			r.lists = append(r.lists, listCall{kind: fmt.Sprintf("%T", list), options: options})

			return inner.List(ctx, list, opts...)
		},
	}
}

func allIncludes() []string { return []string{"quotas", "projectsCount"} }

func qty(s string) *resource.Quantity {
	v := resource.MustParse(s)

	return &v
}

func orgLabels(id string) map[string]string {
	return map[string]string{constants.OrganizationLabel: id}
}

// Organization-owned fixtures are in an organization namespace, not in the
// identity namespace. A list that reads only the identity namespace cannot
// find them.
const orgNS = "org-ns"

func quotaObj(name, org, quantity string) *unikornv1.Quota {
	return &unikornv1.Quota{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: orgNS, Labels: orgLabels(org)},
		Spec:       unikornv1.QuotaSpec{Quotas: []unikornv1.ResourceQuota{{Kind: "gpus", Quantity: qty(quantity)}}},
	}
}

// quotaObjNilQuantity builds a Quota whose "gpus" entry has no quantity.
// This is a data fault.
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
// committed or reserved quantity. This is a data fault.
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

func newHandler(t *testing.T, r *recorder, objects ...client.Object) *Handler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(r.funcs()).Build()

	return &Handler{client: c, namespace: ns}
}

// requireSharedLists asserts that every list disables deep copies and has no
// selector. Only the QuotaMetadata list reads the identity namespace. Every
// other list reads all namespaces.
func requireSharedLists(t *testing.T, r *recorder) {
	t.Helper()

	quotaMetadataKind := fmt.Sprintf("%T", &unikornv1.QuotaMetadataList{})

	for _, call := range r.lists {
		require.True(t, ptr.Deref(call.options.UnsafeDisableDeepCopy, false))
		require.Nil(t, call.options.LabelSelector)

		if call.kind == quotaMetadataKind {
			require.Equal(t, ns, call.options.Namespace)
			continue
		}

		require.Empty(t, call.options.Namespace)
	}
}

func items(ids ...string) openapi.Organizations {
	out := make(openapi.Organizations, 0, len(ids))

	for _, id := range ids {
		out = append(out, openapi.OrganizationRead{Metadata: coreopenapi.ResourceReadMetadata{Id: id}})
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

func globalContext(t *testing.T) context.Context {
	t.Helper()

	return rbac.NewContext(t.Context(), &openapi.Acl{Global: &openapi.AclEndpoints{read("identity:quotas"), read("identity:projects")}})
}

func projectScopeContext(t *testing.T, project string) context.Context {
	t.Helper()

	return rbac.NewContext(t.Context(), projectScopedACL(project))
}

func TestIncludeGlobalReaderSeesEverything(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	h := newHandler(t, r, metaObj(), quotaObj("q1", orgA, "8"), allocationObj("a1", orgA, "3", "1"), projectObj(p1, orgA), projectObj(p2, orgA), projectObj(p3, orgB))
	rows := items(orgA, orgB)

	require.NoError(t, h.includeOrganizationExtras(globalContext(t), rows, allIncludes()))

	require.NotNil(t, rows[0].Quotas)
	require.NotEmpty(t, *rows[0].Quotas)
	require.Equal(t, 8, (*rows[0].Quotas)[0].Quantity)
	require.Equal(t, 4, (*rows[0].Quotas)[0].Used)
	require.Equal(t, ptr.To(2), rows[0].ProjectsCount)
	require.Nil(t, rows[0].QuotasError)

	require.NotNil(t, rows[1].Quotas, "virtual quota renders the metadata defaults")
	require.NotEmpty(t, *rows[1].Quotas)
	require.Equal(t, 1, (*rows[1].Quotas)[0].Quantity)
	require.Equal(t, ptr.To(1), rows[1].ProjectsCount)

	require.Len(t, r.lists, 4, "quotas, allocations, metadata and projects, once each")
	requireSharedLists(t, r)
}

func TestIncludeOmitsWhatTheCallerMayNotSee(t *testing.T) {
	t.Parallel()

	h := newHandler(t, &recorder{}, metaObj(), projectObj(p1, orgA), projectObj(p2, orgA), projectObj(p3, orgB))
	rows := items(orgA, orgB)

	// The caller can read project p1 only. It cannot read quotas.
	require.NoError(t, h.includeOrganizationExtras(projectScopeContext(t, p1), rows, allIncludes()))

	require.Nil(t, rows[0].Quotas)
	require.Nil(t, rows[0].QuotasError)
	require.Equal(t, ptr.To(1), rows[0].ProjectsCount)
	require.Nil(t, rows[1].Quotas)
	require.Nil(t, rows[1].ProjectsCount)
}

func TestIncludeOrganizationReaderSeesItsOrganizationOnly(t *testing.T) {
	t.Parallel()

	h := newHandler(t, &recorder{}, metaObj(), quotaObj("q1", orgA, "8"), quotaObj("q2", orgB, "9"), projectObj(p1, orgA), projectObj(p2, orgA), projectObj(p3, orgB))
	rows := items(orgA, orgB)

	// The caller can read quotas and projects in orgA only. orgA gets quotas
	// and the full count. orgB gets no extras.
	require.NoError(t, h.includeOrganizationExtras(rbac.NewContext(t.Context(), orgScopedACL("identity:quotas", "identity:projects")), rows, allIncludes()))

	require.NotNil(t, rows[0].Quotas)
	require.NotEmpty(t, *rows[0].Quotas)
	require.Equal(t, 8, (*rows[0].Quotas)[0].Quantity)
	require.Equal(t, ptr.To(2), rows[0].ProjectsCount)
	require.Nil(t, rows[1].Quotas)
	require.Nil(t, rows[1].QuotasError)
	require.Nil(t, rows[1].ProjectsCount)
}

func TestIncludeIgnoresObjectsWithoutTheOrganizationLabel(t *testing.T) {
	t.Parallel()

	unlabelled := quotaObj("stray", orgA, "99")
	unlabelled.Labels = nil
	strayProject := projectObj(p4, orgA)
	strayProject.Labels = nil

	h := newHandler(t, &recorder{}, metaObj(), unlabelled, strayProject, projectObj(p1, orgA))
	rows := items(orgA)

	require.NoError(t, h.includeOrganizationExtras(globalContext(t), rows, allIncludes()))

	require.NotNil(t, rows[0].Quotas, "no labelled quota, so the virtual quota renders the defaults")
	require.NotEmpty(t, *rows[0].Quotas)
	require.Equal(t, 1, (*rows[0].Quotas)[0].Quantity)
	require.Equal(t, ptr.To(1), rows[0].ProjectsCount)
}

func TestIncludeEmptyRequestsIssueNoLists(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	h := newHandler(t, r, metaObj())

	require.NoError(t, h.includeOrganizationExtras(globalContext(t), items(orgA), nil))
	require.NoError(t, h.includeOrganizationExtras(globalContext(t), items(), allIncludes()))
	require.Empty(t, r.lists)
}

func TestIncludeRowFaultDegradesThatRowOnly(t *testing.T) {
	t.Parallel()

	const (
		orgC = "c3333333-3333-4333-8333-333333333333"
		orgD = "d4444444-4444-4444-8444-444444444444"
	)

	h := newHandler(t, &recorder{}, metaObj(), quotaObj("q1", orgA, "8"), quotaObj("q2", orgA, "9"), quotaObjNilQuantity("q3", orgB), allocationObjNilQuantity("a9", orgD))
	rows := items(orgA, orgB, orgC, orgD)

	require.NoError(t, h.includeOrganizationExtras(globalContext(t), rows, []string{"quotas"}))

	require.Nil(t, rows[0].Quotas, "two quota objects")
	require.Equal(t, ptr.To(quotasErrorText), rows[0].QuotasError)
	require.Nil(t, rows[1].Quotas, "nil quota quantity")
	require.Equal(t, ptr.To(quotasErrorText), rows[1].QuotasError)
	require.NotNil(t, rows[2].Quotas, "a healthy row still renders")
	require.Nil(t, rows[2].QuotasError)
	require.Nil(t, rows[3].Quotas, "nil allocation quantity")
	require.Equal(t, ptr.To(quotasErrorText), rows[3].QuotasError)
}

func TestIncludeRowFaultNeedsQuotaReadAndRequest(t *testing.T) {
	t.Parallel()

	h := newHandler(t, &recorder{}, metaObj(), quotaObj("q1", orgA, "8"), quotaObj("q2", orgA, "9"))

	rows := items(orgA)
	require.NoError(t, h.includeOrganizationExtras(globalContext(t), rows, []string{"projectsCount"}))
	require.Nil(t, rows[0].QuotasError)

	rows = items(orgA)
	require.NoError(t, h.includeOrganizationExtras(rbac.NewContext(t.Context(), &openapi.Acl{}), rows, []string{"quotas"}))
	require.Nil(t, rows[0].QuotasError)
}

func TestIncludeMetadataFaultFailsTheRequest(t *testing.T) {
	t.Parallel()

	broken := metaObj()
	broken.Spec.Default = nil

	h := newHandler(t, &recorder{}, broken)

	err := h.includeOrganizationExtras(globalContext(t), items(orgA), []string{"quotas"})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}
