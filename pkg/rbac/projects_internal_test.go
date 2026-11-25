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

package rbac

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cachetest"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	estateNamespace = "identity"
	estateSubject   = "alice@example.com"
)

func estateOrganizationID(i int) string { return fmt.Sprintf("org-%d", i) }

func estateOrganizationNamespace(i int) string { return "ns-" + estateOrganizationID(i) }

// estateObjects returns organizations, each with a group holding the subject
// and projects linked to it, plus the one role they grant.
func estateObjects(organizations, projects int) []client.Object {
	objects := []client.Object{
		&unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: estateNamespace, Name: "role"},
			Spec: unikornv1.RoleSpec{Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{{Name: "organization:read", Operations: []unikornv1.Operation{unikornv1.Read}}},
				Project:      []unikornv1.RoleScope{{Name: "project:read", Operations: []unikornv1.Operation{unikornv1.Read}}},
			}},
		},
	}

	for i := range organizations {
		objects = append(objects,
			&unikornv1.Organization{
				ObjectMeta: metav1.ObjectMeta{Namespace: estateNamespace, Name: estateOrganizationID(i)},
				Status:     unikornv1.OrganizationStatus{Namespace: estateOrganizationNamespace(i)},
			},
			&unikornv1.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: estateOrganizationNamespace(i), Name: "group"},
				Spec: unikornv1.GroupSpec{
					RoleIDs:  []string{"role"},
					Subjects: []unikornv1.GroupSubject{{ID: estateSubject}},
				},
			},
		)

		for j := range projects {
			objects = append(objects, &unikornv1.Project{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: estateOrganizationNamespace(i),
					Name:      fmt.Sprintf("project-%d-%d", i, j),
					Labels:    map[string]string{constants.OrganizationLabel: estateOrganizationID(i)},
				},
				Spec: unikornv1.ProjectSpec{GroupIDs: []string{"group"}},
			})
		}
	}

	return objects
}

func newEstateClient(tb testing.TB, objects []client.Object, funcs interceptor.Funcs) client.Client {
	tb.Helper()

	scheme := runtime.NewScheme()
	require.NoError(tb, unikornv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(funcs).Build()
}

func estateContext(organizationID string) context.Context {
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: estateSubject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  []string{organizationID},
			},
		},
	}

	return authorization.NewContext(context.Background(), info)
}

// TestGetProjectsReturnsOnlyTheOrganizationsProjects checks that the namespaced
// List returns exactly the set the organization label selected, across many
// organizations, and that the ACL names only that organization's projects.
func TestGetProjectsReturnsOnlyTheOrganizationsProjects(t *testing.T) {
	t.Parallel()

	objects := estateObjects(40, 3)
	c := newEstateClient(t, objects, interceptor.Funcs{})
	r := New(c, estateNamespace, &Options{})

	for _, i := range []int{0, 17, 39} {
		projects, err := r.getProjects(t.Context(), estateOrganizationNamespace(i))
		require.NoError(t, err)

		byLabel := &unikornv1.ProjectList{}
		selector := labels.SelectorFromSet(labels.Set{constants.OrganizationLabel: estateOrganizationID(i)})
		require.NoError(t, c.List(t.Context(), byLabel, &client.ListOptions{LabelSelector: selector}))

		names := func(list *unikornv1.ProjectList) []string {
			out := make([]string, len(list.Items))
			for k := range list.Items {
				out[k] = list.Items[k].Name
			}

			return out
		}

		require.Len(t, projects.Items, 3)
		require.ElementsMatch(t, names(byLabel), names(projects))

		acl, err := r.GetACL(estateContext(estateOrganizationID(i)), estateOrganizationID(i))
		require.NoError(t, err)
		require.NotNil(t, acl.Projects)
		require.Len(t, *acl.Projects, 3)

		for _, project := range *acl.Projects {
			require.True(t, strings.HasPrefix(project.Id, fmt.Sprintf("project-%d-", i)), project.Id)
		}
	}
}

// labelProjects reads as the code did before: projects by organization label,
// with no namespace.
type labelProjects struct {
	client.Reader
}

func (l labelProjects) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*unikornv1.ProjectList); !ok {
		return l.Reader.List(ctx, list, opts...)
	}

	options := client.ListOptions{}
	options.ApplyOptions(opts)

	selector := labels.SelectorFromSet(labels.Set{constants.OrganizationLabel: strings.TrimPrefix(options.Namespace, "ns-")})

	return l.Reader.List(ctx, list, &client.ListOptions{LabelSelector: selector})
}

// BenchmarkACLBuild measures a scoped ACL build in an estate of 20,000
// organizations of 3 projects each, on a reader that costs what the informer
// cache costs (see cachetest). "namespaced" is the code as it is; "label" is
// the old project List by organization label, which walks every cached project.
func BenchmarkACLBuild(b *testing.B) {
	cache, err := cachetest.NewReader(estateObjects(20000, 3))
	require.NoError(b, err)

	for name, reader := range map[string]client.Reader{"namespaced": cache, "label": labelProjects{cache}} {
		b.Run(name, func(b *testing.B) {
			r := New(reader, estateNamespace, &Options{})
			ctx := estateContext(estateOrganizationID(0))

			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				if _, err := r.GetACL(ctx, estateOrganizationID(0)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
