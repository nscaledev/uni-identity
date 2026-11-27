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

package project_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/constants"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/provisioners/project"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	orgID          = "org-1"
	projectID      = "project-1"
	otherProjectID = "project-2"
	projectNS      = "project-abc"
	identityNS     = "identity"
	instanceKind   = "instance"
	clusterKind    = "cluster"
)

// stubManager serves what the provisioner reads from the manager: a REST config
// for discovery and an API reader for the namespace lookup.
type stubManager struct {
	manager.Manager

	config *rest.Config
	reader client.Reader
}

func (m *stubManager) GetConfig() *rest.Config     { return m.config }
func (m *stubManager) GetAPIReader() client.Reader { return m.reader }

// discoveryServer answers the discovery call for the unikorn-cloud.org group
// with the given resource types (none by default, so the descendant sweep finds nothing).
func discoveryServer(t *testing.T, kinds ...metav1.APIResource) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(&metav1.APIResourceList{
			TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
			GroupVersion: "unikorn-cloud.org/v1alpha1",
			APIResources: kinds,
		}))
	}))

	t.Cleanup(server.Close)

	return server
}

func allocation(name, project, kind string) *unikornv1.Allocation {
	return &unikornv1.Allocation{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: projectNS,
			Name:      name,
			Labels: map[string]string{
				constants.OrganizationLabel:           orgID,
				constants.ProjectLabel:                project,
				constants.ReferencedResourceKindLabel: kind,
			},
		},
	}
}

// deprovision runs the project provisioner's Deprovision against a fake cluster
// that holds the project namespace and the given allocations.
func deprovision(t *testing.T, allocations ...*unikornv1.Allocation) (client.Client, error) {
	t.Helper()

	cli, _, err := deprovisionWithKinds(t, nil, nil, allocations...)

	return cli, err
}

// deprovisionWithKinds is deprovision with discovery serving the given kinds and the given
// objects in the cluster. It also returns the names the provisioner called delete on.
func deprovisionWithKinds(t *testing.T, kinds []metav1.APIResource, objects []client.Object, allocations ...*unikornv1.Allocation) (client.Client, []string, error) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: projectNS,
			Labels: map[string]string{
				constants.KindLabel:         constants.KindLabelValueProject,
				constants.OrganizationLabel: orgID,
				constants.ProjectLabel:      projectID,
			},
		},
	})

	for _, a := range allocations {
		builder = builder.WithObjects(a)
	}

	builder = builder.WithObjects(objects...)

	var deleted []string

	builder = builder.WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			deleted = append(deleted, obj.GetName())

			return c.Delete(ctx, obj, opts...)
		},
	})

	cli := builder.Build()

	server := discoveryServer(t, kinds...)

	p := project.New(nil)

	obj, ok := p.Object().(*unikornv1.Project)
	require.True(t, ok)

	obj.Namespace = identityNS
	obj.Name = projectID
	obj.Labels = map[string]string{constants.OrganizationLabel: orgID}

	ctx := coremanager.NewContext(t.Context(), &stubManager{config: &rest.Config{Host: server.URL}, reader: cli})
	ctx = coreclient.NewContext(ctx, cli)
	ctx = coreclient.NewContextWithCluster(ctx, &coreclient.ClusterContext{Client: cli})

	return cli, deleted, p.Deprovision(ctx)
}

func namespaceExists(t *testing.T, cli client.Client) bool {
	t.Helper()

	err := cli.Get(t.Context(), client.ObjectKey{Name: projectNS}, &corev1.Namespace{})
	if errors.IsNotFound(err) {
		return false
	}

	require.NoError(t, err)

	return true
}

func allocationNames(t *testing.T, cli client.Client) []string {
	t.Helper()

	var list unikornv1.AllocationList

	require.NoError(t, cli.List(t.Context(), &list))

	names := make([]string, 0, len(list.Items))
	for i := range list.Items {
		names = append(names, list.Items[i].Name)
	}

	return names
}

func TestDeprovision_NoAllocationsDeletesNamespace(t *testing.T) {
	t.Parallel()

	cli, err := deprovision(t)

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.False(t, namespaceExists(t, cli))
}

func TestDeprovision_AllocationLeftWaits(t *testing.T) {
	t.Parallel()

	cli, err := deprovision(t, allocation("a", projectID, instanceKind), allocation("b", projectID, instanceKind), allocation("c", projectID, clusterKind), allocation("d", projectID, ""))

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.Contains(t, err.Error(), "4 allocations")
	assert.Contains(t, err.Error(), "cluster=1, instance=2, unknown=1")
	assert.True(t, namespaceExists(t, cli), "namespace must stay while allocations are left")
}

func TestDeprovision_NeverDeletesAllocations(t *testing.T) {
	t.Parallel()

	cli, err := deprovision(t, allocation("a", projectID, instanceKind))

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.Equal(t, []string{"a"}, allocationNames(t, cli))
}

func TestDeprovision_OtherProjectsAllocationsDoNotHold(t *testing.T) {
	t.Parallel()

	cli, err := deprovision(t, allocation("other", otherProjectID, instanceKind))

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.False(t, namespaceExists(t, cli))
	assert.Equal(t, []string{"other"}, allocationNames(t, cli))
}

func TestDeprovision_SelectsByLabelNotNamespace(t *testing.T) {
	t.Parallel()

	held := allocation("held", projectID, instanceKind)
	held.Namespace = "somewhere-else"

	cli, err := deprovision(t, held)

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.True(t, namespaceExists(t, cli))
}

// The descendant sweep must run, and delete what it finds, before the allocation wait
// yields: a project held by an allocation still has its in-namespace resources cleaned up.
func TestDeprovision_SweepsDescendantsBeforeAllocationWait(t *testing.T) {
	t.Parallel()

	widget := &unstructured.Unstructured{}
	widget.SetGroupVersionKind(schema.GroupVersionKind{Group: "unikorn-cloud.org", Version: "v1alpha1", Kind: "Widget"})
	widget.SetNamespace(projectNS)
	widget.SetName("widget")

	kinds := []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: metav1.Verbs{"list", "delete"}}}

	cli, deleted, err := deprovisionWithKinds(t, kinds, []client.Object{widget}, allocation("a", projectID, instanceKind))

	require.ErrorIs(t, err, provisioners.ErrYield)
	assert.Equal(t, []string{"widget"}, deleted)
	assert.Equal(t, []string{"a"}, allocationNames(t, cli))
	assert.True(t, namespaceExists(t, cli))
}
