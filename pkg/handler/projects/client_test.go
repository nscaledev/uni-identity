/*
Copyright 2025 the Unikorn Authors.

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

package projects_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	namespace             = "base"
	organizationID        = "foo"
	organizationNamespace = "bar"
	projectID             = "baz"
	reference             = "cat"
)

// setupFixtures sets up all the required apparatus to actually test
// anything, proving how annoying organization namespaces are!
func setupFixtures(t *testing.T) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, identityv1.AddToScheme(scheme))

	organization := &identityv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      organizationID,
		},
		Status: identityv1.OrganizationStatus{
			Namespace: organizationNamespace,
		},
	}

	organizationNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: organizationNamespace,
		},
	}

	project := &identityv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: organizationNamespace,
			Name:      projectID,
		},
	}

	objects := []client.Object{
		organization,
		organizationNS,
		project,
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func getProject(t *testing.T, cli client.Client) *identityv1.Project {
	t.Helper()

	project := &identityv1.Project{}

	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: organizationNamespace, Name: projectID}, project))

	return project
}

// TestReferences tests reference creation and deletion works and is idempotent.
func TestReferences(t *testing.T) {
	t.Parallel()

	cli := setupFixtures(t)

	client := projects.New(cli, namespace)

	// Create succeeds.
	require.NoError(t, client.ReferenceCreate(t.Context(), organizationID, projectID, reference))

	project := getProject(t, cli)
	require.Len(t, project.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(project, reference))

	// Create as second time succeeds.
	require.NoError(t, client.ReferenceCreate(t.Context(), organizationID, projectID, reference))

	project = getProject(t, cli)
	require.Len(t, project.Finalizers, 1)
	require.True(t, controllerutil.ContainsFinalizer(project, reference))

	// Delete succeeds.
	require.NoError(t, client.ReferenceDelete(t.Context(), organizationID, projectID, reference))

	project = getProject(t, cli)
	require.Empty(t, project.Finalizers)

	// Delete a second time succeeds.
	require.NoError(t, client.ReferenceDelete(t.Context(), organizationID, projectID, reference))

	project = getProject(t, cli)
	require.Empty(t, project.Finalizers)
}
