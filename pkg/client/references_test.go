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

package client_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/util"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	openapiMock "github.com/unikorn-cloud/identity/pkg/openapi/mock"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	crClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errConnectionRefused = errors.New("connection refused")

// newReferencesTestContext creates a context containing a fake Kubernetes client
// with the identity scheme and a REST mapper that knows about Project resources.
func newReferencesTestContext(t *testing.T) context.Context {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, identityv1.AddToScheme(scheme))

	gv := identityv1.SchemeGroupVersion
	mapper := apimeta.NewDefaultRESTMapper([]schema.GroupVersion{gv})
	mapper.Add(gv.WithKind("Project"), apimeta.RESTScopeNamespace)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRESTMapper(mapper).
		Build()

	return coreclient.NewContext(t.Context(), c)
}

// newTestResource returns a Project with org/project labels set.
func newTestResource() crClient.Object {
	return &identityv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-resource",
			Namespace: "test-ns",
			Labels: map[string]string{
				constants.OrganizationLabel: "test-org",
				constants.ProjectLabel:      "test-project",
			},
		},
	}
}

// newTestReferences creates a References with the given mock injected as the HTTP client factory.
func newTestReferences(mock openapi.ClientWithResponsesInterface) *client.References {
	r := client.NewReferences(util.ServiceDescriptor{}, nil, nil)
	r.SetClientFactory(func(_ context.Context, _ crClient.Client, _ crClient.Object) (openapi.ClientWithResponsesInterface, error) {
		return mock, nil
	})

	return r
}

func TestAddReferenceToProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(m *openapiMock.MockClientWithResponsesInterface)
		wantError bool
	}{
		{
			name: "success (new reference)",
			setup: func(m *openapiMock.MockClientWithResponsesInterface) {
				m.EXPECT().
					PutApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(
						gomock.Any(), "test-org", "test-project", gomock.Any(),
					).
					Return(&openapi.PutApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusCreated},
					}, nil)
			},
			wantError: false,
		},
		{
			name: "idempotent (reference already exists)",
			setup: func(m *openapiMock.MockClientWithResponsesInterface) {
				m.EXPECT().
					PutApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(
						gomock.Any(), "test-org", "test-project", gomock.Any(),
					).
					Return(&openapi.PutApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusCreated},
					}, nil)
			},
			wantError: false,
		},
		{
			name: "server error propagates",
			setup: func(m *openapiMock.MockClientWithResponsesInterface) {
				m.EXPECT().
					PutApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(
						gomock.Any(), "test-org", "test-project", gomock.Any(),
					).
					Return(nil, errConnectionRefused)
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			m := openapiMock.NewMockClientWithResponsesInterface(ctrl)
			tc.setup(m)

			refs := newTestReferences(m)
			ctx := newReferencesTestContext(t)
			resource := newTestResource()

			err := refs.AddReferenceToProject(ctx, resource)

			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRemoveReferenceFromProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(m *openapiMock.MockClientWithResponsesInterface)
		wantError bool
	}{
		{
			name: "success (reference existed)",
			setup: func(m *openapiMock.MockClientWithResponsesInterface) {
				m.EXPECT().
					DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(
						gomock.Any(), "test-org", "test-project", gomock.Any(),
					).
					Return(&openapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusNoContent},
					}, nil)
			},
			wantError: false,
		},
		{
			name: "idempotent (reference already gone, 204)",
			setup: func(m *openapiMock.MockClientWithResponsesInterface) {
				m.EXPECT().
					DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(
						gomock.Any(), "test-org", "test-project", gomock.Any(),
					).
					Return(&openapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusNoContent},
					}, nil)
			},
			wantError: false,
		},
		{
			name: "idempotent (project deleted, 404)",
			setup: func(m *openapiMock.MockClientWithResponsesInterface) {
				m.EXPECT().
					DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(
						gomock.Any(), "test-org", "test-project", gomock.Any(),
					).
					Return(&openapi.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceResponse{
						HTTPResponse: &http.Response{StatusCode: http.StatusNotFound},
					}, nil)
			},
			wantError: false,
		},
		{
			name: "server error propagates",
			setup: func(m *openapiMock.MockClientWithResponsesInterface) {
				m.EXPECT().
					DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(
						gomock.Any(), "test-org", "test-project", gomock.Any(),
					).
					Return(nil, errConnectionRefused)
			},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			m := openapiMock.NewMockClientWithResponsesInterface(ctrl)
			tc.setup(m)

			refs := newTestReferences(m)
			ctx := newReferencesTestContext(t)
			resource := newTestResource()

			err := refs.RemoveReferenceFromProject(ctx, resource)

			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
