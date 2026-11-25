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

//nolint:testpackage // The test exercises the unexported namespace lookup directly.
package provisioners

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	mockmanager "github.com/unikorn-cloud/core/pkg/manager/mock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetResourceNamespaceUsesAPIReader(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	selector := labels.Set{"unikorn-cloud.org/organization": "organization"}
	apiReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "organization",
			Labels: selector,
		},
	}).Build()
	cachedClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	controller := gomock.NewController(t)
	manager := mockmanager.NewMockManager(controller)
	manager.EXPECT().GetAPIReader().Return(apiReader)

	ctx := coremanager.NewContext(t.Context(), manager)
	ctx = coreclient.NewContext(ctx, cachedClient)

	namespace, err := GetResourceNamespace(ctx, selector)
	require.NoError(t, err)
	require.Equal(t, "organization", namespace.Name)
}
