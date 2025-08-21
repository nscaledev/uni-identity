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

package common_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/common/fixtures"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestMetadataCreate ensures identity and principal information is correcly
// applied to an unscoped object.
func TestMetadataCreate(t *testing.T) {
	t.Parallel()

	ctx := fixtures.HandlerContextFixture(t.Context(), 0)

	meta := &metav1.ObjectMeta{}

	require.NoError(t, common.SetIdentityMetadata(ctx, meta))

	require.Nil(t, meta.Labels)

	require.NotNil(t, meta.Annotations)
	require.Equal(t, fixtures.TokenActor, meta.Annotations[constants.CreatorAnnotation])
	require.Equal(t, fixtures.PrincipalActor, meta.Annotations[constants.CreatorPrincipalAnnotation])
}

// TestMetadataCreateWithOrganization ensures identity and principal information is correcly
// applied to an organization scoped object.
func TestMetadataCreateWithOrganization(t *testing.T) {
	t.Parallel()

	ctx := fixtures.HandlerContextFixture(t.Context(), fixtures.WithOrganization)

	meta := &metav1.ObjectMeta{}

	require.NoError(t, common.SetIdentityMetadata(ctx, meta))

	require.NotNil(t, meta.Labels)
	require.Equal(t, fixtures.PrincipalOrganizationID, meta.Labels[constants.OrganizationPrincipalLabel])
	require.NotContains(t, meta.Labels, constants.ProjectPrincipalLabel)

	require.NotNil(t, meta.Annotations)
	require.Equal(t, fixtures.TokenActor, meta.Annotations[constants.CreatorAnnotation])
	require.Equal(t, fixtures.PrincipalActor, meta.Annotations[constants.CreatorPrincipalAnnotation])
}

// TestMetadataCreateWithProject ensures identity and principal information is correcly
// applied to a project scoped object.
func TestMetadataCreateWithProject(t *testing.T) {
	t.Parallel()

	ctx := fixtures.HandlerContextFixture(t.Context(), fixtures.WithProject)

	meta := &metav1.ObjectMeta{}

	require.NoError(t, common.SetIdentityMetadata(ctx, meta))

	require.NotNil(t, meta.Labels)
	require.Equal(t, fixtures.PrincipalOrganizationID, meta.Labels[constants.OrganizationPrincipalLabel])
	require.Equal(t, fixtures.PrincipalProjectID, meta.Labels[constants.ProjectPrincipalLabel])

	require.NotNil(t, meta.Annotations)
	require.Equal(t, fixtures.TokenActor, meta.Annotations[constants.CreatorAnnotation])
	require.Equal(t, fixtures.PrincipalActor, meta.Annotations[constants.CreatorPrincipalAnnotation])
}
