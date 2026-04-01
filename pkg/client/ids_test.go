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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/principal"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testOrganizationID = "00000000-0000-0000-0000-000000000001"
	testProjectUUID    = "00000000-0000-0000-0000-000000000002"
)

func TestGetOrganizationAndProjectIDs(t *testing.T) {
	t.Parallel()

	resource := &metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				constants.OrganizationLabel: testOrganizationID,
				constants.ProjectLabel:      testProjectUUID,
			},
		},
	}

	organizationID, projectID, err := client.GetOrganizationAndProjectIDs(resource)
	require.NoError(t, err)
	require.Equal(t, ids.MustParseOrganizationID(testOrganizationID), organizationID)
	require.Equal(t, ids.MustParseProjectID(testProjectUUID), projectID)
}

func TestGetPrincipalOrganizationAndProjectIDs(t *testing.T) {
	t.Parallel()

	organizationID, projectID, err := client.GetPrincipalOrganizationAndProjectIDs(&principal.Principal{
		OrganizationID: ids.MustParseOrganizationID(testOrganizationID),
		ProjectID:      ids.MustParseProjectID(testProjectUUID),
	})
	require.NoError(t, err)
	require.Equal(t, ids.MustParseOrganizationID(testOrganizationID), organizationID)
	require.Equal(t, ids.MustParseProjectID(testProjectUUID), projectID)
}

func TestGetAllocationUUID(t *testing.T) {
	t.Parallel()

	allocationID := uuid.New()
	resource := &metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				constants.AllocationAnnotation: allocationID.String(),
			},
		},
	}

	got, err := client.GetAllocationUUID(resource)
	require.NoError(t, err)
	require.Equal(t, allocationID, got)
}
