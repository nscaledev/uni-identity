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

package client

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func parseResourceID(label, value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: invalid %s %q", errors.ErrConsistency, label, value)
	}

	return id, nil
}

func parseOrganizationID(value string) (ids.OrganizationID, error) {
	id, err := ids.ParseOrganizationID(value)
	if err != nil {
		return ids.OrganizationID{}, fmt.Errorf("%w: invalid organization ID %q", errors.ErrConsistency, value)
	}

	return id, nil
}

func parseProjectID(value string) (ids.ProjectID, error) {
	id, err := ids.ParseProjectID(value)
	if err != nil {
		return ids.ProjectID{}, fmt.Errorf("%w: invalid project ID %q", errors.ErrConsistency, value)
	}

	return id, nil
}

// getOrganizationAndProjectIDs extracts the organization and project IDs from a resource.
func getOrganizationAndProjectIDs(resource client.Object) (ids.OrganizationID, ids.ProjectID, error) {
	labels := resource.GetLabels()

	organizationID, ok := labels[constants.OrganizationLabel]
	if !ok {
		return ids.OrganizationID{}, ids.ProjectID{}, fmt.Errorf("%w: resource missing organization ID label", errors.ErrConsistency)
	}

	projectID, ok := labels[constants.ProjectLabel]
	if !ok {
		return ids.OrganizationID{}, ids.ProjectID{}, fmt.Errorf("%w: resource missing project ID label", errors.ErrConsistency)
	}

	organizationUUID, err := parseOrganizationID(organizationID)
	if err != nil {
		return ids.OrganizationID{}, ids.ProjectID{}, err
	}

	projectUUID, err := parseProjectID(projectID)
	if err != nil {
		return ids.OrganizationID{}, ids.ProjectID{}, err
	}

	return organizationUUID, projectUUID, nil
}

func getPrincipalOrganizationAndProjectIDs(userPrincipal *principal.Principal) (ids.OrganizationID, ids.ProjectID, error) {
	return userPrincipal.OrganizationID, userPrincipal.ProjectID, nil
}

func getAllocationUUID(resource client.Object) (uuid.UUID, error) {
	allocationID, err := getAllocationID(resource)
	if err != nil {
		return uuid.Nil, err
	}

	return parseResourceID("allocation ID", allocationID)
}
