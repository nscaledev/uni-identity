/*
Copyright 2025 the Unikorn Authors.
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
	"context"
	"fmt"
	"net/http"
	"net/url"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// organizationAndProjectID recovers the typed organization and project IDs that own a
// resource. If the resource implements ids.ProjectScopeReader the typed accessor is used
// directly; otherwise it parses the standard organization and project labels.
//
// The label path is a backwards-compatibility ramp, not a fallback to nowhere: resources
// that have not yet adopted the ids.ProjectScopeReader accessors (and callers in repos that
// pre-date it) keep working unchanged, while resources that do implement it are read through
// the typed accessor. Both paths read the same labels, so they agree by construction.
func organizationAndProjectID(resource client.Object) (ids.OrganizationID, ids.ProjectID, error) {
	if r, ok := resource.(ids.ProjectScopeReader); ok {
		return r.OrganizationAndProjectID()
	}

	labels := resource.GetLabels()

	organizationID, ok := labels[constants.OrganizationLabel]
	if !ok {
		return ids.OrganizationID{}, ids.ProjectID{}, fmt.Errorf("%w: resource missing organization ID label", errors.ErrConsistency)
	}

	projectID, ok := labels[constants.ProjectLabel]
	if !ok {
		return ids.OrganizationID{}, ids.ProjectID{}, fmt.Errorf("%w: resource missing project ID label", errors.ErrConsistency)
	}

	orgID, err := ids.ParseOrganizationID(organizationID)
	if err != nil {
		return ids.OrganizationID{}, ids.ProjectID{}, fmt.Errorf("%w: invalid organization ID on resource", err)
	}

	projID, err := ids.ParseProjectID(projectID)
	if err != nil {
		return ids.OrganizationID{}, ids.ProjectID{}, fmt.Errorf("%w: invalid project ID on resource", err)
	}

	return orgID, projID, nil
}

// References allows references to be added and removed on identity
// resources from remote services.
type References struct {
	serviceDescriptor util.ServiceDescriptor
	serverOptions     *coreclient.HTTPOptions
	clientOptions     *coreclient.HTTPClientOptions
	clientFactory     func(ctx context.Context, c client.Client, resource client.Object) (openapi.ClientWithResponsesInterface, error)
}

func NewReferences(serviceDescriptor util.ServiceDescriptor, serverOptions *coreclient.HTTPOptions, clientOptions *coreclient.HTTPClientOptions) *References {
	r := &References{
		serviceDescriptor: serviceDescriptor,
		serverOptions:     serverOptions,
		clientOptions:     clientOptions,
	}

	r.clientFactory = func(ctx context.Context, c client.Client, resource client.Object) (openapi.ClientWithResponsesInterface, error) {
		return New(c, r.serverOptions, r.clientOptions).ControllerClient(ctx, resource)
	}

	return r
}

func (r *References) httpClient(ctx context.Context, c client.Client, resource client.Object) (openapi.ClientWithResponsesInterface, error) {
	return r.clientFactory(ctx, c, resource)
}

func (r *References) AddReferenceToProject(ctx context.Context, resource client.Object) error {
	client, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	httpClient, err := r.httpClient(ctx, client, resource)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(client, resource)
	if err != nil {
		return err
	}

	orgID, projID, err := organizationAndProjectID(resource)
	if err != nil {
		return err
	}

	response, err := httpClient.PutApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(ctx, orgID, projID, url.PathEscape(reference))
	if err != nil {
		return err
	}

	if response.StatusCode() != http.StatusCreated {
		return servererrors.PropagateError(response.HTTPResponse, response)
	}

	return nil
}

func (r *References) RemoveReferenceFromProject(ctx context.Context, resource client.Object) error {
	client, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	httpClient, err := r.httpClient(ctx, client, resource)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(client, resource)
	if err != nil {
		return err
	}

	orgID, projID, err := organizationAndProjectID(resource)
	if err != nil {
		return err
	}

	response, err := httpClient.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReferenceWithResponse(ctx, orgID, projID, url.PathEscape(reference))
	if err != nil {
		return err
	}

	switch response.StatusCode() {
	case http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return servererrors.PropagateError(response.HTTPResponse, response)
	}
}
