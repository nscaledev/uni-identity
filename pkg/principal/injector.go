/*
Copyright 2024-2025 the Unikorn Authors.
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

package principal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Injector is used by internal clients and propagates the pincipal from the
// context.
func Injector(cli client.Client, options *coreclient.HTTPClientOptions) func(context.Context, *http.Request) error {
	return func(ctx context.Context, r *http.Request) error {
		principal, err := FromContext(ctx)
		if err != nil {
			return err
		}

		data, err := json.Marshal(principal)
		if err != nil {
			return err
		}

		r.Header.Set(Header, base64.RawURLEncoding.EncodeToString(data))

		return nil
	}
}

// FromResource loads the identity principal stored in the resource.
func FromResource(resource metav1.Object) (*Principal, error) {
	// Check the consistency of the resource, we should always have some
	// labels and annotations.
	labels := resource.GetLabels()
	if labels == nil {
		return nil, fmt.Errorf("%w: labels missing from resource", errors.ErrConsistency)
	}

	annotations := resource.GetAnnotations()
	if annotations == nil {
		return nil, fmt.Errorf("%w: annotations missing from resource", errors.ErrConsistency)
	}

	// Select some defaults, this covers the case when the resource has been created
	// by the principal.
	// TODO: we should ALWAYS have a principal available, except when transitioning
	// from the old world to the new, and resources don't possess those labels.  We
	// can either let nature take its course, or write an upgrade script.
	organizationID := labels[constants.OrganizationLabel]
	projectID := labels[constants.ProjectLabel]
	actor := annotations[constants.CreatorAnnotation]

	// Override with princial information if set, this caters for when the resource
	// was created on behalf of the principal.
	if t, ok := labels[constants.OrganizationPrincipalLabel]; ok {
		organizationID = t
	}

	if t, ok := labels[constants.ProjectPrincipalLabel]; ok {
		projectID = t
	}

	if t, ok := annotations[constants.CreatorPrincipalAnnotation]; ok {
		actor = t
	}

	principal := &Principal{
		OrganizationID: organizationID,
		ProjectID:      projectID,
		Actor:          actor,
	}

	return principal, nil
}

// ControllerInjector takes a Kubernetes object e.g. a cluster of some variety, when we
// are provisioning resources in another service (as a system account, not the principal)
// on the principal's behalf.  It encodes the principal and passes it to the remote
// service so we can ultimately derive who it belongs to for perhaps billing, quota or
// support workflows.
func ControllerInjector(cli client.Client, options *coreclient.HTTPClientOptions, resource metav1.Object) func(context.Context, *http.Request) error {
	return func(ctx context.Context, r *http.Request) error {
		// Check the concistency of the resource, we should always have some
		// labels and annotations.
		labels := resource.GetLabels()
		if labels == nil {
			return fmt.Errorf("%w: labels missing from resource", errors.ErrConsistency)
		}

		annotations := resource.GetAnnotations()
		if annotations == nil {
			return fmt.Errorf("%w: annotations missing from resource", errors.ErrConsistency)
		}

		principal, err := FromResource(resource)
		if err != nil {
			return err
		}

		value, err := options.EncodeAndSign(ctx, cli, principal)
		if err != nil {
			return err
		}

		r.Header.Set(Header, value)

		return nil
	}
}
