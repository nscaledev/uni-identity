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

package api

import (
	"context"
	"errors"
	"fmt"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrNoOrganizationNamespace is returned when an organization exists but its
// controller has not yet recorded the provisioned namespace on the status.
var ErrNoOrganizationNamespace = errors.New("organization has no provisioned namespace")

// ErrOrganizationNotFound is returned when no Organization CR named by the given
// ID exists in any namespace the caller can see.
var ErrOrganizationNotFound = errors.New("organization not found in any namespace")

// ErrNoKubeconfig is returned when no kubeconfig is configured at all — an
// HTTP-API-only run with no cluster access. It is deliberately distinct from a
// present-but-broken kubeconfig, which is a real fault the caller must surface
// rather than skip over.
var ErrNoKubeconfig = errors.New("no kubeconfig available")

// NewKubernetesClient builds a controller-runtime client from KUBECONFIG for
// installing fixtures that have no HTTP API (e.g. Role CRs, or a Group CR
// referencing a role the caller cannot grant).  When no kubeconfig is
// configured at all it returns ErrNoKubeconfig, so cluster-only specs can skip
// on an HTTP-API-only run; a present-but-broken kubeconfig returns a real error.
func NewKubernetesClient() (client.Client, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		if clientcmd.IsEmptyConfig(err) {
			return nil, ErrNoKubeconfig
		}

		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := unikornv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("registering identity scheme: %w", err)
	}

	cli, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	return cli, nil
}

// OrganizationNamespaces finds the Organization CR named orgID across all
// namespaces — the integration kubeconfig is cluster-scoped — and returns the
// identity namespace the CR lives in (where Role CRs are created) and the
// namespace provisioned for the organization (where groups and other
// org-scoped resources live).  Discovering both from the organization ID keeps
// the suite from needing a separate IDENTITY_NAMESPACE input, since it already
// requires TEST_ORG_ID.
func OrganizationNamespaces(ctx context.Context, cli client.Client, orgID string) (string, string, error) {
	organizations := &unikornv1.OrganizationList{}
	if err := cli.List(ctx, organizations); err != nil {
		return "", "", fmt.Errorf("listing organizations: %w", err)
	}

	for i := range organizations.Items {
		org := &organizations.Items[i]
		if org.Name != orgID {
			continue
		}

		if org.Status.Namespace == "" {
			return "", "", fmt.Errorf("%w: %s", ErrNoOrganizationNamespace, orgID)
		}

		return org.Namespace, org.Status.Namespace, nil
	}

	return "", "", fmt.Errorf("%w: %s", ErrOrganizationNotFound, orgID)
}

// InstallFixture creates any custom resource and returns a cleanup function
// suitable for DeferCleanup: it returns an error, so a failed teardown fails
// the spec rather than silently leaking the fixture into later specs.  A
// fixture already deleted by the test itself is not an error.
func InstallFixture(ctx context.Context, cli client.Client, object client.Object) (func() error, error) {
	if err := cli.Create(ctx, object); err != nil {
		return nil, fmt.Errorf("creating fixture %s/%s: %w", object.GetNamespace(), object.GetName(), err)
	}

	cleanup := func() error {
		if err := cli.Delete(context.WithoutCancel(ctx), object); err != nil && !kerrors.IsNotFound(err) {
			return fmt.Errorf("deleting fixture %s/%s: %w", object.GetNamespace(), object.GetName(), err)
		}

		return nil
	}

	return cleanup, nil
}
