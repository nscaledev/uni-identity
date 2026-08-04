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
	"slices"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrNoOrganizationNamespace is returned when an organization exists but its
// controller has not yet recorded the provisioned namespace on the status.
var ErrNoOrganizationNamespace = errors.New("organization has no provisioned namespace")

// NewKubernetesClient builds a controller-runtime client from KUBECONFIG for
// installing fixtures that have no HTTP API (e.g. Role CRs, or a Group CR
// referencing a role the caller cannot grant).  Integration runs always have
// cluster access — the same kubeconfig drives hack/ci.
func NewKubernetesClient() (client.Client, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
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

// OrganizationNamespace resolves the namespace provisioned for an organization
// by reading its CR from the identity service namespace.  Organization scoped
// resources (groups, projects, service accounts) live there, so fixtures have
// to look it up rather than guess it.
func OrganizationNamespace(ctx context.Context, cli client.Client, identityNamespace, orgID string) (string, error) {
	org := &unikornv1.Organization{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: identityNamespace, Name: orgID}, org); err != nil {
		return "", fmt.Errorf("getting organization %s: %w", orgID, err)
	}

	if org.Status.Namespace == "" {
		return "", fmt.Errorf("%w: %s", ErrNoOrganizationNamespace, orgID)
	}

	return org.Status.Namespace, nil
}

// AddGroupMember writes a user onto a Group custom resource directly.  The API
// refuses to add a member to a group carrying a role the caller cannot grant,
// because joining the group would confer that role, so a spec that needs to
// start from "the member is already there" has to seed it out of band.
func AddGroupMember(ctx context.Context, cli client.Client, namespace, groupID, userID string) error {
	group := &unikornv1.Group{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: namespace, Name: groupID}, group); err != nil {
		return fmt.Errorf("getting group %s: %w", groupID, err)
	}

	if slices.Contains(group.Spec.UserIDs, userID) {
		return nil
	}

	group.Spec.UserIDs = append(group.Spec.UserIDs, userID)

	if err := cli.Update(ctx, group); err != nil {
		return fmt.Errorf("adding member %s to group %s: %w", userID, groupID, err)
	}

	return nil
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
