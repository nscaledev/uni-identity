/*
Copyright 2022-2024 EscherCloud.
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

package project

import (
	"context"
	"errors"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/core/pkg/provisioners/resource"
	"github.com/unikorn-cloud/core/pkg/provisioners/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrLabelMissing = errors.New("expected label missing")
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// project is the Kubernetes project we're provisioning.
	project unikornv1.Project
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return &p.project
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	labels, err := p.project.ResourceLabels()
	if err != nil {
		return err
	}

	// Namespace exists, leave it alone.
	namespace, err := util.GetResourceNamespace(ctx, labels)
	if err != nil {
		// Some other error, propagate it back up the stack.
		if !errors.Is(err, util.ErrNamespaceLookup) {
			return err
		}
	}

	if namespace == nil {
		// Create a new project namespace.
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "project-",
				Labels:       labels,
			},
		}

		if err := resource.New(namespace).Provision(ctx); err != nil {
			return err
		}
	}

	p.project.Status.Namespace = namespace.Name

	// TODO: we may want to consider rolling up the conditions of subordinates,
	// but then again it may be overkill and cause undue stress!
	p.project.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "Healthy")

	return nil
}

// deprovisionDescendants selectively deletes project namespace resources
// so they have a chance to clean up correctly.
//
//nolint:cyclop
func (p *Provisioner) deprovisionDescendants(ctx context.Context, namespace *corev1.Namespace) error {
	log := log.FromContext(ctx)

	// TODO: this needs to be configurable, which we have no precedent for
	// and also it needs to be mirrored in the clusterrole in Helm.
	gvs := []schema.GroupVersion{
		{
			Group:   "unikorn-cloud.org",
			Version: "v1alpha1",
		},
	}

	manager := manager.FromContext(ctx)

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(manager.GetConfig())
	if err != nil {
		return err
	}

	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	// If we found any resources, we need to await deletion.
	yield := false

	for _, gv := range gvs {
		apiResources, err := discoveryClient.ServerResourcesForGroupVersion(gv.String())
		if err != nil {
			return err
		}

		// Remove any global resource types, we only care about ones in the namespace.
		// and remove any resources that cannot be deleted (this gets rid of any
		// resource/subresource type entries.
		apiResources.APIResources = slices.DeleteFunc(apiResources.APIResources, func(resource metav1.APIResource) bool {
			return !resource.Namespaced || !slices.Contains(resource.Verbs, "delete")
		})

		for _, apiResource := range apiResources.APIResources {
			// NOTE: GV not populated by the discovery call.
			gvk := schema.GroupVersionKind{
				Group:   gv.Group,
				Version: gv.Version,
				Kind:    apiResource.Kind + "List",
			}

			log.V(1).Info("discovered resource for deletion", "gvk", gvk)

			resources := &unstructured.UnstructuredList{}
			resources.SetGroupVersionKind(gvk)

			if err := cli.List(ctx, resources, &client.ListOptions{Namespace: namespace.Name}); err != nil {
				return err
			}

			if len(resources.Items) == 0 {
				continue
			}

			yield = true

			for i := range resources.Items {
				resource := &resources.Items[i]

				if resource.GetDeletionTimestamp() != nil {
					log.Info("awaiting project resource deletion", "gvk", resource.GroupVersionKind(), "name", resource.GetName())
					continue
				}

				log.Info("deleting project resource", "gvk", resource.GroupVersionKind(), "name", resource.GetName())

				if err := cli.Delete(ctx, resource); err != nil {
					return err
				}
			}
		}
	}

	if yield {
		return provisioners.ErrYield
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	labels, err := p.project.ResourceLabels()
	if err != nil {
		return err
	}

	// Get the project's namespace.
	namespace, err := util.GetResourceNamespace(ctx, labels)
	if err != nil {
		// Already dead.
		if errors.Is(err, util.ErrNamespaceLookup) {
			return nil
		}

		return err
	}

	if err := p.deprovisionDescendants(ctx, namespace); err != nil {
		return err
	}

	// Deprovision the namespace and await deletion.
	if err := resource.New(namespace).Deprovision(ctx); err != nil {
		return err
	}

	return nil
}
