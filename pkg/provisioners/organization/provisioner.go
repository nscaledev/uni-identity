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

package organization

import (
	"context"
	"errors"
	"fmt"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	"github.com/unikorn-cloud/core/pkg/provisioners/resource"
	"github.com/unikorn-cloud/core/pkg/provisioners/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	organization *unikornv1.Organization
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		organization: &unikornv1.Organization{},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.organization
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	if err := p.provisionOrganizationNamespace(ctx); err != nil {
		return err
	}

	auth0Organization, err := p.provisionAuth0Organization(ctx)
	if err != nil {
		return err
	}

	conditionAvailable, err := auth0Organization.StatusConditionRead(unikornv1core.ConditionAvailable)
	if err != nil {
		conditionAvailable = &unikornv1core.Condition{
			Type:    unikornv1core.ConditionAvailable,
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1core.ConditionReasonProvisioning,
			Message: "provisioning",
		}
	}

	if conditionAvailable.Status != corev1.ConditionTrue {
		reason := unikornv1core.ConditionReasonUnknown
		if conditionAvailable.Reason == unikornv1core.ConditionReasonErrored {
			reason = unikornv1core.ConditionReasonErrored
		}

		message := conditionAvailable.Message
		if message != "" {
			message = fmt.Sprintf("auth0 organization: %s", message)
		}

		p.organization.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionFalse, reason, message)

		return provisioners.ErrYield
	}

	// TODO: we may want to consider rolling up the conditions of subordinates,
	// but then again it may be overkill and cause undue stress!
	p.organization.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "Healthy")

	return nil
}

func (p *Provisioner) provisionOrganizationNamespace(ctx context.Context) error {
	labels, err := p.organization.ResourceLabels()
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
		// Create a new organization namespace.
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "organization-",
				Labels:       labels,
			},
		}

		if err := resource.New(namespace).Provision(ctx); err != nil {
			return err
		}
	}

	p.organization.Status.Namespace = namespace.Name

	return nil
}

func (p *Provisioner) provisionAuth0Organization(ctx context.Context) (*unikornv1.Auth0Organization, error) {
	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	objectKey := client.ObjectKey{
		Namespace: p.organization.Namespace,
		Name:      p.organization.Name,
	}

	var auth0Organization unikornv1.Auth0Organization
	if err = kubeClient.Get(ctx, objectKey, &auth0Organization); err == nil {
		return &auth0Organization, nil
	}

	if !kerrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get auth0 organization: %w", err)
	}

	auth0Organization = unikornv1.Auth0Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.organization.Name,
			Namespace: p.organization.Namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: p.organization.Name,
			},
		},
	}

	if err = controllerutil.SetControllerReference(p.organization, &auth0Organization, kubeClient.Scheme()); err != nil {
		return nil, fmt.Errorf("failed to set controller reference on auth0 organization: %w", err)
	}

	if err = kubeClient.Create(ctx, &auth0Organization); err != nil {
		return nil, fmt.Errorf("failed to create auth0 organization: %w", err)
	}

	return &auth0Organization, nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	if err := p.deprovisionAuth0Organization(ctx); err != nil {
		return err
	}

	if err := p.deprovisionOrganizationNamespace(ctx); err != nil {
		return err
	}

	return nil
}

func (p *Provisioner) deprovisionOrganizationNamespace(ctx context.Context) error {
	labels, err := p.organization.ResourceLabels()
	if err != nil {
		return err
	}

	// Get the organization's namespace.
	namespace, err := util.GetResourceNamespace(ctx, labels)
	if err != nil {
		// Already dead.
		if errors.Is(err, util.ErrNamespaceLookup) {
			return nil
		}

		return err
	}

	// Deprovision the namespace and await deletion.
	if err := resource.New(namespace).Deprovision(ctx); err != nil {
		return err
	}

	return nil
}

func (p *Provisioner) deprovisionAuth0Organization(ctx context.Context) error {
	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	objectKey := client.ObjectKey{
		Namespace: p.organization.Namespace,
		Name:      p.organization.Name,
	}

	var auth0Organization unikornv1.Auth0Organization
	if err = kubeClient.Get(ctx, objectKey, &auth0Organization); err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}

		return fmt.Errorf("failed to get auth0 organization: %w", err)
	}

	if auth0Organization.DeletionTimestamp != nil {
		return fmt.Errorf("auth0 organization is already being deleted: %w", provisioners.ErrYield)
	}

	if err = kubeClient.Delete(ctx, &auth0Organization); err != nil {
		return fmt.Errorf("failed to delete auth0 organization: %w", err)
	}

	return fmt.Errorf("auth0 organization is not yet deleted: %w", provisioners.ErrYield)
}
