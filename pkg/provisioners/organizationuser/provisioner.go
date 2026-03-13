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

package organizationuser

import (
	"context"
	"fmt"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
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

	organizationUser *unikornv1.OrganizationUser
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		organizationUser: &unikornv1.OrganizationUser{},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.organizationUser
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	auth0OrganizationMember, err := p.provisionAuth0OrganizationMember(ctx)
	if err != nil {
		return err
	}

	conditionAvailable, err := auth0OrganizationMember.StatusConditionRead(unikornv1core.ConditionAvailable)
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
			message = fmt.Sprintf("auth0 organization member: %s", message)
		}

		p.organizationUser.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionFalse, reason, message)

		return provisioners.ErrYield
	}

	// TODO: we may want to consider rolling up the conditions of subordinates,
	// but then again it may be overkill and cause undue stress!
	p.organizationUser.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "Healthy")

	return nil
}

//nolint:cyclop
func (p *Provisioner) provisionAuth0OrganizationMember(ctx context.Context) (*unikornv1.Auth0OrganizationMember, error) {
	namespace, err := coreclient.NamespaceFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth0 resource namespace from context: %w", err)
	}

	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	var auth0OrganizationMember unikornv1.Auth0OrganizationMember
	if err = p.getKubernetesResource(ctx, p.organizationUser.Namespace, p.organizationUser.Name, &auth0OrganizationMember, kubeClient); err == nil {
		return &auth0OrganizationMember, nil
	}

	if !kerrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get auth0 organization member: %w", err)
	}

	organizationID, ok := p.organizationUser.Labels[coreconstants.OrganizationLabel]
	if !ok || organizationID == "" {
		return nil, unikornv1.NewMissingLabelError("organization user", p.organizationUser.Name, coreconstants.OrganizationLabel)
	}

	userID, ok := p.organizationUser.Labels[coreconstants.UserLabel]
	if !ok || userID == "" {
		return nil, unikornv1.NewMissingLabelError("organization user", p.organizationUser.Name, coreconstants.UserLabel)
	}

	var auth0Organization unikornv1.Auth0Organization
	if err = p.getKubernetesResource(ctx, namespace, organizationID, &auth0Organization, kubeClient); err != nil {
		return nil, fmt.Errorf("failed to get auth0 organization: %w", err)
	}

	var auth0User unikornv1.Auth0User
	if err = p.getKubernetesResource(ctx, namespace, userID, &auth0User, kubeClient); err != nil {
		return nil, fmt.Errorf("failed to get auth0 user: %w", err)
	}

	auth0OrganizationMember = unikornv1.Auth0OrganizationMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.organizationUser.Name,
			Namespace: p.organizationUser.Namespace,
			Labels: map[string]string{
				coreconstants.OrganizationLabel: organizationID,
				coreconstants.UserLabel:         userID,
			},
		},
	}

	if err = controllerutil.SetControllerReference(p.organizationUser, &auth0OrganizationMember, kubeClient.Scheme()); err != nil {
		return nil, fmt.Errorf("failed to set controller reference on auth0 organization member: %w", err)
	}

	// FIXME: Cross-namespace owner references are disallowed in Kubernetes.
	// Auth0Organization and Auth0User reside in the 'unikorn-identity' namespace,
	// while Auth0OrganizationMember lives in organization-specific namespaces.
	// Because Kubernetes only allows owner references within the same namespace,
	// these SetOwnerReference calls are commented out to avoid errors.
	// TODO: Track ownership using labels or annotations instead of owner references.
	// if err = controllerutil.SetOwnerReference(&auth0Organization, &auth0OrganizationMember, kubeClient.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
	// 	return nil, fmt.Errorf("failed to set auth0 organization as owner of auth0 organization member: %w", err)
	// }
	//
	// if err = controllerutil.SetOwnerReference(&auth0User, &auth0OrganizationMember, kubeClient.Scheme(), controllerutil.WithBlockOwnerDeletion(true)); err != nil {
	// 	return nil, fmt.Errorf("failed to set auth0 user as owner of auth0 organization member: %w", err)
	// }

	if err = kubeClient.Create(ctx, &auth0OrganizationMember); err != nil {
		return nil, fmt.Errorf("failed to create auth0 organization member: %w", err)
	}

	return &auth0OrganizationMember, nil
}

func (p *Provisioner) getKubernetesResource(ctx context.Context, namespace, name string, resource client.Object, kubeClient client.Client) error {
	objectKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	return kubeClient.Get(ctx, objectKey, resource)
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	objectKey := client.ObjectKey{
		Namespace: p.organizationUser.Namespace,
		Name:      p.organizationUser.Name,
	}

	var auth0OrganizationMember unikornv1.Auth0OrganizationMember
	if err = kubeClient.Get(ctx, objectKey, &auth0OrganizationMember); err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}

		return fmt.Errorf("failed to get auth0 organization member: %w", err)
	}

	if auth0OrganizationMember.DeletionTimestamp != nil {
		return fmt.Errorf("auth0 organization member is already being deleted: %w", provisioners.ErrYield)
	}

	if err = kubeClient.Delete(ctx, &auth0OrganizationMember); err != nil {
		return fmt.Errorf("failed to delete auth0 organization member: %w", err)
	}

	return fmt.Errorf("auth0 organization member is not yet deleted: %w", provisioners.ErrYield)
}
