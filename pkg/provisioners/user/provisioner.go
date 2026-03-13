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

package user

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

	user *unikornv1.User
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{
		user: &unikornv1.User{},
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.user
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	auth0User, err := p.provisionAuth0User(ctx)
	if err != nil {
		return err
	}

	conditionAvailable, err := auth0User.StatusConditionRead(unikornv1core.ConditionAvailable)
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
			message = fmt.Sprintf("auth0 user: %s", message)
		}

		p.user.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionFalse, reason, message)

		return provisioners.ErrYield
	}

	// TODO: we may want to consider rolling up the conditions of subordinates,
	// but then again it may be overkill and cause undue stress!
	p.user.StatusConditionWrite(unikornv1core.ConditionHealthy, corev1.ConditionTrue, unikornv1core.ConditionReasonHealthy, "Healthy")

	return nil
}

func (p *Provisioner) provisionAuth0User(ctx context.Context) (*unikornv1.Auth0User, error) {
	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	objectKey := client.ObjectKey{
		Namespace: p.user.Namespace,
		Name:      p.user.Name,
	}

	var auth0User unikornv1.Auth0User
	if err = kubeClient.Get(ctx, objectKey, &auth0User); err == nil {
		return &auth0User, nil
	}

	if !kerrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get auth0 user: %w", err)
	}

	auth0User = unikornv1.Auth0User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.user.Name,
			Namespace: p.user.Namespace,
			Labels: map[string]string{
				coreconstants.UserLabel: p.user.Name,
			},
		},
	}

	if err = controllerutil.SetControllerReference(p.user, &auth0User, kubeClient.Scheme()); err != nil {
		return nil, fmt.Errorf("failed to set controller reference on auth0 user: %w", err)
	}

	if err = kubeClient.Create(ctx, &auth0User); err != nil {
		return nil, fmt.Errorf("failed to create auth0 user: %w", err)
	}

	return &auth0User, nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	objectKey := client.ObjectKey{
		Namespace: p.user.Namespace,
		Name:      p.user.Name,
	}

	var auth0User unikornv1.Auth0User
	if err = kubeClient.Get(ctx, objectKey, &auth0User); err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}

		return fmt.Errorf("failed to get auth0 user: %w", err)
	}

	if auth0User.DeletionTimestamp != nil {
		return fmt.Errorf("auth0 user is already being deleted: %w", provisioners.ErrYield)
	}

	if err = kubeClient.Delete(ctx, &auth0User); err != nil {
		return fmt.Errorf("failed to delete auth0 user: %w", err)
	}

	return fmt.Errorf("auth0 user is not yet deleted: %w", provisioners.ErrYield)
}
