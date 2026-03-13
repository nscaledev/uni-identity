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

package auth0organizationmember

import (
	"context"
	"fmt"
	"sync"

	"github.com/auth0/go-auth0/v2/management"
	mgmtclient "github.com/auth0/go-auth0/v2/management/client"
	mgmtoption "github.com/auth0/go-auth0/v2/management/option"
	"github.com/spf13/pflag"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Options struct {
	auth0Domain       string
	auth0ClientID     string
	auth0ClientSecret string

	auth0Client *mgmtclient.Management
	mutex       sync.Mutex
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.auth0Domain, "auth0-domain", "", "Auth0 tenant domain (e.g. your-tenant.us.auth0.com)")
	f.StringVar(&o.auth0ClientID, "auth0-client-id", "", "Auth0 application client ID with permissions to manage organization members")
	f.StringVar(&o.auth0ClientSecret, "auth0-client-secret", "", "Auth0 application client secret")
}

func (o *Options) getAuth0Client(ctx context.Context) (*mgmtclient.Management, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.auth0Client != nil {
		return o.auth0Client, nil
	}

	auth0ClientCredentials := mgmtoption.WithClientCredentials(ctx, o.auth0ClientID, o.auth0ClientSecret)

	auth0Client, err := mgmtclient.New(o.auth0Domain, auth0ClientCredentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth0 management client: %w", err)
	}

	o.auth0Client = auth0Client

	return auth0Client, nil
}

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	auth0OrganizationMember *unikornv1.Auth0OrganizationMember

	options *Options
}

// New returns a new initialized provisioner object.
func New(opts manager.ControllerOptions) provisioners.ManagerProvisioner {
	options, _ := opts.(*Options)

	return &Provisioner{
		auth0OrganizationMember: &unikornv1.Auth0OrganizationMember{},
		options:                 options,
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.auth0OrganizationMember
}

// Provision implements the Provision interface
//
//nolint:cyclop
func (p *Provisioner) Provision(ctx context.Context) error {
	namespace, err := coreclient.NamespaceFromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth0 resource namespace from context: %w", err)
	}

	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	auth0Client, err := p.options.getAuth0Client(ctx)
	if err != nil {
		return err
	}

	organizationID, ok := p.auth0OrganizationMember.Labels[coreconstants.OrganizationLabel]
	if !ok || organizationID == "" {
		return unikornv1.NewMissingLabelError("auth0 organization member", p.auth0OrganizationMember.Name, coreconstants.OrganizationLabel)
	}

	userID, ok := p.auth0OrganizationMember.Labels[coreconstants.UserLabel]
	if !ok || userID == "" {
		return unikornv1.NewMissingLabelError("auth0 organization member", p.auth0OrganizationMember.Name, coreconstants.UserLabel)
	}

	var auth0Organization unikornv1.Auth0Organization
	if err = p.getKubernetesResource(ctx, namespace, organizationID, &auth0Organization, kubeClient); err != nil {
		return fmt.Errorf("failed to get auth0 organization: %w", err)
	}

	if auth0Organization.Status.OrganizationID == "" {
		return fmt.Errorf("auth0 organization is not yet ready: %w", provisioners.ErrYield)
	}

	var auth0User unikornv1.Auth0User
	if err = p.getKubernetesResource(ctx, namespace, userID, &auth0User, kubeClient); err != nil {
		return fmt.Errorf("failed to get auth0 user: %w", err)
	}

	if auth0User.Status.UserID == "" {
		return fmt.Errorf("auth0 user is not yet ready: %w", provisioners.ErrYield)
	}

	params := &management.CreateOrganizationMemberRequestContent{
		Members: []string{
			auth0User.Status.UserID,
		},
	}

	if err = auth0Client.Organizations.Members.Create(ctx, auth0Organization.Status.OrganizationID, params); err != nil {
		return fmt.Errorf("failed to add member to auth0 organization: %w", err)
	}

	return nil
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
	var (
		auth0OrganizationResourceID = p.auth0OrganizationMember.Status.OrganizationID
		auth0UserResourceID         = p.auth0OrganizationMember.Status.UserID
	)

	if auth0OrganizationResourceID == "" || auth0UserResourceID == "" {
		return fmt.Errorf("waiting for auth0 organization.member.added webhook delivery: %w", provisioners.ErrYield)
	}

	auth0Client, err := p.options.getAuth0Client(ctx)
	if err != nil {
		return err
	}

	params := &management.DeleteOrganizationMembersRequestContent{
		Members: []string{
			auth0UserResourceID,
		},
	}

	if err = auth0Client.Organizations.Members.Delete(ctx, auth0OrganizationResourceID, params); err != nil {
		return fmt.Errorf("failed to remove member from auth0 organization: %w", err)
	}

	return nil
}
