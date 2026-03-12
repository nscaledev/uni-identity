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

package auth0organization

import (
	"context"
	"fmt"
	"net/http"
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
	"github.com/unikorn-cloud/identity/pkg/auth0"

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
	f.StringVar(&o.auth0ClientID, "auth0-client-id", "", "Auth0 application client ID with permissions to manage organizations")
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

	auth0Organization *unikornv1.Auth0Organization

	options *Options
}

// New returns a new initialized provisioner object.
func New(opts manager.ControllerOptions) provisioners.ManagerProvisioner {
	options, _ := opts.(*Options)

	return &Provisioner{
		auth0Organization: &unikornv1.Auth0Organization{},
		options:           options,
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.auth0Organization
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	kubeClient, err := coreclient.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get kubernetes client from context: %w", err)
	}

	auth0Client, err := p.options.getAuth0Client(ctx)
	if err != nil {
		return err
	}

	organizationID, ok := p.auth0Organization.Labels[coreconstants.OrganizationLabel]
	if !ok || organizationID == "" {
		return unikornv1.NewMissingLabelError("auth0 organization", p.auth0Organization.Name, coreconstants.OrganizationLabel)
	}

	objectKey := client.ObjectKey{
		Namespace: p.auth0Organization.Namespace,
		Name:      organizationID,
	}

	var organization unikornv1.Organization
	if err = kubeClient.Get(ctx, objectKey, &organization); err != nil {
		return fmt.Errorf("failed to get organization: %w", err)
	}

	displayName, ok := organization.Labels[coreconstants.NameLabel]
	if !ok || displayName == "" {
		return unikornv1.NewMissingLabelError("organization", organizationID, coreconstants.NameLabel)
	}

	params := &management.CreateOrganizationRequestContent{
		Name:        organizationID,
		DisplayName: management.String(displayName),
		Metadata: &management.OrganizationMetadata{
			auth0.MetadataKeyManagedBy:                     management.String(auth0.MetadataValueManagedByMigrationController),
			auth0.MetadataKeyUniAuth0OrganizationNamespace: management.String(p.auth0Organization.Namespace),
			auth0.MetadataKeyUniAuth0OrganizationName:      management.String(p.auth0Organization.Name),
			auth0.MetadataKeyUniOrganizationID:             management.String(organizationID),
		},
	}

	if _, err = auth0Client.Organizations.Create(ctx, params); err != nil {
		if auth0.IsStatusCodeError(err, http.StatusConflict) {
			return nil
		}

		return fmt.Errorf("failed to create auth0 organization: %w", err)
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	auth0ResourceID := p.auth0Organization.Status.OrganizationID
	if auth0ResourceID == "" {
		return fmt.Errorf("waiting for auth0 organization.created webhook delivery: %w", provisioners.ErrYield)
	}

	auth0Client, err := p.options.getAuth0Client(ctx)
	if err != nil {
		return err
	}

	if err = auth0Client.Organizations.Delete(ctx, auth0ResourceID); err != nil {
		if auth0.IsStatusCodeError(err, http.StatusNotFound) {
			return nil
		}

		return fmt.Errorf("failed to delete auth0 organization: %w", err)
	}

	return nil
}
