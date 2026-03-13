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

package auth0user

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"sync"

	"github.com/auth0/go-auth0/v2/management"
	mgmtclient "github.com/auth0/go-auth0/v2/management/client"
	mgmtoption "github.com/auth0/go-auth0/v2/management/option"
	"github.com/google/uuid"
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
	auth0Domain         string
	auth0ClientID       string
	auth0ClientSecret   string
	auth0ConnectionName string

	auth0Client *mgmtclient.Management
	mutex       sync.Mutex
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.auth0Domain, "auth0-domain", "", "Auth0 tenant domain (e.g. your-tenant.us.auth0.com)")
	f.StringVar(&o.auth0ClientID, "auth0-client-id", "", "Auth0 application client ID with permissions to manage users")
	f.StringVar(&o.auth0ClientSecret, "auth0-client-secret", "", "Auth0 application client secret")
	f.StringVar(&o.auth0ConnectionName, "auth0-connection-name", "", "Auth0 connection name to store users credentials in (e.g. Username-Password-Authentication)")
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

	auth0User *unikornv1.Auth0User

	options *Options
}

// New returns a new initialized provisioner object.
func New(opts manager.ControllerOptions) provisioners.ManagerProvisioner {
	options, _ := opts.(*Options)

	return &Provisioner{
		auth0User: &unikornv1.Auth0User{},
		options:   options,
	}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return p.auth0User
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

	userID, ok := p.auth0User.Labels[coreconstants.UserLabel]
	if !ok || userID == "" {
		return unikornv1.NewMissingLabelError("auth0 user", p.auth0User.Name, coreconstants.UserLabel)
	}

	objectKey := client.ObjectKey{
		Namespace: p.auth0User.Namespace,
		Name:      userID,
	}

	var user unikornv1.User
	if err = kubeClient.Get(ctx, objectKey, &user); err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	email := user.Spec.Subject
	if _, err = mail.ParseAddress(email); err != nil {
		return fmt.Errorf("failed to parse user subject as email address: %w", err)
	}

	params := &management.CreateUserRequestContent{
		Email:         management.String(email),
		EmailVerified: management.Bool(true),
		AppMetadata: &management.AppMetadata{
			auth0.MetadataKeyManagedBy:             auth0.MetadataValueManagedByMigrationController,
			auth0.MetadataKeyUniAuth0UserNamespace: p.auth0User.Namespace,
			auth0.MetadataKeyUniAuth0UserName:      p.auth0User.Name,
			auth0.MetadataKeyUniAccountType:        auth0.MetadataKeyUniAccountTypeUser,
			auth0.MetadataKeyUniAccountID:          userID,
		},
		Connection: p.options.auth0ConnectionName,
		Password:   management.String(uuid.NewString()),
	}

	if _, err = auth0Client.Users.Create(ctx, params); err != nil {
		if auth0.IsStatusCodeError(err, http.StatusConflict) {
			return nil
		}

		return fmt.Errorf("failed to create auth0 user: %w", err)
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(ctx context.Context) error {
	auth0ResourceID := p.auth0User.Status.UserID
	if auth0ResourceID == "" {
		return fmt.Errorf("waiting for auth0 user.created webhook delivery: %w", provisioners.ErrYield)
	}

	auth0Client, err := p.options.getAuth0Client(ctx)
	if err != nil {
		return err
	}

	if err = auth0Client.Users.Delete(ctx, auth0ResourceID); err != nil {
		if auth0.IsStatusCodeError(err, http.StatusNotFound) {
			return nil
		}

		return fmt.Errorf("failed to delete auth0 user: %w", err)
	}

	return nil
}
