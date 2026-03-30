/*
Copyright 2025 the Unikorn Authors.
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

package oauth2client

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// Provisioner encapsulates control plane provisioning.
type Provisioner struct {
	provisioners.Metadata

	// oauth2client is the Kubernetes oauth2client we're provisioning.
	oauth2client unikornv1.OAuth2Client
}

// New returns a new initialized provisioner object.
func New(_ manager.ControllerOptions) provisioners.ManagerProvisioner {
	return &Provisioner{}
}

// Ensure the ManagerProvisioner interface is implemented.
var _ provisioners.ManagerProvisioner = &Provisioner{}

func (p *Provisioner) Object() unikornv1core.ManagableResourceInterface {
	return &p.oauth2client
}

// Provision implements the Provision interface.
func (p *Provisioner) Provision(ctx context.Context) error {
	// TODO: things like Entra will expire secrets, we may want to consider
	// this in the long term for security.
	// TODO: We _could_ cryptographically sign this rather than it being a
	// PSK.
	if p.oauth2client.Status.Secret == "" {
		secret := make([]byte, 32)

		if _, err := rand.Read(secret); err != nil {
			return err
		}

		p.oauth2client.Status.Secret = base64.RawURLEncoding.EncodeToString(secret)
	}

	return nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(_ context.Context) error {
	return nil
}
