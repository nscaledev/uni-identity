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
	"errors"
	"fmt"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/provisioners"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// OAuth2ClientLabel is set on the credentials Secret, so tools like PushSecret
// can select them, its value is the OAuth2Client name.
const OAuth2ClientLabel = "unikorn-cloud.org/oauth2client"

var (
	ErrSecretMissing = errors.New("credentials secret has no secret key")
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
	cli, err := coreclient.FromContext(ctx)
	if err != nil {
		return err
	}

	key := client.ObjectKey{
		Namespace: p.oauth2client.Namespace,
		Name:      p.oauth2client.CredentialsSecretName(),
	}

	// Uncached read, a cached one would list and watch every Secret in the cluster.
	secret := &corev1.Secret{}

	if err := manager.FromContext(ctx).GetAPIReader().Get(ctx, key, secret); err != nil {
		if !kerrors.IsNotFound(err) {
			return err
		}

		if secret, err = p.createSecret(ctx, cli, key); err != nil {
			return err
		}
	}

	value := secret.Data["secret"]
	if len(value) == 0 {
		return fmt.Errorf("%w: %s", ErrSecretMissing, key)
	}

	// The Secret is the source of truth, status is a copy kept so a rollback
	// to a release that only reads status sees the same secret.
	p.oauth2client.Status.Secret = string(value)

	return nil
}

// createSecret creates the credentials Secret.  An existing status secret is
// copied as-is so clients migrating from status keep working.
func (p *Provisioner) createSecret(ctx context.Context, cli client.Client, key client.ObjectKey) (*corev1.Secret, error) {
	value := p.oauth2client.Status.Secret

	if value == "" {
		random := make([]byte, 32)

		if _, err := rand.Read(random); err != nil {
			return nil, err
		}

		value = base64.RawURLEncoding.EncodeToString(random)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: key.Namespace,
			Name:      key.Name,
			Labels: map[string]string{
				OAuth2ClientLabel: p.oauth2client.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"id":     []byte(p.oauth2client.Name),
			"secret": []byte(value),
		},
	}

	if err := controllerutil.SetOwnerReference(&p.oauth2client, secret, cli.Scheme()); err != nil {
		return nil, err
	}

	if err := cli.Create(ctx, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

// Deprovision implements the Provision interface.
func (p *Provisioner) Deprovision(_ context.Context) error {
	return nil
}
