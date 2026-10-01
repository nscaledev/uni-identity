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

package oauth2client_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	mockmanager "github.com/unikorn-cloud/core/pkg/manager/mock"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/provisioners/oauth2client"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	namespace  = "identity"
	clientName = "test-client"
)

func newClient(status string) *unikornv1.OAuth2Client {
	return &unikornv1.OAuth2Client{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      clientName,
			UID:       "f00d",
		},
		Status: unikornv1.OAuth2ClientStatus{
			Secret: status,
		},
	}
}

func newSecret(value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      clientName + "-credentials",
		},
		Data: map[string][]byte{
			"id":     []byte(clientName),
			"secret": []byte(value),
		},
	}
}

// provision runs the provisioner against a fake cluster holding objects and
// returns the client and cluster after reconcile.
func provision(t *testing.T, in *unikornv1.OAuth2Client, objects ...client.Object) (*unikornv1.OAuth2Client, client.Client, error) {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()

	manager := mockmanager.NewMockManager(gomock.NewController(t))
	manager.EXPECT().GetAPIReader().Return(cli).AnyTimes()

	ctx := coremanager.NewContext(t.Context(), manager)
	ctx = coreclient.NewContext(ctx, cli)

	provisioner := oauth2client.New(nil)

	object, ok := provisioner.Object().(*unikornv1.OAuth2Client)
	require.True(t, ok)

	in.DeepCopyInto(object)

	err := provisioner.Provision(ctx)

	return object, cli, err
}

func getSecret(t *testing.T, cli client.Client) *corev1.Secret {
	t.Helper()

	secret := &corev1.Secret{}

	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: clientName + "-credentials"}, secret))

	return secret
}

func TestProvisionNewClient(t *testing.T) {
	t.Parallel()

	object, cli, err := provision(t, newClient(""))
	require.NoError(t, err)

	secret := getSecret(t, cli)
	require.Equal(t, clientName, string(secret.Data["id"]))
	require.NotEmpty(t, secret.Data["secret"])
	require.Equal(t, clientName, secret.Labels[oauth2client.OAuth2ClientLabel])
	require.Len(t, secret.OwnerReferences, 1)
	require.Equal(t, clientName, secret.OwnerReferences[0].Name)

	// Status mirrors the Secret so a rollback sees the same value.
	require.Equal(t, string(secret.Data["secret"]), object.Status.Secret)
}

func TestProvisionMigratesStatusSecret(t *testing.T) {
	t.Parallel()

	object, cli, err := provision(t, newClient("existing"))
	require.NoError(t, err)

	require.Equal(t, "existing", string(getSecret(t, cli).Data["secret"]))
	require.Equal(t, "existing", object.Status.Secret)
}

func TestProvisionLeavesExistingSecret(t *testing.T) {
	t.Parallel()

	object, cli, err := provision(t, newClient("stale"), newSecret("current"))
	require.NoError(t, err)

	require.Equal(t, "current", string(getSecret(t, cli).Data["secret"]))
	require.Equal(t, "current", object.Status.Secret)
}

func TestProvisionIsIdempotent(t *testing.T) {
	t.Parallel()

	first, cli, err := provision(t, newClient(""))
	require.NoError(t, err)

	second, _, err := provision(t, first, getSecret(t, cli))
	require.NoError(t, err)

	require.Equal(t, first.Status.Secret, second.Status.Secret)
}

func TestProvisionRejectsEmptySecret(t *testing.T) {
	t.Parallel()

	object, _, err := provision(t, newClient("existing"), newSecret(""))
	require.ErrorIs(t, err, oauth2client.ErrSecretMissing)

	// Status is left alone so older releases keep working.
	require.Equal(t, "existing", object.Status.Secret)
}
