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

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func checkClientSecretFixture(t *testing.T, status string, secret *string) (*Authenticator, *unikornv1.OAuth2Client) {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	oauth2client := &unikornv1.OAuth2Client{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "identity",
			Name:      "test-client",
		},
		Status: unikornv1.OAuth2ClientStatus{
			Secret: status,
		},
	}

	var objects []client.Object

	if secret != nil {
		objects = append(objects, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: oauth2client.Namespace,
				Name:      oauth2client.CredentialsSecretName(),
			},
			Data: map[string][]byte{
				"secret": []byte(*secret),
			},
		})
	}

	authenticator := &Authenticator{
		client: fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build(),
	}

	return authenticator, oauth2client
}

func TestCheckClientSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    string
		secret    *string
		presented string
		ok        bool
	}{
		{name: "secret matches", status: "old", secret: ptr.To("new"), presented: "new", ok: true},
		{name: "secret wins over status", status: "old", secret: ptr.To("new"), presented: "old"},
		{name: "falls back to status before migration", status: "old", presented: "old", ok: true},
		{name: "wrong secret", status: "old", presented: "wrong"},
		{name: "empty secret is never valid", secret: ptr.To(""), presented: ""},
		{name: "empty status is never valid", presented: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authenticator, oauth2client := checkClientSecretFixture(t, test.status, test.secret)

			err := authenticator.checkClientSecret(t.Context(), oauth2client, test.presented)
			if test.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
