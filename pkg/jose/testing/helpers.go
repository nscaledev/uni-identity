/*
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

package testing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/jose"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	fakecoordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1/fake"
	clientgotesting "k8s.io/client-go/testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	Namespace     = "default"
	RefreshPeriod = time.Second
	KeySecretName = "tls-cert"
)

type FakeCoordinationClientGetter struct{}

func (*FakeCoordinationClientGetter) Client() (coordinationv1.CoordinationV1Interface, error) {
	coordination := &fakecoordinationv1.FakeCoordinationV1{
		Fake: &clientgotesting.Fake{},
	}

	return coordination, nil
}

func generateSerial(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	return serial
}

func RotateCertificate(t *testing.T, client client.Client) []byte {
	t.Helper()

	pkey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(pkey)
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "my-signing-key",
		},
		SerialNumber: generateSerial(t),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pkey.Public(), pkey)
	require.NoError(t, err)

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}

	key := pem.EncodeToMemory(keyBlock)

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	cert := pem.EncodeToMemory(certBlock)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: Namespace,
			Name:      KeySecretName,
		},
	}

	mutate := func() error {
		secret.Type = corev1.SecretTypeTLS
		secret.Data = map[string][]byte{
			corev1.TLSCertKey:       cert,
			corev1.TLSPrivateKeyKey: key,
		}

		return nil
	}

	_, err = controllerutil.CreateOrUpdate(t.Context(), client, secret, mutate)
	require.NoError(t, err)

	return key
}

func CheckSigningKeys(t *testing.T, cli client.Client, keys ...[]byte) {
	t.Helper()

	var signingKeys unikornv1.SigningKey

	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: Namespace, Name: jose.SigningKeyName}, &signingKeys))
	require.Len(t, signingKeys.Spec.PrivateKeys, len(keys))

	for i, privateKey := range signingKeys.Spec.PrivateKeys {
		require.Equal(t, privateKey.PEM, keys[i])
	}
}
