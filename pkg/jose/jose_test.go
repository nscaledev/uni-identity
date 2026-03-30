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

package jose_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type TestClaims struct {
	Foo string `json:"foo"`
}

func getScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	return s
}

// TestRotation tests the behaviour of the low level certificate rotation code, ensuring
// our shadown keys are kept in sync with what's provided by cert-manager.
func TestRotation(t *testing.T) {
	t.Parallel()

	client := fake.NewClientBuilder().WithScheme(getScheme(t)).Build()

	key1 := josetesting.RotateCertificate(t, client)

	options := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, options)

	ctx := t.Context()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	// After at least one tick, expect the primary copy to exist, and the secondary not to.
	time.Sleep(josetesting.RefreshPeriod * 2)
	josetesting.CheckSigningKeys(t, client, key1)

	// After ar at least another tick, expect the state to be the same.
	time.Sleep(josetesting.RefreshPeriod)
	josetesting.CheckSigningKeys(t, client, key1)

	// Rotate the certificate, and after at least one tick the primary should be updated
	// and the old primary copied to the secondary.
	key2 := josetesting.RotateCertificate(t, client)

	time.Sleep(josetesting.RefreshPeriod * 2)
	josetesting.CheckSigningKeys(t, client, key2, key1)

	// After ar at least another tick, expect the state to be the same.
	time.Sleep(josetesting.RefreshPeriod)
	josetesting.CheckSigningKeys(t, client, key2, key1)

	// And one more time...
	key3 := josetesting.RotateCertificate(t, client)

	time.Sleep(josetesting.RefreshPeriod * 2)
	josetesting.CheckSigningKeys(t, client, key3, key2)
}

// TestJWTIssue tests that issued JWTs validate across key rotation, and cease working
// when a key is rotated out.
func TestJWTIssue(t *testing.T) {
	t.Parallel()

	client := fake.NewClientBuilder().WithScheme(getScheme(t)).Build()

	josetesting.RotateCertificate(t, client)

	options := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, options)

	ctx := t.Context()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	// Wait for the primary key to be rotated in.
	time.Sleep(josetesting.RefreshPeriod * 2)

	claims := &TestClaims{
		Foo: "bar",
	}

	// Check the token can be issued, and validates.
	token1, err := issuer.EncodeJWT(ctx, claims)
	require.NoError(t, err)

	var decodedClaims TestClaims

	require.NoError(t, issuer.DecodeJWT(ctx, token1, &decodedClaims))

	// Rotate the key, check the existing token and a new on validate.
	josetesting.RotateCertificate(t, client)

	time.Sleep(josetesting.RefreshPeriod * 2)

	token2, err := issuer.EncodeJWT(ctx, claims)
	require.NoError(t, err)

	require.NoError(t, issuer.DecodeJWT(ctx, token1, &decodedClaims))
	require.NoError(t, issuer.DecodeJWT(ctx, token2, &decodedClaims))

	// Do it again, the first token shouldn't work any more, but the second one should.
	josetesting.RotateCertificate(t, client)

	time.Sleep(josetesting.RefreshPeriod * 2)

	require.Error(t, issuer.DecodeJWT(ctx, token1, &decodedClaims))
	require.NoError(t, issuer.DecodeJWT(ctx, token2, &decodedClaims))
}

// TestJWEIssue tests that issued encrypted JWTs validate across key rotation, and cease working
// when a key is rotated out.
func TestJWEIssue(t *testing.T) {
	t.Parallel()

	client := fake.NewClientBuilder().WithScheme(getScheme(t)).Build()

	josetesting.RotateCertificate(t, client)

	options := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, options)

	ctx := t.Context()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	// Wait for the primary key to be rotated in.
	time.Sleep(josetesting.RefreshPeriod * 2)

	claims := &TestClaims{
		Foo: "bar",
	}

	// Check the token can be issued, and validates.
	token1, err := issuer.EncodeJWEToken(ctx, claims, jose.TokenTypeAccessToken)
	require.NoError(t, err)

	var decodedClaims TestClaims

	require.NoError(t, issuer.DecodeJWEToken(ctx, token1, &decodedClaims, jose.TokenTypeAccessToken))

	// Rotate the key, check the existing token and a new on validate.
	josetesting.RotateCertificate(t, client)

	time.Sleep(josetesting.RefreshPeriod * 2)

	token2, err := issuer.EncodeJWEToken(ctx, claims, jose.TokenTypeAccessToken)
	require.NoError(t, err)

	require.NoError(t, issuer.DecodeJWEToken(ctx, token1, &decodedClaims, jose.TokenTypeAccessToken))
	require.NoError(t, issuer.DecodeJWEToken(ctx, token2, &decodedClaims, jose.TokenTypeAccessToken))

	// Do it again, the first token shouldn't work any more, but the second one should.
	josetesting.RotateCertificate(t, client)

	time.Sleep(josetesting.RefreshPeriod * 2)

	require.Error(t, issuer.DecodeJWEToken(ctx, token1, &decodedClaims, jose.TokenTypeAccessToken))
	require.NoError(t, issuer.DecodeJWEToken(ctx, token2, &decodedClaims, jose.TokenTypeAccessToken))
}
