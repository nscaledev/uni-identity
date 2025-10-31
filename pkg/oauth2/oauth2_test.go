/*
Copyright 2024-2025 the Unikorn Authors.

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

package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	// JWT claims have second accuracy, so use whole seconds as our time
	// basis.
	accessTokenDuration  = time.Second
	refreshTokenDuration = 30 * time.Second
)

func getScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	return s
}

func TestTokens(t *testing.T) {
	t.Parallel()

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      "fake",
		},
		Spec: unikornv1.UserSpec{
			Subject: "barry@foo.com",
			State:   unikornv1.UserStateActive,
		},
	}

	client := fake.NewClientBuilder().WithScheme(getScheme(t)).WithObjects(user).Build()

	josetesting.RotateCertificate(t, client)

	joseOptions := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, joseOptions)

	ctx := t.Context()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	rbac := rbac.New(client, josetesting.Namespace, &rbac.Options{})

	options := &oauth2.Options{
		AccessTokenDuration:      accessTokenDuration,
		RefreshTokenDuration:     refreshTokenDuration,
		TokenLeewayDuration:      accessTokenDuration,
		TokenCacheSize:           1024,
		CodeCacheSize:            1024,
		AccountCreationCacheSize: 1024,
	}

	issuerVal := handlercommon.IssuerValue{
		URL:      "https://foo.com",
		Hostname: "foo.com",
	}

	authenticator := oauth2.New(options, josetesting.Namespace, issuerVal, client, issuer, rbac)

	time.Sleep(2 * josetesting.RefreshPeriod)

	issueInfo := &oauth2.IssueInfo{
		Issuer:   "https://foo.com",
		Audience: "foo.com",
		Subject:  "barry@foo.com",
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			UserID: "fake",
		},
	}

	tokens, err := authenticator.Issue(ctx, issueInfo)
	require.NoError(t, err)

	verifyInfo := &oauth2.VerifyInfo{
		Issuer:   "https://foo.com",
		Audience: "foo.com",
		Token:    tokens.AccessToken,
	}

	_, err = authenticator.Verify(ctx, verifyInfo)
	require.NoError(t, err)

	// Wait for expiry and verify it doesn't work.
	time.Sleep(2 * accessTokenDuration)

	_, err = authenticator.Verify(ctx, verifyInfo)
	require.Error(t, err)
}
