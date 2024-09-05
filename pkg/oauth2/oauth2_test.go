/*
Copyright 2024 the Unikorn Authors.

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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	// JWT claims have second accuracy, so use whole seconds as our time
	// basis.
	accessTokenDuration  = time.Second
	refreshTokenDuration = 30 * time.Second
)

func TestTokens(t *testing.T) {
	t.Parallel()

	client := fake.NewFakeClient()

	serial1 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial1)

	joseOptions := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, joseOptions)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	options := &oauth2.Options{
		AccessTokenDuration:  accessTokenDuration,
		RefreshTokenDuration: refreshTokenDuration,
		TokenLeewayDuration:  accessTokenDuration,
		TokenCacheSize:       1024,
	}

	authenticator := oauth2.New(options, josetesting.Namespace, client, issuer, nil)

	time.Sleep(2 * josetesting.RefreshPeriod)

	refreshToken := "bar"

	issueInfo := &oauth2.IssueInfo{
		Issuer:   "https://foo.com",
		Audience: "foo.com",
		Subject:  "barry@foo.com",
		Tokens: &oauth2.Tokens{
			AccessToken:  "foo",
			RefreshToken: &refreshToken,
			Expiry:       time.Now().Add(2 * accessTokenDuration),
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
