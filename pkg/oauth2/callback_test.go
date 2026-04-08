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

package oauth2 //nolint:testpackage

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errBoom = staticError("boom")

type staticError string

func (e staticError) Error() string {
	return string(e)
}

func getCallbackTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	return s
}

func newCallbackTestAuthenticator(t *testing.T, accountCreationEnabled bool, objects ...runtime.Object) *Authenticator {
	t.Helper()

	client := fake.NewClientBuilder().WithScheme(getCallbackTestScheme(t)).WithRuntimeObjects(objects...).Build()

	josetesting.RotateCertificate(t, client)

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	})

	ctx := t.Context()
	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))
	time.Sleep(2 * josetesting.RefreshPeriod)

	return New(&Options{
		AccessTokenDuration:      time.Second,
		RefreshTokenDuration:     30 * time.Second,
		TokenLeewayDuration:      time.Second,
		TokenCacheSize:           32,
		CodeCacheSize:            32,
		AccountCreationCacheSize: 32,
		AccountCreationEnabled:   accountCreationEnabled,
	}, josetesting.Namespace, common.IssuerValue{
		URL:      "https://identity.example.com",
		Hostname: "identity.example.com",
	}, client, issuer, userdb.NewUserDatabase(client, josetesting.Namespace), nil)
}

func TestHandleMissingUserStartsOnboardingForUnknownUser(t *testing.T) {
	t.Parallel()

	authenticator := newCallbackTestAuthenticator(t, true, &unikornv1.OAuth2Client{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      "test-client",
		},
		Spec: unikornv1.OAuth2ClientSpec{
			RedirectURI:   "https://console.example/callback",
			OnboardingURI: ptr.To("https://console.example/onboarding"),
		},
	})

	clientQuery := url.Values{}
	clientQuery.Set("client_id", "test-client")
	clientQuery.Set("redirect_uri", "https://console.example/callback")
	clientQuery.Set("state", "client-state")

	req := httptest.NewRequest(http.MethodGet, "https://identity.example.com/oauth2/v2/callback", nil)
	recorder := httptest.NewRecorder()
	redirector := newRedirector(recorder, req, clientQuery.Get("redirect_uri"), clientQuery.Get("state"))

	authenticator.handleMissingUser(recorder, req, redirector, clientQuery, &State{
		OAuth2Provider: "test-provider",
		ClientQuery:    clientQuery.Encode(),
	}, &oidc.IDToken{
		Email: oidc.Email{
			Email: "new.user@example.com",
		},
		Profile: oidc.Profile{
			Name:       "New User",
			GivenName:  "New",
			FamilyName: "User",
		},
	}, userdb.ErrResourceReference)

	response := recorder.Result()
	require.Equal(t, http.StatusFound, response.StatusCode)

	location, err := response.Location()
	require.NoError(t, err)
	assert.Equal(t, "https://console.example/onboarding", location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, "https://identity.example.com/oauth2/v2/onboard", location.Query().Get("callback"))
	assert.Equal(t, "new.user@example.com", location.Query().Get("email"))

	onboardingState := location.Query().Get("state")
	require.NotEmpty(t, onboardingState)

	_, ok := authenticator.accountCreationCache.Get(onboardingState)
	assert.True(t, ok)

	decoded := &OnboardingState{}
	require.NoError(t, authenticator.jwtIssuer.DecodeJWEToken(t.Context(), onboardingState, decoded, jose.TokenTypeOnboardState))
	assert.Equal(t, "test-provider", decoded.OAuth2Provider)
	assert.Equal(t, "new.user@example.com", decoded.IDToken.Email.Email)
}

func TestHandleMissingUserStopsOnLookupFailure(t *testing.T) {
	t.Parallel()

	authenticator := newCallbackTestAuthenticator(t, true)

	clientQuery := url.Values{}
	clientQuery.Set("client_id", "test-client")
	clientQuery.Set("redirect_uri", "https://console.example/callback")
	clientQuery.Set("state", "client-state")

	req := httptest.NewRequest(http.MethodGet, "https://identity.example.com/oauth2/v2/callback", nil)
	recorder := httptest.NewRecorder()
	redirector := newRedirector(recorder, req, clientQuery.Get("redirect_uri"), clientQuery.Get("state"))

	authenticator.handleMissingUser(recorder, req, redirector, clientQuery, &State{
		OAuth2Provider: "test-provider",
		ClientQuery:    clientQuery.Encode(),
	}, &oidc.IDToken{
		Email: oidc.Email{
			Email: "new.user@example.com",
		},
	}, errBoom)

	response := recorder.Result()
	require.Equal(t, http.StatusFound, response.StatusCode)

	location, err := response.Location()
	require.NoError(t, err)
	assert.Equal(t, "https://console.example/callback", location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, string(ErrorServerError), location.Query().Get("error"))
	assert.Equal(t, "user lookup failure", location.Query().Get("error_description"))
	assert.Equal(t, "client-state", location.Query().Get("state"))
}
