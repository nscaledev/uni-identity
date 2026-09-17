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

package oauth2_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	bearerCasingAudience = "https://casing.example.com"
	bearerCasingFolded   = "bob@example.com"
	bearerCasingClaim    = "Bob@Example.com"
	bearerCasingOrgID    = "org-casing"
)

// bearerCasingObjects builds a folded User record with an organization
// membership, in the given state. The stored subject is the folded form that
// the ID-408 migration left behind.
func bearerCasingObjects(state unikornv1.UserState) []client.Object {
	return []client.Object{
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      bearerCasingOrgID,
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: josetesting.Namespace + "-" + bearerCasingOrgID,
			},
		},
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "casing-user",
			},
			Spec: unikornv1.UserSpec{
				Subject: bearerCasingFolded,
				State:   state,
			},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      bearerCasingOrgID + "-user",
				Labels: map[string]string{
					constants.UserLabel:         "casing-user",
					constants.OrganizationLabel: bearerCasingOrgID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{
				State: unikornv1.UserStateActive,
			},
		},
	}
}

func bearerCasingEnv(t *testing.T, issuer *auth0TestIssuer, state unikornv1.UserState) *passportTestEnv {
	t.Helper()

	objects := append([]client.Object{
		&unikornv1.OAuth2Provider{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "casing-provider",
			},
			Spec: unikornv1.OAuth2ProviderSpec{
				Issuer: issuer.issuer(),
				BearerTrust: &unikornv1.BearerTrustSpec{
					Audience: bearerCasingAudience,
					// Deliberately false: a subject the lookup cannot find is
					// rejected rather than admitted with no memberships. That
					// is what makes the assertions below meaningful.
					AllowExternalIdentity: false,
				},
			},
		},
	}, bearerCasingObjects(state)...)

	return setupPassportTestEnvWithOAuth2Options(t, &rbac.Options{}, &oauth2.Options{
		AccessTokenDuration:     accessTokenDuration,
		RefreshTokenDuration:    refreshTokenDuration,
		TokenLeewayDuration:     accessTokenDuration,
		TokenVerificationLeeway: 0,
		TokenCacheSize:          1024,
		CodeCacheSize:           1024,
	}, objects...)
}

// TestBearerMixedCaseClaimResolvesFoldedRecord pins the property the ID-408
// migration was for. The stored subject is folded and the bearer claim carries
// the pre-migration case. The trusted-issuer path folds the claim before it
// resolves the user, so the record is found and its organization membership is
// returned. Before storage and the claim agreed, this holder was admitted as
// never onboarded with no memberships.
func TestBearerMixedCaseClaimResolvesFoldedRecord(t *testing.T) {
	t.Parallel()

	issuer := newAuth0TestIssuer(t)
	env := bearerCasingEnv(t, issuer, unikornv1.UserStateActive)

	token := issuer.token(t, bearerCasingAudience, bearerCasingClaim, time.Now().Add(45*time.Second))

	result, err := env.authenticator.TokenExchange(nil, exchangeRequest(t, token, nil))
	require.NoError(t, err, "a mixed-case claim must resolve the folded record")
	require.NotNil(t, result)

	claims := parsePassport(t, env, result.AccessToken)

	assert.Equal(t, bearerCasingFolded, claims.Subject,
		"the passport subject must be the folded form, not the claim's case")
	assert.Contains(t, claims.OrgIDs, bearerCasingOrgID,
		"membership must resolve, proving the record was found rather than treated as never onboarded")
}

// TestBearerDeactivationReachesFormerlyMixedCaseUser is ID-408 acceptance
// criterion 4. Deactivation can only fire on a record the lookup finds, so
// before storage and the claim agreed on case, a suspended holder with a
// mixed-case record kept bearer access.
//
// Both arms run with one token and one set of fixtures, differing only in
// User.spec.state. That difference is the whole point: a refusal on its own
// proves nothing here, because a record the lookup cannot find is refused with
// the same "user identity not found or inactive" message by design. The active
// arm is the control. If the claim fold were removed, the active arm fails, so
// this test cannot pass for the wrong reason.
func TestBearerDeactivationReachesFormerlyMixedCaseUser(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		state   unikornv1.UserState
		allowed bool
	}{
		{name: "active is admitted", state: unikornv1.UserStateActive, allowed: true},
		{name: "suspended is refused", state: unikornv1.UserStateSuspended, allowed: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			issuer := newAuth0TestIssuer(t)
			env := bearerCasingEnv(t, issuer, tt.state)

			token := issuer.token(t, bearerCasingAudience, bearerCasingClaim, time.Now().Add(45*time.Second))

			result, err := env.authenticator.TokenExchange(nil, exchangeRequest(t, token, nil))

			if !tt.allowed {
				require.Error(t, err,
					"a suspended user must be refused even when the claim carries the pre-migration case")

				return
			}

			require.NoError(t, err,
				"the control arm: an active user with a mixed-case claim must resolve the folded record")
			require.NotNil(t, result)

			claims := parsePassport(t, env, result.AccessToken)
			assert.Contains(t, claims.OrgIDs, bearerCasingOrgID,
				"membership must resolve, proving the refusal above came from the state and not a failed lookup")
		})
	}
}
