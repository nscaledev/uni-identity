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
	casingAudience = "https://casing.example.com"
	casingClaim    = "Bob@Example.com"
	casingOrgID    = "org-casing"
)

// casingObjects builds a User record, stored in the given form and state, with
// one organization membership.
func casingObjects(stored string, state unikornv1.UserState) []client.Object {
	return []client.Object{
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      casingOrgID,
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: josetesting.Namespace + "-" + casingOrgID,
			},
		},
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      "casing-user",
			},
			Spec: unikornv1.UserSpec{
				Subject: stored,
				State:   state,
			},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      casingOrgID + "-user",
				Labels: map[string]string{
					constants.UserLabel:         "casing-user",
					constants.OrganizationLabel: casingOrgID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{
				State: unikornv1.UserStateActive,
			},
		},
	}
}

// casingUser builds a User record with no organization membership.
func casingUser(name, subject string, state unikornv1.UserState) *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      name,
		},
		Spec: unikornv1.UserSpec{
			Subject: subject,
			State:   state,
		},
	}
}

// casingEnv trusts issuer with allowExternalIdentity set.  That setting admits a
// subject with no record, so it is where an ignored record shows.
func casingEnv(t *testing.T, issuer *auth0TestIssuer, records ...client.Object) *passportTestEnv {
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
					Audience:              casingAudience,
					AllowExternalIdentity: true,
				},
			},
		},
	}, records...)

	return setupPassportTestEnvWithOAuth2Options(t, &rbac.Options{}, &oauth2.Options{
		AccessTokenDuration:     accessTokenDuration,
		RefreshTokenDuration:    refreshTokenDuration,
		TokenLeewayDuration:     accessTokenDuration,
		TokenVerificationLeeway: 0,
		TokenCacheSize:          1024,
		CodeCacheSize:           1024,
	}, objects...)
}

// TestBearerDeactivationReachesAMixedCaseRecord is ID-408 acceptance criterion 4,
// and the reason the ticket exists. The trusted-issuer path folds the email claim
// before it resolves a user. A record stored in another case was invisible to it,
// so a suspended holder kept bearer access: deactivation can only fire on a record
// the lookup finds.
//
// Both stored forms are exercised, because the lookup must find the record
// before the data is migrated as well as after it. That is what lets the migration
// run with no login or authorization affected.
//
// The provider sets allowExternalIdentity, because only then does the defect
// show: a record the lookup cannot find is admitted with no memberships, so a
// suspended holder gets in. As a result, a refusal proves that the lookup found
// the record and rejected it as inactive. The active arm is the control: its
// membership proves that the record was found rather than treated as never
// onboarded.
func TestBearerDeactivationReachesAMixedCaseRecord(t *testing.T) {
	t.Parallel()

	// The two forms a record can be stored in until the data migration
	// completes. Production holds the first today.
	storedForms := []struct {
		name   string
		stored string
	}{
		{name: "unmigrated record", stored: "Bob@Example.com"},
		{name: "migrated record", stored: "bob@example.com"},
	}

	for _, form := range storedForms {
		for _, tt := range []struct {
			name    string
			state   unikornv1.UserState
			allowed bool
		}{
			{name: "active is admitted", state: unikornv1.UserStateActive, allowed: true},
			{name: "suspended is refused", state: unikornv1.UserStateSuspended, allowed: false},
		} {
			t.Run(form.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				issuer := newAuth0TestIssuer(t)
				env := casingEnv(t, issuer, casingObjects(form.stored, tt.state)...)

				token := issuer.token(t, casingAudience, casingClaim, time.Now().Add(45*time.Second))

				result, err := env.authenticator.TokenExchange(nil, exchangeRequest(t, token, nil))

				if !tt.allowed {
					require.Error(t, err, "a suspended user must be refused whatever form the record is stored in")

					return
				}

				require.NoError(t, err, "the control arm: an active user must resolve whatever form the record is stored in")
				require.NotNil(t, result)

				claims := parsePassport(t, env, result.AccessToken)
				assert.Contains(t, claims.OrgIDs, casingOrgID,
					"membership must resolve, proving the record was found rather than treated as never onboarded")
			})
		}
	}
}

// TestBearerRefusesASubjectThatFoldsOntoTwoRecords covers the one input that
// allowExternalIdentity can otherwise let through. The claim matches no record
// exactly but folds onto two, so the lookup cannot tell which user it names.
// That address is onboarded, twice, so it is not an external identity. If it is
// admitted, the suspended record of the pair gets in.
//
// The control arm uses the same setting with no matching record, and is
// admitted. That proves the refusal comes from the ambiguity, not the setting.
func TestBearerRefusesASubjectThatFoldsOntoTwoRecords(t *testing.T) {
	t.Parallel()

	t.Run("control: a subject with no record is admitted", func(t *testing.T) {
		t.Parallel()

		issuer := newAuth0TestIssuer(t)
		env := casingEnv(t, issuer, casingUser("casing-other", "carol@example.com", unikornv1.UserStateActive))

		token := issuer.token(t, casingAudience, casingClaim, time.Now().Add(45*time.Second))

		result, err := env.authenticator.TokenExchange(nil, exchangeRequest(t, token, nil))
		require.NoError(t, err, "allowExternalIdentity must admit a subject with no record")
		require.NotNil(t, result)

		claims := parsePassport(t, env, result.AccessToken)
		assert.Empty(t, claims.OrgIDs)
	})

	t.Run("a subject that folds onto two records is refused", func(t *testing.T) {
		t.Parallel()

		// Neither stored form equals the claim, raw or folded, so the lookup
		// is ambiguous whichever form reaches it.
		issuer := newAuth0TestIssuer(t)
		env := casingEnv(t, issuer,
			casingUser("casing-suspended", "BOB@Example.com", unikornv1.UserStateSuspended),
			casingUser("casing-active", "bob@EXAMPLE.com", unikornv1.UserStateActive),
		)

		token := issuer.token(t, casingAudience, casingClaim, time.Now().Add(45*time.Second))

		result, err := env.authenticator.TokenExchange(nil, exchangeRequest(t, token, nil))
		require.Error(t, err, "a subject that folds onto two records must be refused, or the suspended one gets in")
		assert.Nil(t, result)

		// The same message as a missing or inactive user, so the response does
		// not show that the address has two records.
		assert.Contains(t, err.Error(), "user identity not found or inactive")
	})
}

// TestBearerLookalikeClaimDoesNotResolveAnotherUser pins the end-to-end effect
// of the claim fold.  The claim uses KELVIN SIGN in place of K, so it names a
// different mailbox from the stored kim@example.com.  With a Unicode fold, the
// claim became kim's address, and the passport carried kim's subject and
// organizations.  The control arm uses a plain upper-case K, which is the same
// mailbox and must still resolve kim.
func TestBearerLookalikeClaimDoesNotResolveAnotherUser(t *testing.T) {
	t.Parallel()

	const stored = "kim@example.com"

	for _, tt := range []struct {
		name    string
		claim   string
		resolve bool
	}{
		{name: "control: a case variant resolves the user", claim: "Kim@Example.com", resolve: true},
		{name: "a lookalike does not", claim: "\u212aim@Example.com", resolve: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			issuer := newAuth0TestIssuer(t)
			env := casingEnv(t, issuer, casingObjects(stored, unikornv1.UserStateActive)...)

			token := issuer.token(t, casingAudience, tt.claim, time.Now().Add(45*time.Second))

			// allowExternalIdentity admits a subject with no record, so the
			// lookalike gets a passport either way.  Only its content shows
			// whether it took kim's identity.
			result, err := env.authenticator.TokenExchange(nil, exchangeRequest(t, token, nil))
			require.NoError(t, err)
			require.NotNil(t, result)

			claims := parsePassport(t, env, result.AccessToken)

			if tt.resolve {
				assert.Contains(t, claims.OrgIDs, casingOrgID, "a case variant of the address must resolve its record")

				return
			}

			assert.NotContains(t, claims.OrgIDs, casingOrgID, "a lookalike must not receive another user's organizations")
			assert.NotEqual(t, stored, claims.Email, "a lookalike must not carry another user's subject")
			assert.NotEqual(t, stored, claims.Subject, "a lookalike must not carry another user's subject")
		})
	}
}
