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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	verifyCallerCN    = "passport-verify-caller"
	verifyUserSubject = "passport-user@example.com"

	verifyAllowIssuer   = "https://allow.example.com/"
	verifyDenyIssuer    = "https://deny.example.com/"
	verifyUnknownIssuer = "https://unknown.example.com/"

	verifyServiceOrg = "passport-sa-org"
)

func passportClaimsFor(subject string) *oauth2.PassportClaims {
	now := time.Now()

	return &oauth2.PassportClaims{
		Claims: jwt.Claims{
			ID:        "passport-id",
			Issuer:    oauth2.PassportIssuer,
			Subject:   subject,
			Audience:  jwt.Audience{verifyCallerCN},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(oauth2.PassportTTL)),
		},
		Type:      oauth2.PassportType,
		Acctype:   openapi.User,
		Source:    oauth2.PassportSourceUNI,
		Email:     subject,
		SrcIss:    oauth2.PassportSourceUNI,
		OrgIDs:    []string{"org-claimed"},
		OrgID:     "org-claimed",
		ProjectID: "project-claimed",
		Groups:    []string{"group-claimed"},
	}
}

func signPassport(t *testing.T, env *passportTestEnv, claims any) string {
	t.Helper()

	token, err := env.jwtIssuer.EncodeJWT(t.Context(), claims)
	require.NoError(t, err)

	return token
}

func signWithForeignKey(t *testing.T, claims any, keyID string) string {
	t.Helper()

	foreign, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	signer, err := gojose.NewSigner(gojose.SigningKey{
		Algorithm: gojose.ES512,
		Key:       gojose.JSONWebKey{Key: foreign, KeyID: keyID},
	}, nil)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

func tamperSubject(t *testing.T, token, subject string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any

	require.NoError(t, json.Unmarshal(payload, &claims))

	claims["sub"] = subject

	payload, err = json.Marshal(claims)
	require.NoError(t, err)

	parts[1] = base64.RawURLEncoding.EncodeToString(payload)

	return strings.Join(parts, ".")
}

func TestVerifyPassport(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t)

	signed := func(mutate func(*oauth2.PassportClaims)) func(*testing.T) string {
		return func(t *testing.T) string {
			t.Helper()

			claims := passportClaimsFor(verifyUserSubject)
			mutate(claims)

			return signPassport(t, env, claims)
		}
	}

	foreignSigned := func(keyID string) func(*testing.T) string {
		return func(t *testing.T) string {
			t.Helper()

			return signWithForeignKey(t, passportClaimsFor(verifyUserSubject), keyID)
		}
	}

	cases := []struct {
		name          string
		token         func(*testing.T) string
		emptyCallerCN bool
	}{
		{name: "Malformed", token: func(*testing.T) string { return "not-a-passport" }},
		{
			name: "WrongKey",
			token: func(t *testing.T) string {
				t.Helper()

				primary, _, err := env.jwtIssuer.GetPrimaryKey(t.Context())
				require.NoError(t, err)

				return foreignSigned(primary.KeyID)(t)
			},
		},
		{name: "UnknownKeyID", token: foreignSigned("unknown-key-id")},
		{name: "NoKeyID", token: foreignSigned("")},
		{
			name: "TamperedPayload",
			token: func(t *testing.T) string {
				t.Helper()

				return tamperSubject(t, signPassport(t, env, passportClaimsFor(verifyUserSubject)), "someone-else@example.com")
			},
		},
		{
			name: "OIDCIDToken",
			token: func(t *testing.T) string {
				t.Helper()

				now := time.Now()

				return signPassport(t, env, &oidc.IDToken{
					Claims: jwt.Claims{
						Issuer:   "https://test.com",
						Subject:  verifyUserSubject,
						Audience: jwt.Audience{verifyCallerCN},
						IssuedAt: jwt.NewNumericDate(now),
						Expiry:   jwt.NewNumericDate(now.Add(time.Minute)),
					},
					Email: oidc.Email{Email: verifyUserSubject},
				})
			},
		},
		{name: "WrongIssuer", token: signed(func(c *oauth2.PassportClaims) { c.Issuer = "https://test.com" })},
		{name: "AudienceForAnotherCN", token: signed(func(c *oauth2.PassportClaims) { c.Audience = jwt.Audience{"another-service"} })},
		{name: "EmptyAudience", token: signed(func(c *oauth2.PassportClaims) { c.Audience = nil })},
		{
			name:          "EmptyCallerCN",
			token:         signed(func(c *oauth2.PassportClaims) { c.Audience = jwt.Audience{""} }),
			emptyCallerCN: true,
		},
		{
			name: "ExpiredBeyondLeeway",
			token: signed(func(c *oauth2.PassportClaims) {
				now := time.Now()
				c.IssuedAt = jwt.NewNumericDate(now.Add(-90 * time.Second))
				c.NotBefore = jwt.NewNumericDate(now.Add(-90 * time.Second))
				c.Expiry = jwt.NewNumericDate(now.Add(-30 * time.Second))
			}),
		},
		{name: "NotYetValid", token: signed(func(c *oauth2.PassportClaims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(30 * time.Second)) })},
		{name: "NoExpiry", token: signed(func(c *oauth2.PassportClaims) { c.Expiry = nil })},
		{name: "AccessTokenType", token: signed(func(c *oauth2.PassportClaims) { c.Type = "access" })},
		{name: "SystemAccountType", token: signed(func(c *oauth2.PassportClaims) { c.Acctype = openapi.System })},
		{name: "EmptySubject", token: signed(func(c *oauth2.PassportClaims) { c.Subject = "" })},
		{name: "Delegated", token: signed(func(c *oauth2.PassportClaims) { c.Actor = &oauth2.ActorClaim{Subject: "acting-party"} })},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			callerCN := verifyCallerCN
			if tc.emptyCallerCN {
				callerCN = ""
			}

			verified, err := env.authenticator.VerifyPassport(t.Context(), tc.token(t), callerCN)
			require.ErrorIs(t, err, oauth2.ErrPassportRefused, "the passport must be refused")
			require.Nil(t, verified)
		})
	}

	t.Run("Valid", func(t *testing.T) {
		t.Parallel()

		claims := passportClaimsFor(verifyUserSubject)
		claims.Audience = jwt.Audience{"another-service", verifyCallerCN}

		_, err := env.authenticator.VerifyPassport(t.Context(), signPassport(t, env, claims), verifyCallerCN)
		require.NoError(t, err)
	})

	t.Run("ExpiredWithinLeeway", func(t *testing.T) {
		t.Parallel()

		claims := passportClaimsFor(verifyUserSubject)
		claims.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * time.Second))

		_, err := env.authenticator.VerifyPassport(t.Context(), signPassport(t, env, claims), verifyCallerCN)
		require.NoError(t, err, "the leeway must absorb a small clock skew between identity replicas")
	})
}

func TestVerifiedPassportHidesItsClaims(t *testing.T) {
	t.Parallel()

	passport := reflect.TypeFor[*oauth2.VerifiedPassport]()
	claimed := []reflect.Type{reflect.TypeFor[rbac.PassportSubject](), reflect.TypeFor[*authorization.Info]()}

	for i := range passport.NumMethod() {
		method := passport.Method(i)

		for j := range method.Type.NumOut() {
			require.NotContains(t, claimed, method.Type.Out(j),
				"VerifiedPassport.%s lets a caller build an Info that skips the subject state check", method.Name)
		}
	}
}

func passportSubjectObjects() []client.Object {
	user := func(name, subject string, state unikornv1.UserState) *unikornv1.User {
		return &unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: name},
			Spec:       unikornv1.UserSpec{Subject: subject, State: state},
		}
	}

	membership := func(name, userName, organizationID string) *unikornv1.OrganizationUser {
		return &unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: josetesting.Namespace,
				Name:      name,
				Labels: map[string]string{
					constants.UserLabel:         userName,
					constants.OrganizationLabel: organizationID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		}
	}

	organization := func(name, namespace string) *unikornv1.Organization {
		return &unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: name},
			Status:     unikornv1.OrganizationStatus{Namespace: namespace},
		}
	}

	serviceAccount := func(name, organizationID, namespace string) *unikornv1.ServiceAccount {
		return &unikornv1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    map[string]string{constants.OrganizationLabel: organizationID},
			},
		}
	}

	provider := func(name, issuer string, allowExternalIdentity bool) *unikornv1.OAuth2Provider {
		return &unikornv1.OAuth2Provider{
			ObjectMeta: metav1.ObjectMeta{Namespace: josetesting.Namespace, Name: name},
			Spec: unikornv1.OAuth2ProviderSpec{
				Issuer: issuer,
				BearerTrust: &unikornv1.BearerTrustSpec{
					Audience:              "https://identity.example.com",
					AllowExternalIdentity: allowExternalIdentity,
				},
			},
		}
	}

	return []client.Object{
		user("user-live", verifyUserSubject, unikornv1.UserStateActive),
		membership("membership-live-1", "user-live", "org-live-1"),
		membership("membership-live-2", "user-live", "org-live-2"),
		user("user-suspended", "suspended@example.com", unikornv1.UserStateSuspended),
		user("user-ambiguous-1", "Amb@Example.com", unikornv1.UserStateActive),
		user("user-ambiguous-2", "AMB@example.com", unikornv1.UserStateActive),
		organization(verifyServiceOrg, "passport-sa-namespace"),
		organization("passport-other-org", "passport-other-namespace"),
		serviceAccount("sa-live", verifyServiceOrg, "passport-sa-namespace"),
		serviceAccount("sa-moved", "passport-other-org", "passport-other-namespace"),
		serviceAccount("sa-orphan", "passport-deleted-org", "passport-deleted-namespace"),
		provider("allow-provider", verifyAllowIssuer, true),
		provider("deny-provider", verifyDenyIssuer, false),
		provider("trust-on-uni-sentinel-admits-external", oauth2.PassportSourceUNI, true),
	}
}

func TestResolvePassportSubject(t *testing.T) {
	t.Parallel()

	env := setupPassportTestEnv(t, passportSubjectObjects()...)

	userClaims := func(subject, srcIss string) *oauth2.PassportClaims {
		claims := passportClaimsFor(subject)
		claims.SrcIss = srcIss

		return claims
	}

	serviceClaims := func(subject string, organizationIDs ...string) *oauth2.PassportClaims {
		claims := passportClaimsFor(subject)
		claims.Acctype = openapi.Service
		claims.Email = ""
		claims.Groups = nil
		claims.OrgIDs = organizationIDs

		return claims
	}

	subjectInfo := func(t *testing.T, claims *oauth2.PassportClaims) (*authorization.Info, error) {
		t.Helper()

		verified, err := env.authenticator.VerifyPassport(t.Context(), signPassport(t, env, claims), verifyCallerCN)
		require.NoError(t, err)

		actor := &principal.Principal{Actor: claims.Subject, Type: claims.Acctype, Issuer: claims.SrcIss}

		return env.authenticator.ResolvePassportSubject(t.Context(), verified, actor)
	}

	refusals := []struct {
		name   string
		claims *oauth2.PassportClaims
	}{
		{name: "InactiveUser", claims: userClaims("suspended@example.com", verifyAllowIssuer)},
		{name: "AmbiguousSubject", claims: userClaims("amb@example.com", verifyAllowIssuer)},
		{name: "DeletedUNIUser", claims: userClaims("deleted@example.com", oauth2.PassportSourceUNI)},
		{name: "ExternalSubjectUnknownIssuer", claims: userClaims("external@example.com", verifyUnknownIssuer)},
		{name: "ExternalSubjectTrustDeniesExternalIdentity", claims: userClaims("external@example.com", verifyDenyIssuer)},
		{name: "DeletedServiceAccount", claims: serviceClaims("sa-deleted", verifyServiceOrg)},
		{name: "ServiceAccountInOtherOrganization", claims: serviceClaims("sa-moved", verifyServiceOrg)},
		{name: "ServiceAccountOrganizationDeleted", claims: serviceClaims("sa-orphan", "passport-deleted-org")},
		{name: "ServiceWithNoOrganization", claims: serviceClaims("sa-live")},
		{name: "ServiceWithTwoOrganizations", claims: serviceClaims("sa-live", verifyServiceOrg, "passport-other-org")},
	}

	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			info, err := subjectInfo(t, tc.claims)
			require.ErrorIs(t, err, oauth2.ErrPassportRefused, "the subject state must refuse the passport")
			require.Nil(t, info)
		})
	}

	t.Run("NilActor", func(t *testing.T) {
		t.Parallel()

		claims := userClaims(verifyUserSubject, oauth2.PassportSourceUNI)

		verified, err := env.authenticator.VerifyPassport(t.Context(), signPassport(t, env, claims), verifyCallerCN)
		require.NoError(t, err)

		info, err := env.authenticator.ResolvePassportSubject(t.Context(), verified, nil)
		require.ErrorIs(t, err, oauth2.ErrPassportRefused, "a request without a principal must be refused, not panic")
		require.Nil(t, info)
	})

	t.Run("ActiveUserGetsLiveOrganizations", func(t *testing.T) {
		t.Parallel()

		info, err := subjectInfo(t, userClaims(verifyUserSubject, oauth2.PassportSourceUNI))
		require.NoError(t, err)

		require.ElementsMatch(t, []string{"org-live-1", "org-live-2"}, info.Userinfo.HttpsunikornCloudOrgauthz.OrgIds,
			"the decision must use the live memberships, not the org_ids claim")
		require.Equal(t, []string{"group-claimed"}, info.Groups, "the groups come from the passport claim")
		require.Equal(t, oauth2.PassportSourceUNI, info.SrcIss)
		require.Equal(t, verifyUserSubject, info.Userinfo.Sub)
		require.Equal(t, verifyUserSubject, *info.Userinfo.Email)
		require.Equal(t, openapi.User, info.Userinfo.HttpsunikornCloudOrgauthz.Acctype)
	})

	t.Run("ExternalSubjectAdmittedByTrust", func(t *testing.T) {
		t.Parallel()

		claims := userClaims("external@example.com", verifyAllowIssuer)
		claims.Groups = []string{"external-group"}

		info, err := subjectInfo(t, claims)
		require.NoError(t, err, "a trust that admits external identities must accept a subject with no record")

		require.Empty(t, info.Userinfo.HttpsunikornCloudOrgauthz.OrgIds, "a subject with no record has no memberships, whatever org_ids claims")
		require.Equal(t, []string{"external-group"}, info.Groups)
		require.Equal(t, verifyAllowIssuer, info.SrcIss)
	})

	t.Run("LiveServiceAccount", func(t *testing.T) {
		t.Parallel()

		info, err := subjectInfo(t, serviceClaims("sa-live", verifyServiceOrg))
		require.NoError(t, err)

		require.Equal(t, []string{verifyServiceOrg}, info.Userinfo.HttpsunikornCloudOrgauthz.OrgIds)
		require.Equal(t, openapi.Service, info.Userinfo.HttpsunikornCloudOrgauthz.Acctype)
		require.True(t, info.ServiceAccount)
	})
}

func BenchmarkVerifyPassport(b *testing.B) {
	scheme := runtime.NewScheme()
	require.NoError(b, unikornv1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(josetesting.SigningKey(b, josetesting.Namespace)).Build()

	jwtIssuer := jose.NewJWTIssuer(cli, josetesting.Namespace, &jose.Options{})

	authenticator, err := oauth2.New(&oauth2.Options{TokenCacheSize: 1, CodeCacheSize: 1}, josetesting.Namespace, handlercommon.IssuerValue{}, cli, cli,
		jwtIssuer, userdb.NewUserDatabase(cli, josetesting.Namespace), rbac.New(cli, josetesting.Namespace, &rbac.Options{}))
	require.NoError(b, err)

	passport, err := jwtIssuer.EncodeJWT(b.Context(), passportClaimsFor(verifyUserSubject))
	require.NoError(b, err)

	for b.Loop() {
		if _, err := authenticator.VerifyPassport(b.Context(), passport, verifyCallerCN); err != nil {
			b.Fatal(err)
		}
	}
}
