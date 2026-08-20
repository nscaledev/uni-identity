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
	"errors"
	"slices"
	"testing"
	"time"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// accessTokenDurationTL is a short access-token lifetime used by trustlist
// tests. It only needs to be positive; the tests do not exercise expiry.
const accessTokenDurationTL = 5 * time.Second

// trustlistTestEnv holds an Authenticator plus the underlying fake client so
// individual tests can mutate cluster state between calls.
type trustlistTestEnv struct {
	authenticator *Authenticator
	client        client.Client
}

func getTrustlistScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()

	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("scheme.AddToScheme: %v", err)
	}

	if err := unikornv1.AddToScheme(s); err != nil {
		t.Fatalf("unikornv1.AddToScheme: %v", err)
	}

	return s
}

// setupAuthenticator builds a minimal Authenticator wired to a fake client that
// holds the given objects, all placed in josetesting.Namespace (the identity
// namespace). It does not start the JWT issuer because validatorForIssuer only
// needs the client and the options.
func setupAuthenticator(t *testing.T, objects ...client.Object) *Authenticator {
	t.Helper()

	return setupAuthenticatorWithClient(t, objects...).authenticator
}

// setupAuthenticatorWithClient is like setupAuthenticator but also returns the
// fake client so callers can delete or mutate objects between calls.
func setupAuthenticatorWithClient(t *testing.T, objects ...client.Object) *trustlistTestEnv {
	t.Helper()

	return setupAuthenticatorWithOptions(t, &Options{
		AccessTokenDuration: accessTokenDurationTL,
		TokenCacheSize:      64,
		CodeCacheSize:       64,
		ValidatorCacheSize:  64,
	}, objects...)
}

// setupAuthenticatorWithOptions is like setupAuthenticatorWithClient, but lets the
// caller supply the full Options, e.g. to configure the deprecated
// Auth0ExchangeIssuer flag that produces the synthetic legacy provider.
func setupAuthenticatorWithOptions(t *testing.T, opts *Options, objects ...client.Object) *trustlistTestEnv {
	t.Helper()

	cli := fake.NewClientBuilder().WithScheme(getTrustlistScheme(t)).WithObjects(objects...).Build()

	josetesting.RotateCertificate(t, cli)

	udb := userdb.NewUserDatabase(cli, josetesting.Namespace)
	rbacInst := rbac.New(cli, josetesting.Namespace, &rbac.Options{})

	issuerVal := handlercommon.IssuerValue{
		URL:      "https://test.com",
		Hostname: "test.com",
	}

	authenticator, err := New(
		opts,
		josetesting.Namespace,
		issuerVal,
		cli,
		nil, // jwtIssuer unused by validatorForIssuer
		udb,
		rbacInst,
	)
	if err != nil {
		t.Fatalf("oauth2.New: %v", err)
	}

	return &trustlistTestEnv{authenticator: authenticator, client: cli}
}

// providerWithBearerTrust returns an OAuth2Provider in josetesting.Namespace
// (the identity namespace) with BearerTrust configured.
func providerWithBearerTrust(issuerURL, audience string) *unikornv1.OAuth2Provider {
	return &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      "staff",
		},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer: issuerURL,
			BearerTrust: &unikornv1.BearerTrustSpec{
				Audience: audience,
			},
		},
	}
}

// providerInOrgNamespace returns an OAuth2Provider placed in an org-scoped
// namespace (not the identity namespace).
func providerInOrgNamespace(issuerURL, audience string) *unikornv1.OAuth2Provider {
	return &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace + "-org1",
			Name:      "org-staff",
		},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer: issuerURL,
			BearerTrust: &unikornv1.BearerTrustSpec{
				Audience: audience,
			},
		},
	}
}

// deleteProvider removes the named OAuth2Provider from the identity namespace
// in the fake client.
func deleteProvider(t *testing.T, cli client.Client, name string) {
	t.Helper()

	obj := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: josetesting.Namespace,
			Name:      name,
		},
	}

	if err := cli.Delete(t.Context(), obj); err != nil {
		t.Fatalf("deleteProvider: %v", err)
	}
}

func TestValidatorForIssuerMatch(t *testing.T) {
	t.Parallel()

	a := setupAuthenticator(t, providerWithBearerTrust("https://staff.auth0.com", "aud"))

	res, err := a.validatorForIssuer(t.Context(), "https://staff.auth0.com")
	if err != nil || res == nil || res.Validator == nil || res.Trust == nil {
		t.Fatalf("expected match, got res=%v err=%v", res, err)
	}
}

func TestValidatorForIssuerIgnoresOrgNamespace(t *testing.T) {
	t.Parallel()

	// Provider is in an org namespace, not the identity namespace; must not be trusted.
	a := setupAuthenticator(t, providerInOrgNamespace("https://staff.auth0.com", "aud"))

	res, err := a.validatorForIssuer(t.Context(), "https://staff.auth0.com")
	if !errors.Is(err, ErrUnknownIssuer) || res != nil {
		t.Fatalf("org-namespace provider must not be trusted; res=%v err=%v", res, err)
	}
}

func TestValidatorForIssuerRejectsEmptyAudience(t *testing.T) {
	t.Parallel()

	a := setupAuthenticator(t, providerWithBearerTrust("https://x.auth0.com", ""))

	if _, err := a.validatorForIssuer(t.Context(), "https://x.auth0.com"); err == nil {
		t.Fatal("expected config error for empty audience")
	}
}

func TestValidatorForIssuerRevokedOnDelete(t *testing.T) {
	t.Parallel()

	env := setupAuthenticatorWithClient(t, providerWithBearerTrust("https://staff.auth0.com", "aud"))

	// First call: provider present → must match.
	if res, _ := env.authenticator.validatorForIssuer(t.Context(), "https://staff.auth0.com"); res == nil {
		t.Fatal("expected match before delete")
	}

	// Delete the provider from the fake client.
	deleteProvider(t, env.client, "staff")

	// Second call: provider absent → must return ErrUnknownIssuer.
	res, err := env.authenticator.validatorForIssuer(t.Context(), "https://staff.auth0.com")
	if res != nil || !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("deleted provider must not remain trusted (no TTL lag); res=%v err=%v", res, err)
	}
}

func TestValidatorFingerprintIncludesGroupsClaim(t *testing.T) {
	t.Parallel()

	a := validatorFingerprint("https://iss/", "aud", nil, false, false, "")
	b := validatorFingerprint("https://iss/", "aud", nil, false, false, "https://unikorn-cloud.org/groups")

	if a == b {
		t.Fatal("fingerprint must change when groupsClaim changes")
	}
}

// TestGroupsClaimByIssuerFirstMatchWins pins that GroupsClaimByIssuer resolves
// first-match, exactly like validatorForIssuer, rather than reporting "some
// provider configured a claim" for an issuer two providers share. providerA
// precedes providerB because bearerTrustProviders name-sorts the CRD subset.
// The sort, not the client's List order, is the ordering guarantee. So
// providerA's empty GroupsClaim must win, although providerB, later by name,
// has one configured.
func TestGroupsClaimByIssuerFirstMatchWins(t *testing.T) {
	t.Parallel()

	const sharedIssuer = "https://staff.auth0.com"

	providerA := providerWithBearerTrust(sharedIssuer, "aud")
	providerA.Name = "provider-a"
	providerA.Spec.BearerTrust.GroupsClaim = ""

	providerB := providerWithBearerTrust(sharedIssuer, "aud")
	providerB.Name = "provider-b"
	providerB.Spec.BearerTrust.GroupsClaim = "https://unikorn-cloud.org/groups"

	a := setupAuthenticator(t, providerA, providerB)

	claims, err := a.GroupsClaimByIssuer(t.Context())
	if err != nil {
		t.Fatalf("GroupsClaimByIssuer: %v", err)
	}

	got, ok := claims[sharedIssuer]
	if !ok {
		t.Fatalf("expected issuer %q in map, got %v", sharedIssuer, claims)
	}

	if got != "" {
		t.Fatalf("got groupsClaim %q, want first-match empty claim from provider-a", got)
	}
}

// TestValidatorForIssuerRejectsBareGroupsClaim pins that a non-empty groupsClaim
// without "://" fails the provider's trust-list entry, the same way an invalid
// audience or algorithm does today, rather than being silently normalised,
// defaulted, or dropped between the OAuth2Provider spec and auth0.NewValidator.
// auth0.NewValidator already rejects a bare groupsClaim on its own (see
// TestNewValidatorRejectsBareGroupsClaim in pkg/oauth2/auth0), but nothing pinned
// that cachedValidator propagates that construction error up through
// validatorForIssuer instead of swallowing it for this one field.
func TestValidatorForIssuerRejectsBareGroupsClaim(t *testing.T) {
	t.Parallel()

	provider := providerWithBearerTrust("https://staff.auth0.com", "aud")
	provider.Spec.BearerTrust.GroupsClaim = "groups" // bare: no "://"

	a := setupAuthenticator(t, provider)

	res, err := a.validatorForIssuer(t.Context(), "https://staff.auth0.com")
	if err == nil {
		t.Fatal("expected the trust-list entry to fail for a bare groupsClaim, got no error")
	}

	if res != nil {
		t.Fatalf("expected no validated issuer for a bare groupsClaim, got %+v", res)
	}
}

// TestGroupsClaimByIssuerIncludesLegacyAuth0Exchange pins the no-CRD case: the
// map includes the synthetic legacy auth0-exchange provider, mapped to an empty
// groupsClaim, because the flag path carries none. A CRD provider that declares
// the same issuer shadows the synthetic instead (see
// TestGroupsClaimByIssuerCRDShadowsLegacySynthetic). The synthetic is
// deliberately absent from computeTrustedNonUNIIssuers, so Options.Validate
// must find it here first.
func TestGroupsClaimByIssuerIncludesLegacyAuth0Exchange(t *testing.T) {
	t.Parallel()

	const legacyIssuer = "https://legacy.auth0.com/"

	env := setupAuthenticatorWithOptions(t, &Options{
		AccessTokenDuration:   accessTokenDurationTL,
		TokenCacheSize:        64,
		CodeCacheSize:         64,
		ValidatorCacheSize:    64,
		Auth0ExchangeIssuer:   legacyIssuer,
		Auth0ExchangeAudience: "legacy-aud",
	})

	claims, err := env.authenticator.GroupsClaimByIssuer(t.Context())
	if err != nil {
		t.Fatalf("GroupsClaimByIssuer: %v", err)
	}

	got, ok := claims[legacyIssuer]
	if !ok {
		t.Fatalf("expected legacy auth0-exchange issuer %q in map, got %v", legacyIssuer, claims)
	}

	if got != "" {
		t.Fatalf("got groupsClaim %q, want empty claim for the synthetic legacy provider", got)
	}
}

// TestGroupsClaimByIssuerCRDShadowsLegacySynthetic pins that a CRD provider
// that declares the legacy auth0-exchange issuer always wins over the
// synthetic. CRD items always precede the synthetic, which is appended last.
// So the operator can set the issuer's groupsClaim without a replacement of
// the legacy flags.
func TestGroupsClaimByIssuerCRDShadowsLegacySynthetic(t *testing.T) {
	t.Parallel()

	const (
		legacyIssuer = "https://legacy.auth0.com/"
		claim        = "https://unikorn-cloud.org/groups"
	)

	provider := providerWithBearerTrust(legacyIssuer, "aud")
	provider.Spec.BearerTrust.GroupsClaim = claim

	env := setupAuthenticatorWithOptions(t, &Options{
		AccessTokenDuration:   accessTokenDurationTL,
		TokenCacheSize:        64,
		CodeCacheSize:         64,
		ValidatorCacheSize:    64,
		Auth0ExchangeIssuer:   legacyIssuer,
		Auth0ExchangeAudience: "legacy-aud",
	}, provider)

	claims, err := env.authenticator.GroupsClaimByIssuer(t.Context())
	if err != nil {
		t.Fatalf("GroupsClaimByIssuer: %v", err)
	}

	if got := claims[legacyIssuer]; got != claim {
		t.Fatalf("got groupsClaim %q, want %q from the CRD provider shadowing the synthetic", got, claim)
	}
}

// TestBearerTrustProvidersSortsByName pins the ordering invariant directly:
// the CRD subset comes back name-sorted regardless of input order, and the
// synthetic legacy provider is always last. The input is deliberately
// reverse-ordered. A pass with the sort deleted would require pre-sorted
// input, and this test rules that out.
func TestBearerTrustProvidersSortsByName(t *testing.T) {
	t.Parallel()

	const legacyIssuer = "https://legacy.auth0.com/"

	providerZ := providerWithBearerTrust("https://z.auth0.com", "aud")
	providerZ.Name = "z-provider"

	providerA := providerWithBearerTrust("https://a.auth0.com", "aud")
	providerA.Name = "a-provider"

	env := setupAuthenticatorWithOptions(t, &Options{
		AccessTokenDuration:   accessTokenDurationTL,
		TokenCacheSize:        64,
		CodeCacheSize:         64,
		ValidatorCacheSize:    64,
		Auth0ExchangeIssuer:   legacyIssuer,
		Auth0ExchangeAudience: "legacy-aud",
	})

	candidates := env.authenticator.bearerTrustProviders([]unikornv1.OAuth2Provider{*providerZ, *providerA})

	want := []string{"a-provider", "z-provider", auth0LegacyProviderName}

	got := make([]string, 0, len(candidates))
	for _, c := range candidates {
		got = append(got, c.Name)
	}

	if !slices.Equal(got, want) {
		t.Fatalf("got candidate order %v, want %v", got, want)
	}
}
