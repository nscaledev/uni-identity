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

package rbac_test

import (
	goerrors "errors"
	"reflect"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"

	"github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestGlobalRoleBindingsValueParse(t *testing.T) {
	t.Parallel()

	accept := []struct {
		in   string
		want rbac.GlobalRoleBinding
	}{
		{"https://staff.example.com/::*::platform-reader", rbac.GlobalRoleBinding{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"platform-reader"}, Wildcard: true}},
		{"uni::admin@nscale.com::role-a,role-b", rbac.GlobalRoleBinding{Issuer: "uni", Subject: "admin@nscale.com", RoleIDs: []string{"role-a", "role-b"}}},
		// IPv6 issuer: right-anchored parsing keeps the "::" inside the URL intact.
		{"https://[2001:db8::1]/::alice@x.com::r1", rbac.GlobalRoleBinding{Issuer: "https://[2001:db8::1]/", Subject: "alice@x.com", RoleIDs: []string{"r1"}}},
		// Subject whitespace normalizes: padded "*" is a real wildcard, clamped and guarded.
		{"https://staff.example.com/:: * ::r1", rbac.GlobalRoleBinding{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"r1"}, Wildcard: true}},
	}

	for _, tc := range accept {
		var v rbac.GlobalRoleBindingsValue
		if err := v.Set(tc.in); err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}

		if !reflect.DeepEqual([]rbac.GlobalRoleBinding(v), []rbac.GlobalRoleBinding{tc.want}) {
			t.Fatalf("%q: got %+v", tc.in, v)
		}
	}

	reject := []string{
		"",                                    // empty
		"no-separators",                       // malformed
		"uni::only-one-separator",             // malformed
		"uni::*::platform-reader",             // wildcard on sentinel
		"uni:: * ::platform-reader",           // padded wildcard on sentinel (normalized, still rejected)
		"::alice@x.com::r1",                   // empty issuer
		"not-a-url::alice@x.com::r1",          // issuer not sentinel/URL
		"https://a.com/::alice@x.com::",       // empty role list
		"https://a.com/::alice@x.com::r1,",    // empty role member
		"https://a.com/::::r1",                // empty subject
		"https://a.com/,https://b.com/::x::r", // comma in issuer (legacy join idiom)
		"https://a .com/::x::r",               // whitespace in issuer
		"uni::a@x.com:: r1 ",                  // whitespace-padded role ID
		"uni::a@x.com::   ",                   // whitespace-only role ID
		"https://a.com/::alice::bob::r1",      // "::" in issuer path swallows a subject segment
	}

	for _, in := range reject {
		var v rbac.GlobalRoleBindingsValue
		if err := v.Set(in); err == nil {
			t.Fatalf("%q: expected error", in)
		}
	}
}

func TestGlobalGroupRoleBindingsValueSet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		value   string
		want    []rbac.GroupRoleBinding
		wantErr bool
	}{
		{name: "valid", value: "https://staff.example.com/::Platform Engineering::role-a,role-b",
			want: []rbac.GroupRoleBinding{{Issuer: "https://staff.example.com/", Group: "Platform Engineering", RoleIDs: []string{"role-a", "role-b"}}}},
		{name: "surrounding whitespace trimmed", value: "https://staff.example.com/:: SRE ::role-a",
			want: []rbac.GroupRoleBinding{{Issuer: "https://staff.example.com/", Group: "SRE", RoleIDs: []string{"role-a"}}}},
		{name: "uni sentinel rejected", value: "uni::SRE::role-a", wantErr: true},
		{name: "wildcard group rejected", value: "https://staff.example.com/::*::role-a", wantErr: true},
		{name: "empty group rejected", value: "https://staff.example.com/::::role-a", wantErr: true},
		{name: "empty issuer rejected", value: "::SRE::role-a", wantErr: true},
		{name: "group with :: shifts into issuer and fails (path issuer)", value: "https://staff.example.com/::my::group::role-a", wantErr: true},
		{name: "group with :: shifts into issuer and fails (pathless issuer)", value: "https://staff.example.com::my::group::role-a", wantErr: true},
		{name: "malformed", value: "no-separators", wantErr: true},
		{name: "empty role", value: "https://staff.example.com/::SRE::", wantErr: true},
		{name: "role with whitespace", value: "https://staff.example.com/::SRE::role a", wantErr: true},
		{name: "issuer with whitespace rejected", value: "not a url::SRE::role-a", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var v rbac.GlobalGroupRoleBindingsValue

			err := v.Set(tc.value)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%q: expected error", tc.value)
				}

				if strings.Contains(tc.name, "shifts into issuer") && !strings.Contains(err.Error(), "group name contains") {
					t.Fatalf("%q: error %q does not mention the group-name possibility", tc.value, err.Error())
				}

				// Pin the specific rejection reason that
				// validateGroupBindingIssuer returns for an empty issuer, not
				// merely that some error fired.
				if tc.name == "empty issuer rejected" && !strings.Contains(err.Error(), "issuer is not an absolute URL") {
					t.Fatalf("%q: error %q does not report the empty-issuer-is-not-a-URL reason", tc.value, err.Error())
				}

				return
			}

			if err != nil {
				t.Fatalf("%q: %v", tc.value, err)
			}

			if !reflect.DeepEqual([]rbac.GroupRoleBinding(v), tc.want) {
				t.Fatalf("%q: got %+v, want %+v", tc.value, v, tc.want)
			}
		})
	}
}

func TestAccumulateGlobalReadPermissionsClampsWrites(t *testing.T) {
	t.Parallel()

	roles := map[string]*unikornv1.Role{
		"crud-role": {
			Spec: unikornv1.RoleSpec{
				Scopes: unikornv1.RoleScopes{
					Global: []unikornv1.RoleScope{
						{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
						{Name: "identity:writeonly", Operations: []unikornv1.Operation{unikornv1.Create}},
					},
				},
			},
		},
	}

	acl := &openapi.Acl{}
	if err := rbac.AccumulateGlobalReadPermissionsForTest(acl, []string{"crud-role"}, roles); err != nil {
		t.Fatal(err)
	}

	want := openapi.AclEndpoints{{Name: "identity:organizations", Operations: []openapi.AclOperation{openapi.Read}}}
	if !reflect.DeepEqual(*acl.Global, want) {
		t.Fatalf("got %+v, want %+v", *acl.Global, want)
	}

	err := rbac.AccumulateGlobalReadPermissionsForTest(&openapi.Acl{}, []string{"missing"}, roles)
	if !goerrors.Is(err, errors.ErrConsistency) { // core/pkg/errors
		t.Fatalf("want ErrConsistency for missing role, got %v", err)
	}
}

func TestEffectiveGlobalRoleBindings(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{
		PlatformAdministratorRoleIDs: []string{"admin-role"},
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
			{Issuer: constants.UNISentinel, Subject: "legacy@x.com"},
			// pkg/server's expandBareAdminSubjects mirrors bare entries onto the
			// legacy exchange issuer: both forms must translate.
			{Issuer: "https://legacy-exchange.example.com/", Subject: "legacy@x.com"},
			// A legacy subject literally "*" stays an EXACT binding (Wildcard
			// false): translation is verbatim, never widening.
			{Issuer: "https://a.com/", Subject: "*"},
		},
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"reader-role"}, Wildcard: true},
		},
	}

	got := rbac.EffectiveGlobalRoleBindingsForTest(opts)
	want := []rbac.GlobalRoleBinding{
		{Issuer: constants.UNISentinel, Subject: "legacy@x.com", RoleIDs: []string{"admin-role"}},
		{Issuer: "https://legacy-exchange.example.com/", Subject: "legacy@x.com", RoleIDs: []string{"admin-role"}},
		{Issuer: "https://a.com/", Subject: "*", RoleIDs: []string{"admin-role"}},
		{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"reader-role"}, Wildcard: true},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestResolveGlobalRoleBindings(t *testing.T) {
	t.Parallel()

	bindings := []rbac.GlobalRoleBinding{
		{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"r"}, Wildcard: true},
		{Issuer: "https://staff.example.com/", Subject: "boss@x.com", RoleIDs: []string{"a"}},
		// External-exact binding, same subject as the sentinel case below: pins
		// that matching is issuer-scoped, not subject-only. A resolver that
		// matched subjects independently of issuer would leak this at the
		// sentinel.

		{Issuer: constants.UNISentinel, Subject: "local@x.com", RoleIDs: []string{"a"}},
		// Defense in depth: even if misconfigured into Options directly
		// (bypassing Set), a sentinel/empty-issuer wildcard never matches.
		// (Also pins the impersonation path: impersonated principals carry the
		// sentinel — processImpersonatedPrincipalACL — so they can never
		// acquire a wildcard or external-issuer binding.)
		{Issuer: constants.UNISentinel, Subject: "*", RoleIDs: []string{"a"}, Wildcard: true},
		{Issuer: "", Subject: "*", RoleIDs: []string{"a"}, Wildcard: true},
	}

	cases := []struct {
		srcIss, subject string
		wantSubjects    []string
	}{
		{"https://staff.example.com/", "anyone@x.com", []string{"*"}},
		{"https://staff.example.com/", " boss@x.com ", []string{"*", "boss@x.com"}}, // exact match trims whitespace on both sides
		{"https://staff.example.com/", " BOSS@x.com ", []string{"*"}},               // mixed case does NOT match the exact binding; only the wildcard catches it
		{constants.UNISentinel, "local@x.com", []string{"local@x.com"}},
		{constants.UNISentinel, "anyone@x.com", nil}, // sentinel wildcard guarded
		{"", "anyone@x.com", nil},                    // empty srcIss guarded
		{"https://other.com/", "boss@x.com", nil},    // issuer exact match
		// Pin: the external-exact binding's subject ("boss@x.com") must not
		// match at the sentinel — an impersonated principal (always evaluated
		// at the sentinel) can never acquire an external-issuer exact binding.
		{constants.UNISentinel, "boss@x.com", nil},
	}

	for _, tc := range cases {
		got := rbac.ResolveGlobalRoleBindingsForTest(bindings, tc.srcIss, tc.subject)

		var gotSubjects []string
		for _, b := range got {
			gotSubjects = append(gotSubjects, b.Subject)
		}

		if !reflect.DeepEqual(gotSubjects, tc.wantSubjects) {
			t.Fatalf("(%q,%q): got %v, want %v", tc.srcIss, tc.subject, gotSubjects, tc.wantSubjects)
		}
	}
}

// TestOptionsValidateGlobalRoleBindingIssuer covers the outcomes of the
// GlobalRoleBindings loop in Options.Validate: an untrusted issuer is
// reported (even against an empty trusted-issuer list, since this check is
// ungated), a trusted issuer is not, and the UNI sentinel is always skipped.
// See TestOptionsValidateReportsEveryOffender for the multiple-offenders case.
func TestOptionsValidateGlobalRoleBindingIssuer(t *testing.T) {
	t.Parallel()

	const trustedIssuer = "https://staff.example.com/"

	// untrusted issuer (not the UNI sentinel, not in trustedNonUNIIssuers) → reported.
	untrusted := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: "https://untrusted.example.com/", Subject: "alice@x.com", RoleIDs: []string{"r"}},
		},
	}

	err := untrusted.Validate([]string{trustedIssuer}, nil)
	if err == nil {
		t.Fatal("expected untrusted-binding-issuer error, got nil")
	}

	if !goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, want ErrUntrustedBindingIssuer", err)
	}

	// trusted issuer → not reported.
	trusted := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: trustedIssuer, Subject: "alice@x.com", RoleIDs: []string{"r"}},
		},
	}

	if err := trusted.Validate([]string{trustedIssuer}, nil); err != nil {
		t.Fatalf("unexpected error for trusted issuer: %v", err)
	}

	// UNI sentinel issuer → skipped, never reported, even against an empty
	// trusted-issuer list.
	sentinel := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: constants.UNISentinel, Subject: "alice@x.com", RoleIDs: []string{"r"}},
		},
	}

	if err := sentinel.Validate(nil, nil); err != nil {
		t.Fatalf("unexpected error for UNI sentinel issuer: %v", err)
	}

	// both a bare admin subject and an untrusted binding issuer present →
	// both diagnostics are reported (errors.Join), not just the first found.
	both := &rbac.Options{
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
			{Issuer: constants.UNISentinel, Subject: "bare@nscale.com"},
		},
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: "https://untrusted.example.com/", Subject: "alice@x.com", RoleIDs: []string{"r"}},
		},
	}

	err = both.Validate([]string{trustedIssuer}, nil)
	if !goerrors.Is(err, rbac.ErrBareAdminSubject) {
		t.Fatalf("got %v, want ErrBareAdminSubject also reported", err)
	}

	if !goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, want ErrUntrustedBindingIssuer also reported", err)
	}

	// empty trusted-issuer list → the binding-issuer check still runs (it has
	// no gate), so a genuinely-untrusted issuer is reported even though no
	// non-UNI issuer is trusted at all.
	emptyTrustedList := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: "https://untrusted.example.com/", Subject: "alice@x.com", RoleIDs: []string{"r"}},
		},
	}

	err = emptyTrustedList.Validate(nil, nil)
	if !goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, want ErrUntrustedBindingIssuer even with an empty trusted-issuer list", err)
	}
}

// TestOptionsValidateReportsEveryOffender pins that Options.Validate reports
// every offending GlobalRoleBindings entry, not just the first, mirroring the
// same errors.Join behaviour already covered per-category above.
func TestOptionsValidateReportsEveryOffender(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: "https://untrusted-a.example.com/", Subject: "alice@x.com", RoleIDs: []string{"r"}},
			{Issuer: "https://untrusted-b.example.com/", Subject: "bob@x.com", RoleIDs: []string{"r"}},
		},
	}

	err := opts.Validate([]string{"https://staff.example.com/"}, nil)
	if !goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, want ErrUntrustedBindingIssuer", err)
	}

	if !strings.Contains(err.Error(), "untrusted-a.example.com") || !strings.Contains(err.Error(), "untrusted-b.example.com") {
		t.Fatalf("expected both offending issuers named in error, got: %v", err)
	}
}

// TestOptionsValidateGroupBindingOutcomes covers the three outcomes of the
// GlobalGroupRoleBindings loop in Options.Validate:
//
//  1. An issuer that is absent from groupsClaimByIssuer and untrusted reports
//     ErrUntrustedBindingIssuer.
//  2. An issuer that is present in the map with an empty groupsClaim, the shape
//     of the synthetic legacy auth0-exchange provider, reports the dead-binding
//     error ErrGroupBindingNoGroupsClaim instead, and never the untrusted error.
//  3. An issuer that is present with a configured claim reports nothing.
//
// Validate must check map membership before the trusted-issuers fallback.
// Otherwise it misreports the second case as untrusted.
func TestOptionsValidateGroupBindingOutcomes(t *testing.T) {
	t.Parallel()

	const (
		unknownIssuer = "https://unknown.example.com/"
		deadIssuer    = "https://auth0-legacy.example.com/"
		liveIssuer    = "https://staff.example.com/"
	)

	groupsClaimByIssuer := map[string]string{
		deadIssuer: "",
		liveIssuer: "https://unikorn-cloud.org/groups",
	}

	// Issuer absent from the map, and untrusted → ErrUntrustedBindingIssuer.
	untrusted := &rbac.Options{
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: unknownIssuer, Group: "staff", RoleIDs: []string{"r"}},
		},
	}

	err := untrusted.Validate(nil, groupsClaimByIssuer)
	if !goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, want ErrUntrustedBindingIssuer", err)
	}

	if goerrors.Is(err, rbac.ErrGroupBindingNoGroupsClaim) {
		t.Fatalf("got %v, unexpectedly ErrGroupBindingNoGroupsClaim", err)
	}

	// Issuer present in the map with an empty groupsClaim →
	// ErrGroupBindingNoGroupsClaim, and NOT ErrUntrustedBindingIssuer, even
	// though deadIssuer is not in any trusted-issuers list.
	dead := &rbac.Options{
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: deadIssuer, Group: "staff", RoleIDs: []string{"r"}},
		},
	}

	err = dead.Validate(nil, groupsClaimByIssuer)
	if !goerrors.Is(err, rbac.ErrGroupBindingNoGroupsClaim) {
		t.Fatalf("got %v, want ErrGroupBindingNoGroupsClaim", err)
	}

	if goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, unexpectedly ErrUntrustedBindingIssuer", err)
	}

	// Issuer present in the map with a configured claim → no error.
	live := &rbac.Options{
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: liveIssuer, Group: "staff", RoleIDs: []string{"r"}},
		},
	}

	if err := live.Validate(nil, groupsClaimByIssuer); err != nil {
		t.Fatalf("unexpected error for issuer with a configured groupsClaim: %v", err)
	}
}

// TestOptionsValidateNilGroupsClaimByIssuerSkipsGroupCheckOnly covers the
// nil-versus-empty-map contract documented on Options.Validate. A nil map means
// "the claims lookup failed" and must skip the GlobalGroupRoleBindings advisory
// entirely. A non-nil empty map means "no issuers configured" and runs that
// check normally.
//
// The fixture's group binding issuer is absent from trustedNonUNIIssuers, so the
// empty-map case reports it as untrusted. A nil map must report neither that nor
// the dead-binding error for it. The fixture also carries a bare admin subject,
// so both cases show the unrelated, ungated checks running identically.
func TestOptionsValidateNilGroupsClaimByIssuerSkipsGroupCheckOnly(t *testing.T) {
	t.Parallel()

	const (
		trustedIssuer = "https://staff.example.com/"
		groupIssuer   = "https://untrusted.example.com/"
	)

	opts := &rbac.Options{
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
			{Issuer: constants.UNISentinel, Subject: "bare@nscale.com"},
		},
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: groupIssuer, Group: "staff", RoleIDs: []string{"r"}},
		},
	}

	// A nil groupsClaimByIssuer ("the claims lookup failed") skips the
	// GlobalGroupRoleBindings check entirely. Validate reports neither
	// ErrGroupBindingNoGroupsClaim nor ErrUntrustedBindingIssuer for
	// groupIssuer, even though groupIssuer is not in trustedNonUNIIssuers.
	// groupsClaimByIssuer does not gate the unrelated bare-admin check, which
	// still runs.
	err := opts.Validate([]string{trustedIssuer}, nil)
	if !goerrors.Is(err, rbac.ErrBareAdminSubject) {
		t.Fatalf("got %v, want ErrBareAdminSubject reported even when the group check is skipped", err)
	}

	if goerrors.Is(err, rbac.ErrGroupBindingNoGroupsClaim) {
		t.Fatalf("got %v, unexpectedly ErrGroupBindingNoGroupsClaim with a nil groupsClaimByIssuer", err)
	}

	if goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, unexpectedly ErrUntrustedBindingIssuer with a nil groupsClaimByIssuer", err)
	}

	// A non-nil empty map ("no issuers configured") runs the check. groupIssuer
	// is absent from the map and not in trustedNonUNIIssuers, so Validate DOES
	// report it as untrusted. This contrast proves that the nil case above is a
	// real skip, not an incidental non-match.
	err = opts.Validate([]string{trustedIssuer}, map[string]string{})
	if !goerrors.Is(err, rbac.ErrBareAdminSubject) {
		t.Fatalf("got %v, want ErrBareAdminSubject still reported with a non-nil empty groupsClaimByIssuer", err)
	}

	if !goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, want ErrUntrustedBindingIssuer reported with a non-nil empty groupsClaimByIssuer", err)
	}
}

// Legacy flags and equivalent bindings must produce identical ACLs.
func TestLegacyFlagsEquivalentToBindings(t *testing.T) {
	t.Parallel()

	legacy := &rbac.Options{
		PlatformAdministratorRoleIDs:  []string{"admin"},
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{{Issuer: "https://a.com/", Subject: "admin@x.com"}},
	}

	viaBindings := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{{Issuer: "https://a.com/", Subject: "admin@x.com", RoleIDs: []string{"admin"}}},
	}

	legacyACL := getACLForSubject(t, legacy, "admin@x.com", "https://a.com/")

	// Guard against vacuous equivalence: DeepEqual alone would also pass if
	// both sides granted nothing.
	if legacyACL.Global == nil {
		t.Fatal("legacy path granted no global ACL; equivalence check would be vacuous")
	}

	if !reflect.DeepEqual(
		legacyACL,
		getACLForSubject(t, viaBindings, "admin@x.com", "https://a.com/"),
	) {
		t.Fatal("legacy translation diverges from direct bindings")
	}
}

// A wildcard match accumulates clamped scopes; an exact match on the same
// issuer unions in a different role's full scopes. Two roles with distinct
// endpoints make a missed accumulation from either binding detectable.
func TestWildcardClampAndMultiBindingUnion(t *testing.T) {
	t.Parallel()

	crudRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "crud-role"},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
				},
			},
		},
	}

	otherRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "other-role"},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read}},
				},
			},
		},
	}

	opts := &rbac.Options{GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
		{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"crud-role"}, Wildcard: true},
	}}

	acl := getACLForSubject(t, opts, "anyone@x.com", "https://staff.example.com/", crudRole, otherRole)
	if acl.Global == nil {
		t.Fatal("wildcard binding granted nothing")
	}

	for _, e := range *acl.Global {
		if !reflect.DeepEqual(e.Operations, []openapi.AclOperation{openapi.Read}) {
			t.Fatalf("wildcard grant not clamped: %+v", e)
		}
	}

	opts.GlobalRoleBindings = append(opts.GlobalRoleBindings,
		rbac.GlobalRoleBinding{Issuer: "https://staff.example.com/", Subject: "boss@x.com", RoleIDs: []string{"other-role"}})

	acl = getACLForSubject(t, opts, "boss@x.com", "https://staff.example.com/", crudRole, otherRole)

	// Union must contain BOTH: crud-role's endpoint clamped to read (wildcard)
	// and other-role's endpoint with full verbs (exact).
	byName := map[string][]openapi.AclOperation{}
	for _, e := range *acl.Global {
		byName[e.Name] = e.Operations
	}

	if !reflect.DeepEqual(byName["identity:organizations"], []openapi.AclOperation{openapi.Read}) {
		t.Fatalf("wildcard contribution missing/unclamped: %+v", byName)
	}

	if len(byName["identity:groups"]) != 2 {
		t.Fatalf("exact contribution missing full verbs: %+v", byName)
	}

	// Direct same-role comparison: binding the SAME role
	// (crud-role) exactly, rather than via wildcard, must yield its full
	// operation set — contrasted directly against the wildcard-bound
	// "anyone@x.com" case above, which got only read on this same endpoint.
	// A distinct issuer keeps this exact binding from also matching the
	// staff.example.com wildcard, which would otherwise union in and mask a
	// clamp-not-applied bug behind an already-full result.
	opts.GlobalRoleBindings = append(opts.GlobalRoleBindings,
		rbac.GlobalRoleBinding{Issuer: "https://other.example.com/", Subject: "admin@x.com", RoleIDs: []string{"crud-role"}})

	acl = getACLForSubject(t, opts, "admin@x.com", "https://other.example.com/", crudRole, otherRole)

	want := []openapi.AclOperation{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}

	byName = map[string][]openapi.AclOperation{}
	for _, e := range *acl.Global {
		byName[e.Name] = e.Operations
	}

	if !reflect.DeepEqual(byName["identity:organizations"], want) {
		t.Fatalf("exact binding on same role did not yield full operations: got %+v, want %+v", byName["identity:organizations"], want)
	}
}

// Regression pin (green before and after this task): an unbound subject gets
// no global block.
func TestUnboundSubjectHasNoGlobalACL(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
		{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"crud-role"}, Wildcard: true},
	}}

	if acl := getACLForSubject(t, opts, "anyone@x.com", constants.UNISentinel); acl.Global != nil {
		t.Fatalf("unbound subject received global ACL: %+v", acl.Global)
	}
}

// Replace semantics pin: a bound subject with org memberships in authz skips
// membership resolution entirely. The fake client has no organization
// fixtures, so an accidental additive implementation errors on the org
// lookup instead of returning the global-only ACL. Table covers both an exact
// binding and its wildcard variant.
//
// The wildcard row is intentional, not an oversight — issuer-wide bindings are
// only appropriate for issuers whose entire user population is itself an
// authorization decision (e.g. a staff-only issuer), so bypassing
// ErrNotInOrganization for every subject at that issuer is the point, not a
// bug to "fix".
func TestBoundSubjectSkipsMembershipResolution(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		binding rbac.GlobalRoleBinding
		subject string
	}{
		{"exact", rbac.GlobalRoleBinding{Issuer: "https://a.com/", Subject: "admin@x.com", RoleIDs: []string{"admin"}}, "admin@x.com"},
		{"wildcard", rbac.GlobalRoleBinding{Issuer: "https://staff.example.com/", Subject: "*", RoleIDs: []string{"admin"}, Wildcard: true}, "anyone@x.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := &rbac.Options{GlobalRoleBindings: rbac.GlobalRoleBindingsValue{tc.binding}}
			acl := getACLForSubjectWithOrgIDs(t, opts, tc.subject, tc.binding.Issuer, []string{"some-org"})

			if acl.Global == nil || acl.Organizations != nil {
				t.Fatalf("expected global-only ACL, got %+v", acl)
			}
		})
	}
}

// TestGroupRoleBindingGrantsFullScopesNoClamp covers the core property of group
// bindings. Unlike a wildcard subject binding, a matched group binding is NOT
// clamped to read. The assertion that a write operation (Create, Update, Delete)
// survives is what separates this from the wildcard-clamp behaviour.
func TestGroupRoleBindingGrantsFullScopesNoClamp(t *testing.T) {
	t.Parallel()

	roleA := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "role-a"},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
				},
			},
		},
	}

	opts := &rbac.Options{
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: "https://staff.example.com/", Group: "Platform Engineering", RoleIDs: []string{"role-a"}},
		},
	}

	acl := getACLForSubjectWithGroups(t, opts, "anyone@x.com", "https://staff.example.com/", nil, []string{"Platform Engineering"}, roleA)

	if acl.Global == nil {
		t.Fatal("group binding granted nothing")
	}

	want := openapi.AclEndpoints{{Name: "identity:organizations", Operations: []openapi.AclOperation{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}}}
	if !reflect.DeepEqual(*acl.Global, want) {
		t.Fatalf("group binding grant was clamped or otherwise wrong: got %+v, want %+v", *acl.Global, want)
	}
}

// TestGroupRoleBindingCaseMismatchDoesNotMatch pins byte-exact matching. There
// is no case folding, and no trimming inside the name.
func TestGroupRoleBindingCaseMismatchDoesNotMatch(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: "https://staff.example.com/", Group: "Platform Engineering", RoleIDs: []string{"admin"}},
		},
	}

	acl := getACLForSubjectWithGroups(t, opts, "anyone@x.com", "https://staff.example.com/", nil, []string{"platform engineering"})

	if acl.Global != nil {
		t.Fatalf("case-mismatched group unexpectedly matched: %+v", acl.Global)
	}
}

// TestGroupRoleBindingWrongIssuerDoesNotMatch pins that group binding matching
// is issuer-qualified, like subject binding matching.
func TestGroupRoleBindingWrongIssuerDoesNotMatch(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: "https://staff.example.com/", Group: "Platform Engineering", RoleIDs: []string{"admin"}},
		},
	}

	acl := getACLForSubjectWithGroups(t, opts, "anyone@x.com", "https://other.example.com/", nil, []string{"Platform Engineering"})

	if acl.Global != nil {
		t.Fatalf("wrong-issuer group binding unexpectedly matched: %+v", acl.Global)
	}
}

// TestUnmatchedGroupsFallsThroughToMembershipResolution pins that replace
// semantics do not fire when no group binding matches, a case mismatch here, and
// that membership resolution proceeds as normal. The fake client has no
// Organization fixture for "some-org", so the normal, non-replace path's
// organization lookup fails deterministically on that missing fixture. That
// failure is the proof. If the implementation incorrectly treated this as a
// match, GetACL would return a global-only ACL with no error instead.
func TestUnmatchedGroupsFallsThroughToMembershipResolution(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: "https://staff.example.com/", Group: "Platform Engineering", RoleIDs: []string{"admin"}},
		},
	}

	_, err := aclOrErrForSubject(t, opts, "anyone@x.com", "https://staff.example.com/", []string{"some-org"}, []string{"platform engineering"})
	if err == nil {
		t.Fatal("expected organization-lookup error proving membership resolution ran (unmatched group incorrectly treated as bound?)")
	}
}

// TestSubjectAndGroupBindingsCombineInOneReplace proves that the clamped
// accumulator (wildcard-subject) and the unclamped accumulators (exact-subject,
// group) combine correctly on a single principal, inside one replace-semantics
// block. An exact subject binding, a wildcard subject binding, and a group
// binding all match. Replace semantics skip the org memberships present in the
// claim entirely. Each leg still keeps its own clamp behaviour inside the union.
func TestSubjectAndGroupBindingsCombineInOneReplace(t *testing.T) {
	t.Parallel()

	wildcardRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "wildcard-role"},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
				},
			},
		},
	}

	exactRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "exact-role"},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read}},
				},
			},
		},
	}

	groupRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "group-role"},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:users", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
				},
			},
		},
	}

	const (
		issuer  = "https://staff.example.com/"
		subject = "boss@x.com"
		group   = "Platform Engineering"
	)

	opts := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: issuer, Subject: "*", RoleIDs: []string{"wildcard-role"}, Wildcard: true},
			{Issuer: issuer, Subject: subject, RoleIDs: []string{"exact-role"}},
		},
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: issuer, Group: group, RoleIDs: []string{"group-role"}},
		},
	}

	// The claim carries org memberships, but the fake client has no Organization
	// fixture. An accidental additive implementation would attempt membership
	// resolution and error on the missing organization, instead of returning the
	// global-only union asserted below.
	acl := getACLForSubjectWithGroups(t, opts, subject, issuer, []string{"some-org"}, []string{group}, wildcardRole, exactRole, groupRole)

	if acl.Organizations != nil || acl.Organization != nil {
		t.Fatalf("replace semantics violated: membership resolution ran: %+v", acl)
	}

	if acl.Global == nil {
		t.Fatal("no global ACL granted")
	}

	byName := map[string][]openapi.AclOperation{}
	for _, e := range *acl.Global {
		byName[e.Name] = e.Operations
	}

	// Wildcard leg: clamped to read.
	if !reflect.DeepEqual(byName["identity:organizations"], []openapi.AclOperation{openapi.Read}) {
		t.Fatalf("wildcard leg not clamped: %+v", byName)
	}

	// Exact subject leg: full verbs, unclamped.
	if len(byName["identity:groups"]) != 2 {
		t.Fatalf("exact subject leg missing full verbs: %+v", byName)
	}

	// Group leg: full verbs including a write operation, unclamped. This is the
	// property under test.
	want := []openapi.AclOperation{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}
	if !reflect.DeepEqual(byName["identity:users"], want) {
		t.Fatalf("group leg not full/unclamped: got %+v, want %+v", byName["identity:users"], want)
	}
}

// TestUnmatchedGroupsLoggedEvenWhenSubjectBindingMatched pins that the
// unmatched-groups diagnostic fires whenever the token carried groups and none
// of them matched a group binding. It fires even when a SUBJECT binding matched
// and accumulateMatchedBindings returns early with a global ACL. Without the
// hoisted check, an operator who adds a group binding for someone who already
// has an exact subject binding would get a silently missing grant, and no
// diagnostic at all.
func TestUnmatchedGroupsLoggedEvenWhenSubjectBindingMatched(t *testing.T) {
	t.Parallel()

	const (
		issuer  = "https://staff.example.com/"
		subject = "boss@x.com"
	)

	opts := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: issuer, Subject: subject, RoleIDs: []string{"admin"}},
		},
		// No matching GlobalGroupRoleBindings entry for "unmapped-group".
	}

	var lines []string

	logger := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{})
	ctx := log.IntoContext(t.Context(), logger)

	acl, err := aclOrErrForSubjectWithContext(ctx, t, opts, subject, issuer, nil, []string{"unmapped-group"})
	if err != nil {
		t.Fatalf("GetACL: %v", err)
	}

	// The subject binding still granted its ACL. The diagnostic is additive, not
	// a substitute for the grant.
	if acl.Global == nil {
		t.Fatal("matched subject binding granted no global ACL")
	}

	var found bool

	for _, l := range lines {
		if strings.Contains(l, "token groups matched no global group role binding") {
			found = true

			if !strings.Contains(l, "unmapped-group") {
				t.Fatalf("unmatched-groups log missing the groups field: %q", l)
			}
		}
	}

	if !found {
		t.Fatal("expected unmatched-groups diagnostic even though a subject binding matched")
	}
}

// TestGlobalRoleBindingsMatchedLogRecordsExerciseDetail pins the content of the
// "global role bindings matched" log line that accumulateMatchedBindings emits.
// Group membership lives in the IdP, outside this system, so this line is the
// only record anywhere of who exercised global authority through a group, and
// why. It must carry the subject, the issuer, the matched binding identities, the
// role IDs each one granted, and the count of organization memberships that
// replace semantics skipped.
//
// The fixture matches both a subject binding and a group binding on the same
// principal, so it exercises both describeSubjectBindings and
// describeGroupBindings. It also supplies a non-empty authz.OrgIds, so the
// skipped count is a real number rather than a vacuous zero.
func TestGlobalRoleBindingsMatchedLogRecordsExerciseDetail(t *testing.T) {
	t.Parallel()

	const (
		issuer  = "https://staff.example.com/"
		subject = "boss@x.com"
		group   = "Platform Engineering"
	)

	opts := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: issuer, Subject: subject, RoleIDs: []string{"admin"}},
		},
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: issuer, Group: group, RoleIDs: []string{"admin"}},
		},
	}

	var lines []string

	logger := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{})
	ctx := log.IntoContext(t.Context(), logger)

	acl, err := aclOrErrForSubjectWithContext(ctx, t, opts, subject, issuer, []string{"org-a", "org-b"}, []string{group})
	if err != nil {
		t.Fatalf("GetACL: %v", err)
	}

	// The exercise log is additive. It is not a substitute for the grant.
	if acl.Global == nil {
		t.Fatal("matched bindings granted no global ACL")
	}

	var found bool

	for _, l := range lines {
		if !strings.Contains(l, "global role bindings matched") {
			continue
		}

		found = true

		for _, want := range []string{
			subject,
			issuer,
			"subject " + subject + " -> admin", // describeSubjectBindings
			"group " + group + " -> admin",     // describeGroupBindings
			"organizationMembershipsSkipped\"=2",
		} {
			if !strings.Contains(l, want) {
				t.Fatalf("exercise log missing %q: %q", want, l)
			}
		}
	}

	if !found {
		t.Fatal("expected a \"global role bindings matched\" exercise log line")
	}
}
