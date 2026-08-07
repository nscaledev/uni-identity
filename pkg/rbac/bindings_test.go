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

	"github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		{"https://staff.example.com/", " BOSS@x.com ", []string{"*", "boss@x.com"}}, // exact match is EqualFold+TrimSpace; both match
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

	err := untrusted.Validate([]string{trustedIssuer})
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

	if err := trusted.Validate([]string{trustedIssuer}); err != nil {
		t.Fatalf("unexpected error for trusted issuer: %v", err)
	}

	// UNI sentinel issuer → skipped, never reported, even against an empty
	// trusted-issuer list.
	sentinel := &rbac.Options{
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: constants.UNISentinel, Subject: "alice@x.com", RoleIDs: []string{"r"}},
		},
	}

	if err := sentinel.Validate(nil); err != nil {
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

	err = both.Validate([]string{trustedIssuer})
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

	err = emptyTrustedList.Validate(nil)
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

	err := opts.Validate([]string{"https://staff.example.com/"})
	if !goerrors.Is(err, rbac.ErrUntrustedBindingIssuer) {
		t.Fatalf("got %v, want ErrUntrustedBindingIssuer", err)
	}

	if !strings.Contains(err.Error(), "untrusted-a.example.com") || !strings.Contains(err.Error(), "untrusted-b.example.com") {
		t.Fatalf("expected both offending issuers named in error, got: %v", err)
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

	// Direct same-role comparison (spec §5 "Tests"): binding the SAME role
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
