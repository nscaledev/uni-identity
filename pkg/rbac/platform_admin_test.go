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
	"context"
	"reflect"
	"testing"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPlatformAdminSubjectsValueParse(t *testing.T) {
	t.Parallel()

	var v rbac.PlatformAdministratorSubjectsValue
	if err := v.Set("https://Staff.Auth0.com/::admin@nscale.com"); err != nil {
		t.Fatal(err)
	}

	if err := v.Set("legacy@nscale.com"); err != nil { // bare → UNI sentinel
		t.Fatal(err)
	}

	// The chart renders every subject into a single comma-joined flag
	// (StringSliceVar heritage) — one Set call must yield one entry per
	// segment, mixed bare and qualified.
	if err := v.Set("mixed@nscale.com,https://other.example.com/::other@nscale.com"); err != nil {
		t.Fatal(err)
	}

	// The chart renders an empty subjects list as an empty flag value; it
	// must not become a phantom entry.
	if err := v.Set(""); err != nil {
		t.Fatal(err)
	}

	got := []rbac.PlatformAdministratorSubject(v)
	want := []rbac.PlatformAdministratorSubject{
		// stored verbatim — no lowercasing or trailing-slash stripping
		{Issuer: "https://Staff.Auth0.com/", Subject: "admin@nscale.com"},
		{Issuer: constants.UNISentinel, Subject: "legacy@nscale.com"},
		{Issuer: constants.UNISentinel, Subject: "mixed@nscale.com"},
		{Issuer: "https://other.example.com/", Subject: "other@nscale.com"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// getACLForSubject builds a minimal RBAC environment with the given opts and
// calls GetACL for the given subject+srcIss pair. It returns the resulting ACL.
// extraRoles are created alongside the fixed "admin" role fixture, letting
// tests that need additional role fixtures (e.g. wildcard-clamp/union
// scenarios) inject them without a bespoke fake-client setup.
func getACLForSubject(t *testing.T, opts *rbac.Options, subject, srcIss string, extraRoles ...*unikornv1.Role) *openapi.Acl {
	t.Helper()

	return getACLForSubjectWithOrgIDs(t, opts, subject, srcIss, nil, extraRoles...)
}

// getACLForSubjectWithOrgIDs is getACLForSubject with control over the
// authz.OrgIds claim, used to prove that a bound subject skips membership
// resolution entirely even when org memberships are present.
func getACLForSubjectWithOrgIDs(t *testing.T, opts *rbac.Options, subject, srcIss string, orgIDs []string, extraRoles ...*unikornv1.Role) *openapi.Acl {
	t.Helper()

	acl, err := aclOrErrForSubject(t, opts, subject, srcIss, orgIDs, nil, extraRoles...)

	return mustACL(t, acl, err)
}

// getACLForSubjectWithGroups is getACLForSubject with control over both the
// authz.OrgIds claim and the token's IdP groups, used to exercise group role
// binding matching (and its replace semantics) without disturbing the
// subject-only callers above.
func getACLForSubjectWithGroups(t *testing.T, opts *rbac.Options, subject, srcIss string, orgIDs, groups []string, extraRoles ...*unikornv1.Role) *openapi.Acl {
	t.Helper()

	acl, err := aclOrErrForSubject(t, opts, subject, srcIss, orgIDs, groups, extraRoles...)

	return mustACL(t, acl, err)
}

// mustACL fails the test if GetACL returned an error, otherwise returns the ACL.
func mustACL(t *testing.T, acl *openapi.Acl, err error) *openapi.Acl {
	t.Helper()

	if err != nil {
		t.Fatalf("GetACL: %v", err)
	}

	return acl
}

// aclOrErrForSubject is the common builder behind getACLForSubject and its
// variants: constructs a minimal RBAC environment and calls GetACL, returning
// the error rather than failing the test so a caller can assert on an
// expected error path (e.g. proving membership resolution actually ran
// against a fake client with no organization fixtures, when no binding
// matched).
func aclOrErrForSubject(t *testing.T, opts *rbac.Options, subject, srcIss string, orgIDs, groups []string, extraRoles ...*unikornv1.Role) (*openapi.Acl, error) {
	t.Helper()

	return aclOrErrForSubjectWithContext(t.Context(), t, opts, subject, srcIss, orgIDs, groups, extraRoles...)
}

// aclOrErrForSubjectWithContext is aclOrErrForSubject with control over the
// base context, used to inject a capturing logger (via log.IntoContext)
// without disturbing the fixed-context callers above.
func aclOrErrForSubjectWithContext(baseCtx context.Context, t *testing.T, opts *rbac.Options, subject, srcIss string, orgIDs, groups []string, extraRoles ...*unikornv1.Role) (*openapi.Acl, error) {
	t.Helper()

	scheme, err := unikornv1.SchemeBuilder.Build()
	if err != nil {
		t.Fatal(err)
	}

	adminRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "admin",
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "org:manage", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
				},
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(adminRole)

	for _, r := range extraRoles {
		builder = builder.WithObjects(r)
	}

	c := builder.Build()
	rbacClient := rbac.New(c, testNamespace, opts)

	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  orgIDs,
			},
		},
		SrcIss: srcIss,
		Groups: groups,
	}

	ctx := authorization.NewContext(baseCtx, info)

	return rbacClient.GetACL(ctx, "")
}

// aclGrantsGlobalAdmin returns true if the ACL has any global endpoints (indicative of the
// platform-admin fast-path having fired).
func aclGrantsGlobalAdmin(acl *openapi.Acl) bool {
	return acl.Global != nil && len(*acl.Global) > 0
}

func TestAdminFastPathIsIssuerAware(t *testing.T) {
	t.Parallel()

	// admin entry expected from the staff issuer
	opts := &rbac.Options{
		PlatformAdministratorRoleIDs: []string{"admin"},
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
			{Issuer: "https://staff.auth0.com", Subject: "admin@nscale.com"},
		},
	}

	// a token with the SAME subject but a DIFFERENT (weaker) issuer must NOT
	// get the global admin ACL (confused-deputy denied).
	acl := getACLForSubject(t, opts, "admin@nscale.com", "https://customer.auth0.com")
	if aclGrantsGlobalAdmin(acl) {
		t.Fatal("confused deputy: customer-issuer token got platform admin")
	}

	// the legitimate staff-issuer token DOES get it.
	acl = getACLForSubject(t, opts, "admin@nscale.com", "https://staff.auth0.com")
	if !aclGrantsGlobalAdmin(acl) {
		t.Fatal("legitimate staff admin denied")
	}
}

// TestAdminFastPathIssuerSlashSensitive is the core safety property of verbatim
// issuer matching: an admin entry configured without a trailing slash must NOT
// match a token whose src_iss carries one (and vice versa). The issuer is matched
// exactly, as the IdP emits it — no normalization.
func TestAdminFastPathIssuerSlashSensitive(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{
		PlatformAdministratorRoleIDs: []string{"admin"},
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
			{Issuer: "https://staff.auth0.com", Subject: "admin@nscale.com"},
		},
	}

	// token src_iss differs only by a trailing slash → must be denied.
	acl := getACLForSubject(t, opts, "admin@nscale.com", "https://staff.auth0.com/")
	if aclGrantsGlobalAdmin(acl) {
		t.Fatal("slash-mismatched issuer granted platform admin")
	}

	// exact match → granted.
	acl = getACLForSubject(t, opts, "admin@nscale.com", "https://staff.auth0.com")
	if !aclGrantsGlobalAdmin(acl) {
		t.Fatal("exact-match issuer denied")
	}
}

// TestAdminFastPathRequiresServerSideGrant verifies the eligibility-vs-authority
// split: the IdP-asserted authz claim (Acctype: User) is present in BOTH cases
// below, yet global-admin authority is conferred ONLY by a server-side
// PlatformAdministratorSubjects grant for the same (issuer, subject). Removing
// the grant revokes admin — the claim alone never confers it. This varies grant
// presence for a fixed identity, a different axis from TestAdminFastPathIsIssuerAware
// (which varies the issuer for a fixed grant).
func TestAdminFastPathRequiresServerSideGrant(t *testing.T) {
	t.Parallel()

	const (
		staffIss = "https://staff.auth0.com"
		subject  = "operator@nscale.com"
	)

	// No server-side grant: the eligibility claim is present but confers nothing.
	noGrant := &rbac.Options{
		PlatformAdministratorRoleIDs:  []string{"admin"},
		PlatformAdministratorSubjects: nil,
	}

	acl := getACLForSubject(t, noGrant, subject, staffIss)
	if aclGrantsGlobalAdmin(acl) {
		t.Fatal("eligibility claim alone granted platform admin without a server-side grant")
	}

	// Same subject and issuer, now with the server-side grant → admin. Adding/
	// removing this entry is the (revocable) authority decision.
	withGrant := &rbac.Options{
		PlatformAdministratorRoleIDs: []string{"admin"},
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
			{Issuer: staffIss, Subject: subject},
		},
	}

	acl = getACLForSubject(t, withGrant, subject, staffIss)
	if !aclGrantsGlobalAdmin(acl) {
		t.Fatal("server-side grant did not confer platform admin")
	}
}

// TestAdminFastPathCaseSensitiveSubject verifies that the platform-admin
// fast-path requires the admin-list entry subject to match the (lowercased,
// trimmed) token subject exactly, including case. The validator already
// normalizes the token subject to lower case, so an admin-list entry typed
// in any other case is a configuration mistake, not an alternate spelling —
// it must not match.
func TestAdminFastPathCaseSensitiveSubject(t *testing.T) {
	t.Parallel()

	const staffIss = "https://staff.auth0.com"

	tests := []struct {
		name         string
		entrySubject string // as operator typed in the admin list
		tokenSubject string // as it arrives from the validator (lowercased+trimmed)
		wantAdminACL bool
	}{
		{
			name:         "exact-case entry matches lowercased token subject",
			entrySubject: "admin@nscale.com",
			tokenSubject: "admin@nscale.com",
			wantAdminACL: true,
		},
		{
			name:         "mixed-case entry does not match lowercased token subject",
			entrySubject: "Admin@Nscale.Com",
			tokenSubject: "admin@nscale.com",
			wantAdminACL: false,
		},
		{
			name:         "lowercased entry does not match mixed-case token subject",
			entrySubject: "admin@nscale.com",
			tokenSubject: "Admin@Nscale.Com",
			wantAdminACL: false,
		},
		{
			name:         "non-matching subject is denied",
			entrySubject: "Admin@Nscale.Com",
			tokenSubject: "other@nscale.com",
			wantAdminACL: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := &rbac.Options{
				PlatformAdministratorRoleIDs: []string{"admin"},
				PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
					{Issuer: staffIss, Subject: tc.entrySubject},
				},
			}

			acl := getACLForSubject(t, opts, tc.tokenSubject, staffIss)
			if aclGrantsGlobalAdmin(acl) != tc.wantAdminACL {
				t.Fatalf("wantAdminACL=%v but got ACL global=%v", tc.wantAdminACL, acl.Global)
			}
		})
	}
}

func TestOptionsValidateMigrationGate(t *testing.T) {
	t.Parallel()

	opts := &rbac.Options{
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{
			{Issuer: constants.UNISentinel, Subject: "bare@nscale.com"}, // bare form
		},
	}

	// a non-UNI trusted issuer exists AND a bare admin entry → report.
	if err := opts.Validate([]string{"https://staff.auth0.com"}, nil); err == nil {
		t.Fatal("expected migration-gate error, got nil")
	}

	// no non-UNI issuer → fine.
	if err := opts.Validate(nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
