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

	got := []rbac.PlatformAdministratorSubject(v)
	want := []rbac.PlatformAdministratorSubject{
		// stored verbatim — no lowercasing or trailing-slash stripping
		{Issuer: "https://Staff.Auth0.com/", Subject: "admin@nscale.com"},
		{Issuer: constants.UNISentinel, Subject: "legacy@nscale.com"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// getACLForSubject builds a minimal RBAC environment with the given opts and
// calls GetACL for the given subject+srcIss pair. It returns the resulting ACL.
func getACLForSubject(t *testing.T, opts *rbac.Options, subject, srcIss string) *openapi.Acl {
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

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(adminRole).Build()
	rbacClient := rbac.New(c, testNamespace, opts)

	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
			},
		},
		SrcIss: srcIss,
	}

	ctx := authorization.NewContext(t.Context(), info)

	acl, err := rbacClient.GetACL(ctx, "")
	if err != nil {
		t.Fatalf("GetACL: %v", err)
	}

	return acl
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

// TestAdminFastPathCaseInsensitiveSubject verifies that the platform-admin
// fast-path matches regardless of case differences between the admin-list
// entry subject and the (lowercased) token subject.
func TestAdminFastPathCaseInsensitiveSubject(t *testing.T) {
	t.Parallel()

	const staffIss = "https://staff.auth0.com"

	tests := []struct {
		name         string
		entrySubject string // as operator typed in the admin list
		tokenSubject string // as it arrives from the validator (lowercased+trimmed)
		wantAdminACL bool
	}{
		{
			name:         "mixed-case entry matches lowercased token subject",
			entrySubject: "Admin@Nscale.Com",
			tokenSubject: "admin@nscale.com",
			wantAdminACL: true,
		},
		{
			name:         "lowercased entry matches mixed-case token subject",
			entrySubject: "admin@nscale.com",
			tokenSubject: "Admin@Nscale.Com",
			wantAdminACL: true,
		},
		{
			name:         "non-matching subject is denied even after normalisation",
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

	// a non-UNI trusted issuer exists AND a bare admin entry → refuse.
	if err := opts.Validate([]string{"https://staff.auth0.com"}); err == nil {
		t.Fatal("expected migration-gate error, got nil")
	}

	// no non-UNI issuer → fine.
	if err := opts.Validate(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
