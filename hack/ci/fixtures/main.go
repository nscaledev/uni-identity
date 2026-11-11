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

// integration-fixtures bootstraps the minimum test resources for integration tests.
// It uses controller-runtime to issue an mTLS client certificate, then
// calls the identity HTTP API via the generated OpenAPI client to create:
//   - two Organizations: one test org and one non-member org
//   - three Groups: "administrator", "user", and "auditor"
//   - a Project (members: both groups)
//   - a user in the user group, yielding a federated bearer token
//   - ServiceAccounts for admin, user, and audit groups, each yielding a distinct bearer token
//
// The resulting tokens exercise both org-scoped (administrator) and
// project-scoped (user) RBAC paths in the main integration suite.
//
// Writes a .env fragment to stdout for consumption by the Ginkgo test suite.
//
//nolint:forbidigo // stdout output is intentional for .env generation
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/unikorn-cloud/identity/hack/ci/internal/fixturelib"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func issueUserToken(ctx context.Context, k8s client.Client, namespace, baseURL, subject, globalUserID string) string {
	issuer := handlercommon.IssuerValue{}
	if err := issuer.Set(baseURL); err != nil {
		fixturelib.Fatalf("failed to parse issuer %q: %v", baseURL, err)
	}

	jwtIssuer := jose.NewJWTIssuer(k8s, k8s, namespace, &jose.Options{})
	authenticator, err := oauth2.New(&oauth2.Options{
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
		TokenCacheSize:       8192,
	}, namespace, issuer, k8s, k8s, jwtIssuer, nil)

	if err != nil {
		fixturelib.Fatalf("failed to create authenticator: %v", err)
	}

	tokens, err := authenticator.Issue(ctx, &oauth2.IssueInfo{
		Issuer:   issuer.URL,
		Audience: issuer.Hostname,
		Subject:  subject,
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			Provider: "ci-fixtures",
			ClientID: "ci-fixtures",
			UserID:   globalUserID,
			Scope:    oauth2.NewScope("openid email profile"),
		},
		Interactive: true,
	})
	if err != nil {
		fixturelib.Fatalf("failed to issue user token for %q: %v", subject, err)
	}

	return tokens.AccessToken
}

func main() {
	baseURL := flag.String("base-url", os.Getenv("IDENTITY_BASE_URL"), "Identity service base URL")
	namespace := flag.String("namespace", os.Getenv("IDENTITY_NAMESPACE"), "Kubernetes namespace where identity is deployed")
	caCertPath := flag.String("ca-cert", os.Getenv("IDENTITY_CA_CERT"), "Path to CA certificate bundle")
	flag.Parse()

	if *baseURL == "" || *namespace == "" || *caCertPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: fixtures --base-url URL --namespace NS --ca-cert PATH")
		os.Exit(1)
	}

	// Resolve CA cert path to absolute so the .env can be read from any working directory.
	absCACertPath, err := filepath.Abs(*caCertPath)
	if err != nil {
		fixturelib.Fatalf("failed to resolve CA cert path: %v", err)
	}

	caCertPath = &absCACertPath

	ctx := context.Background()

	// Build a controller-runtime client using the in-cluster or KUBECONFIG credentials.
	cfg, err := config.GetConfig()
	if err != nil {
		fixturelib.Fatalf("failed to get kubeconfig: %v", err)
	}

	k8s, err := client.New(cfg, client.Options{Scheme: fixturelib.NewClientScheme()})
	if err != nil {
		fixturelib.Fatalf("failed to create Kubernetes client: %v", err)
	}

	// Issue mTLS client cert for ci-fixtures. The CN maps directly to the
	// platform-administrator system account — no token exchange required.
	fixturelib.Logf("Issuing mTLS client certificate for ci-fixtures...")

	certPEM, keyPEM := fixturelib.IssueCert(ctx, k8s, *namespace, "ci-fixtures", "ci-fixtures")

	ac := fixturelib.NewAPIClient(*baseURL, *caCertPath, certPEM, keyPEM)

	// ── Create Organizations ─────────────────────────────────────────────────
	orgID := fixturelib.CreateOrganization(ctx, ac, k8s, *namespace, "ci-test-org")

	// A second org that test identities are not members of.
	// Used by non-member authorization tests (UNAUTHORISED_ORG_ID).
	unauthorisedOrgID := fixturelib.CreateOrganization(ctx, ac, k8s, *namespace, fmt.Sprintf("ci-unauthorised-org-%d", time.Now().UnixNano()))

	// ── Resolve role IDs ─────────────────────────────────────────────────────
	// platform-administrator is protected and not returned by the API.
	// We use administrator (org-scoped identity CRUD, minus oauth2provider writes) and
	// user (project-scoped).
	administratorRoleID, userRoleID, auditRoleID := fixturelib.ResolveRoles(ctx, ac, orgID)

	// ── Create Groups ─────────────────────────────────────────────────────────
	// ci-admin-group: organization administrator — identity CRUD at org scope, except
	// oauth2providers, which is read-only.
	adminGroupID := fixturelib.CreateGroup(ctx, ac, orgID, "ci-admin-group", []string{administratorRoleID})

	// ci-user-group: project user — project-scoped access only.
	userGroupID := fixturelib.CreateGroup(ctx, ac, orgID, "ci-user-group", []string{userRoleID})

	// ── Create Project ────────────────────────────────────────────────────────
	// Both groups are members so both service accounts can access project endpoints.
	projectID := fixturelib.CreateProject(ctx, ac, orgID, "ci-test-project", []string{adminGroupID, userGroupID})

	// ── Create user and ServiceAccounts ───────────────────────────────────────
	const ciFixtureUserSubject = "ci-user@nscale.test"

	adminSAID, adminToken := fixturelib.CreateServiceAccount(ctx, ac, orgID, "ci-admin-sa", []string{adminGroupID})
	userSAID, serviceAccountToken := fixturelib.CreateServiceAccount(ctx, ac, orgID, "ci-user-sa", []string{userGroupID})
	auditGroupID := fixturelib.CreateGroup(ctx, ac, orgID, "ci-audit-group", []string{auditRoleID})
	_, auditToken := fixturelib.CreateServiceAccount(ctx, ac, orgID, "ci-audit-sa", []string{auditGroupID})

	userID := fixturelib.CreateUser(ctx, ac, orgID, ciFixtureUserSubject, []string{userGroupID})
	userGlobalID := fixturelib.FindGlobalUserID(ctx, k8s, *namespace, ciFixtureUserSubject)
	userToken := issueUserToken(ctx, k8s, *namespace, *baseURL, ciFixtureUserSubject, userGlobalID)

	// ── Create identities bound via the legacy and new global admin paths ─────
	// Each subject is pre-bound in hack/ci/test-values.yaml: legacyAdminSubject
	// via platformAdministrators.subjects, bindingAdminSubject via
	// globalRoleBindings. Used to prove the two paths grant equivalent authority.
	const (
		legacyAdminSubject  = "ci-legacy-admin@nscale.test"
		bindingAdminSubject = "ci-binding-admin@nscale.test"
	)

	// legacyAdminSubject's authority comes entirely from the legacy
	// platformAdministrators.subjects binding, so it needs no group membership
	// at all; userSpec.groupIDs has no minItems constraint and updateGroups
	// tolerates an empty list, so this is a supported shape, not a workaround.
	fixturelib.CreateUser(ctx, ac, orgID, legacyAdminSubject, []string{})
	legacyAdminToken := issueUserToken(ctx, k8s, *namespace, *baseURL, legacyAdminSubject,
		fixturelib.FindGlobalUserID(ctx, k8s, *namespace, legacyAdminSubject))

	// ci-bound-admin-group: dedicated group for bindingAdminSubject, kept
	// separate from ci-user-group so its org membership doesn't inflate
	// TEST_USER_GROUP_ID's UserIDs/Subjects (see groups_test.go's fixture
	// assertions). bindingAdminSubject must remain an organization member (via
	// this group) so the replace-semantics assertion in
	// global_role_bindings_test.go — that the resolved ACL is Global-only with
	// Organizations nil, not both — is non-vacuous.
	boundAdminGroupID := fixturelib.CreateGroup(ctx, ac, orgID, "ci-bound-admin-group", []string{userRoleID})

	fixturelib.CreateUser(ctx, ac, orgID, bindingAdminSubject, []string{boundAdminGroupID})
	bindingAdminToken := issueUserToken(ctx, k8s, *namespace, *baseURL, bindingAdminSubject,
		fixturelib.FindGlobalUserID(ctx, k8s, *namespace, bindingAdminSubject))

	// ci-platform-reader: bound to the protected platform-reader role via an
	// exact uni binding in hack/ci/test-values.yaml. Like legacyAdminSubject,
	// it needs no group membership — its authority comes entirely from the
	// binding.
	const platformReaderSubject = "ci-platform-reader@nscale.test"

	fixturelib.CreateUser(ctx, ac, orgID, platformReaderSubject, []string{})
	platformReaderToken := issueUserToken(ctx, k8s, *namespace, *baseURL, platformReaderSubject,
		fixturelib.FindGlobalUserID(ctx, k8s, *namespace, platformReaderSubject))

	// Protected roles are invisible through the API by design, so the role ID
	// for the non-grantability test is resolved from the Role CRD by its
	// unikorn-cloud.org/name label.
	platformReaderRoleID := fixturelib.FindRoleID(ctx, k8s, *namespace, "platform-reader")

	// ── Output .env fragment to stdout ────────────────────────────────────────
	fmt.Printf("IDENTITY_BASE_URL=%s\n", *baseURL)
	fmt.Printf("IDENTITY_CA_CERT=%s\n", *caCertPath)
	fmt.Printf("TEST_ORG_ID=%s\n", orgID)
	fmt.Printf("UNAUTHORISED_ORG_ID=%s\n", unauthorisedOrgID)
	fmt.Printf("TEST_PROJECT_ID=%s\n", projectID)
	fmt.Printf("API_AUTH_TOKEN=%s\n", adminToken)
	fmt.Printf("TEST_ADMIN_GROUP_ID=%s\n", adminGroupID)
	fmt.Printf("TEST_USER_GROUP_ID=%s\n", userGroupID)
	fmt.Printf("TEST_USER_ID=%s\n", userID)
	fmt.Printf("TEST_USER_SUBJECT_EMAIL=%s\n", ciFixtureUserSubject)
	fmt.Printf("TEST_ADMIN_SA_ID=%s\n", adminSAID)
	fmt.Printf("TEST_USER_SA_ID=%s\n", userSAID)
	fmt.Printf("ADMIN_AUTH_TOKEN=%s\n", adminToken)
	fmt.Printf("USER_AUTH_TOKEN=%s\n", userToken)
	fmt.Printf("SERVICE_ACCOUNT_TOKEN=%s\n", serviceAccountToken)
	fmt.Printf("AUDIT_AUTH_TOKEN=%s\n", auditToken)
	fmt.Printf("PLATFORM_ADMIN_AUTH_TOKEN=%s\n", legacyAdminToken)
	fmt.Printf("BINDING_ADMIN_AUTH_TOKEN=%s\n", bindingAdminToken)
	fmt.Printf("PLATFORM_READER_AUTH_TOKEN=%s\n", platformReaderToken)
	fmt.Printf("TEST_PLATFORM_READER_ROLE_ID=%s\n", platformReaderRoleID)
}
