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
//   - an Organization
//   - two Groups: one with the "administrator" role, one with the "user" role
//   - a Project (members: both groups)
//   - two ServiceAccounts: one per group, each yielding a distinct bearer token
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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "==> "+format+"\n", args...)
}

// issueCert creates a cert-manager Certificate via controller-runtime and
// waits for the backing Secret to be ready. Returns the cert and key PEM bytes.
func issueCert(ctx context.Context, k8s client.Client, namespace, name, cn string) ([]byte, []byte) {
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "cert-manager.io",
		Version: "v1",
		Kind:    "Certificate",
	})
	cert.SetNamespace(namespace)
	cert.SetName(name)
	cert.Object["spec"] = map[string]interface{}{
		"secretName": name + "-tls",
		"commonName": cn,
		"duration":   "1h",
		"issuerRef": map[string]interface{}{
			"name":  "unikorn-client-issuer",
			"kind":  "ClusterIssuer",
			"group": "cert-manager.io",
		},
	}

	if err := k8s.Create(ctx, cert); client.IgnoreAlreadyExists(err) != nil {
		fatalf("failed to create Certificate %s: %v", name, err)
	}

	logf("Waiting for Certificate %s/%s to be ready...", namespace, name)

	key := types.NamespacedName{Namespace: namespace, Name: name}

	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		current := &unstructured.Unstructured{}
		current.SetGroupVersionKind(cert.GroupVersionKind())

		if err := k8s.Get(ctx, key, current); err != nil {
			return false, nil //nolint:nilerr
		}

		conditions, _, _ := unstructured.NestedSlice(current.Object, "status", "conditions")

		for _, c := range conditions {
			m, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			if m["type"] == "Ready" && m["status"] == "True" {
				return true, nil
			}
		}

		return false, nil
	}); err != nil {
		fatalf("Certificate %s/%s not ready: %v", namespace, name, err)
	}

	secret := &corev1.Secret{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name + "-tls"}, secret); err != nil {
		fatalf("failed to read Secret %s-tls: %v", name, err)
	}

	return secret.Data["tls.crt"], secret.Data["tls.key"]
}

// newAPIClient builds an openapi.ClientWithResponses that authenticates via mTLS.
// The certificate CN maps directly to an RBAC role — no bearer token is needed.
// An X-Principal header is injected on every request as required by the middleware.
func newAPIClient(baseURL, caCertPath string, certPEM, keyPEM []byte) *openapi.ClientWithResponses {
	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		fatalf("failed to read CA cert: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		fatalf("failed to parse CA cert")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fatalf("failed to parse mTLS key pair: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
			},
		},
		Timeout: 30 * time.Second,
	}

	// The middleware requires an X-Principal header: base64url-encoded JSON of
	// principal.Principal. The actor "ci-fixtures" maps to the platform-administrator role.
	principalJSON, err := json.Marshal(map[string]string{"actor": "ci-fixtures"})
	if err != nil {
		fatalf("failed to marshal principal: %v", err)
	}

	principalHeader := base64.RawURLEncoding.EncodeToString(principalJSON)

	principalEditor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("X-Principal", principalHeader)

		return nil
	}

	ac, err := openapi.NewClientWithResponses(baseURL,
		openapi.WithHTTPClient(httpClient),
		openapi.WithRequestEditorFn(principalEditor),
	)
	if err != nil {
		fatalf("failed to create API client: %v", err)
	}

	return ac
}

// findRole returns the ID of a named role within an organization.
// platform-administrator and other protected roles are excluded from the API response.
func findRole(roles *openapi.RolesResponse, name string) string {
	if roles == nil {
		return ""
	}

	for _, r := range *roles {
		if r.Metadata.Name == name {
			return r.Metadata.Id
		}
	}

	return ""
}

// createGroup creates a group with the given role IDs assigned.
func createGroup(ctx context.Context, ac *openapi.ClientWithResponses, orgID, name string, roleIDs []string) string {
	logf("Creating group %q...", name)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDGroupsWithResponse(ctx, orgID, openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec: openapi.GroupSpec{
			RoleIDs:           roleIDs,
			ServiceAccountIDs: openapi.StringList{},
		},
	})
	if err != nil {
		fatalf("failed to create group %q: %v", name, err)
	}

	if resp.JSON201 == nil {
		fatalf("create group %q returned %s", name, resp.Status())
	}

	id := resp.JSON201.Metadata.Id
	logf("  group %q ID: %s", name, id)

	return id
}

// createProject creates a project with the given group memberships and returns its ID.
func createProject(ctx context.Context, ac *openapi.ClientWithResponses, orgID, name string, groupIDs []string) string {
	logf("Creating project %q...", name)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDProjectsWithResponse(ctx, orgID, openapi.ProjectWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec:     openapi.ProjectSpec{GroupIDs: groupIDs},
	})
	if err != nil {
		fatalf("failed to create project %q: %v", name, err)
	}

	if resp.JSON202 == nil {
		fatalf("create project %q returned %s", name, resp.Status())
	}

	id := resp.JSON202.Metadata.Id
	logf("  project %q ID: %s", name, id)

	return id
}

// createUser creates a user in the given groups and returns its ID.
func createUser(ctx context.Context, ac *openapi.ClientWithResponses, orgID, subject string, groupIDs []string) string {
	logf("Creating user %q...", subject)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDUsersWithResponse(ctx, orgID, openapi.UserWrite{
		Spec: openapi.UserSpec{
			Subject:  subject,
			State:    openapi.Active,
			GroupIDs: groupIDs,
		},
	})
	if err != nil {
		fatalf("failed to create user %q: %v", subject, err)
	}

	if resp.JSON201 == nil {
		fatalf("create user %q returned %s", subject, resp.Status())
	}

	id := resp.JSON201.Metadata.Id
	logf("  user %q ID: %s", subject, id)

	return id
}

// writeCertFiles writes the cert and key PEM to disk next to the CA bundle so
// the integration suite can load them via IDENTITY_IMPERSONATE_CLIENT_*_PATH.
// Paths are returned absolute.
func writeCertFiles(caCertPath string, certPEM, keyPEM []byte) (string, string) {
	dir := filepath.Dir(caCertPath)

	certPath := filepath.Join(dir, "impersonator-cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		fatalf("failed to write impersonator cert: %v", err)
	}

	keyPath := filepath.Join(dir, "impersonator-key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		fatalf("failed to write impersonator key: %v", err)
	}

	absCert, err := filepath.Abs(certPath)
	if err != nil {
		fatalf("failed to resolve impersonator cert path: %v", err)
	}

	absKey, err := filepath.Abs(keyPath)
	if err != nil {
		fatalf("failed to resolve impersonator key path: %v", err)
	}

	return absCert, absKey
}

// createServiceAccount creates a service account in the given groups and returns its ID and token.
func createServiceAccount(ctx context.Context, ac *openapi.ClientWithResponses, orgID, name string, groupIDs []string) (string, string) {
	logf("Creating service account %q...", name)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDServiceaccountsWithResponse(ctx, orgID, openapi.ServiceAccountWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec:     openapi.ServiceAccountSpec{GroupIDs: groupIDs},
	})
	if err != nil {
		fatalf("failed to create service account %q: %v", name, err)
	}

	if resp.JSON201 == nil {
		fatalf("create service account %q returned %s", name, resp.Status())
	}

	id := resp.JSON201.Metadata.Id
	token := ""

	if resp.JSON201.Status.AccessToken != nil {
		token = *resp.JSON201.Status.AccessToken
	}

	logf("  service account %q ID: %s", name, id)

	return id, token
}

// waitForOrgNamespace polls until the organization controller has provisioned the backing namespace.
func waitForOrgNamespace(ctx context.Context, k8s client.Client, namespace, orgID string) {
	logf("Waiting for Organization %s to be provisioned...", orgID)

	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		org := &unstructured.Unstructured{}
		org.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "identity.unikorn-cloud.org",
			Version: "v1alpha1",
			Kind:    "Organization",
		})

		if err := k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: orgID}, org); err != nil {
			return false, nil //nolint:nilerr
		}

		ns, _, _ := unstructured.NestedString(org.Object, "status", "namespace")

		return ns != "", nil
	}); err != nil {
		fatalf("Organization %s not provisioned: %v", orgID, err)
	}
}

// resolveRoles lists the organization roles and returns the IDs for administrator and user.
func resolveRoles(ctx context.Context, ac *openapi.ClientWithResponses, orgID string) (string, string) {
	logf("Resolving role IDs...")

	rolesResp, err := ac.GetApiV1OrganizationsOrganizationIDRolesWithResponse(ctx, orgID)
	if err != nil {
		fatalf("failed to list roles: %v", err)
	}

	if rolesResp.JSON200 == nil {
		fatalf("list roles returned %s", rolesResp.Status())
	}

	administratorRoleID := findRole(rolesResp.JSON200, "administrator")
	if administratorRoleID == "" {
		fatalf("administrator role not found in org %s", orgID)
	}

	userRoleID := findRole(rolesResp.JSON200, "user")
	if userRoleID == "" {
		fatalf("user role not found in org %s", orgID)
	}

	logf("  administrator role ID: %s", administratorRoleID)
	logf("  user role ID: %s", userRoleID)

	return administratorRoleID, userRoleID
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
		fatalf("failed to resolve CA cert path: %v", err)
	}

	caCertPath = &absCACertPath

	ctx := context.Background()

	// Build a controller-runtime client using the in-cluster or KUBECONFIG credentials.
	cfg, err := config.GetConfig()
	if err != nil {
		fatalf("failed to get kubeconfig: %v", err)
	}

	k8s, err := client.New(cfg, client.Options{})
	if err != nil {
		fatalf("failed to create Kubernetes client: %v", err)
	}

	// Issue mTLS client cert for ci-fixtures. The CN maps directly to the
	// platform-administrator system account — no token exchange required.
	logf("Issuing mTLS client certificate for ci-fixtures...")

	certPEM, keyPEM := issueCert(ctx, k8s, *namespace, "ci-fixtures", "ci-fixtures")

	ac := newAPIClient(*baseURL, *caCertPath, certPEM, keyPEM)

	// ── Create Organization ──────────────────────────────────────────────────
	logf("Creating test Organization...")

	orgResp, err := ac.PostApiV1OrganizationsWithResponse(ctx, openapi.OrganizationWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: "ci-test-org"},
		Spec:     openapi.OrganizationSpec{OrganizationType: openapi.Adhoc},
	})
	if err != nil {
		fatalf("failed to create Organization: %v", err)
	}

	if orgResp.JSON202 == nil {
		fatalf("create Organization returned %s", orgResp.Status())
	}

	orgID := orgResp.JSON202.Metadata.Id
	logf("  Organization ID: %s", orgID)

	// Wait for the organization controller to provision the backing namespace.
	waitForOrgNamespace(ctx, k8s, *namespace, orgID)

	// ── Resolve role IDs ─────────────────────────────────────────────────────
	// platform-administrator is protected and not returned by the API.
	// We use administrator (org-scoped, full identity CRUD) and user (project-scoped).
	administratorRoleID, userRoleID := resolveRoles(ctx, ac, orgID)

	// ── Create Groups ─────────────────────────────────────────────────────────
	// ci-admin-group: organization administrator — full identity CRUD at org scope.
	adminGroupID := createGroup(ctx, ac, orgID, "ci-admin-group", []string{administratorRoleID})

	// ci-user-group: project user — project-scoped access only.
	userGroupID := createGroup(ctx, ac, orgID, "ci-user-group", []string{userRoleID})

	// ── Create Project ────────────────────────────────────────────────────────
	// Both groups are members so both service accounts can access project endpoints.
	projectID := createProject(ctx, ac, orgID, "ci-test-project", []string{adminGroupID, userGroupID})

	// ── Create ServiceAccounts ────────────────────────────────────────────────
	adminSAID, adminToken := createServiceAccount(ctx, ac, orgID, "ci-admin-sa", []string{adminGroupID})
	userSAID, userToken := createServiceAccount(ctx, ac, orgID, "ci-user-sa", []string{userGroupID})

	// ── Impersonation fixtures ────────────────────────────────────────────────
	// Issue a second mTLS cert for the impersonation system account. Its CN
	// (ci-impersonator) maps to ci-impersonator-role in test-values.yaml.
	// The passport-exchange integration suite uses this cert to call
	// /oauth2/v2/exchange with X-Impersonate: true.
	logf("Issuing mTLS client certificate for ci-impersonator...")

	imperCertPEM, imperKeyPEM := issueCert(ctx, k8s, *namespace, "ci-impersonator", "ci-impersonator")
	imperCertPath, imperKeyPath := writeCertFiles(*caCertPath, imperCertPEM, imperKeyPEM)

	// Pre-provision a user in the org to be impersonated. Membership in
	// ci-user-group gives them a project-scoped ACL that will be intersected
	// with ci-impersonator-role's global read-only scope at exchange time.
	const impersonatedSubject = "ci-impersonated-user@example.com"
	impersonatedUserID := createUser(ctx, ac, orgID, impersonatedSubject, []string{userGroupID})

	// ── Output .env fragment to stdout ────────────────────────────────────────
	fmt.Printf("IDENTITY_BASE_URL=%s\n", *baseURL)
	fmt.Printf("IDENTITY_CA_CERT=%s\n", *caCertPath)
	fmt.Printf("TEST_ORG_ID=%s\n", orgID)
	fmt.Printf("TEST_PROJECT_ID=%s\n", projectID)
	fmt.Printf("API_AUTH_TOKEN=%s\n", adminToken)
	fmt.Printf("TEST_ADMIN_GROUP_ID=%s\n", adminGroupID)
	fmt.Printf("TEST_USER_GROUP_ID=%s\n", userGroupID)
	fmt.Printf("TEST_ADMIN_SA_ID=%s\n", adminSAID)
	fmt.Printf("TEST_USER_SA_ID=%s\n", userSAID)
	fmt.Printf("ADMIN_AUTH_TOKEN=%s\n", adminToken)
	fmt.Printf("USER_AUTH_TOKEN=%s\n", userToken)
	fmt.Printf("IDENTITY_IMPERSONATE_CLIENT_CERT_PATH=%s\n", imperCertPath)
	fmt.Printf("IDENTITY_IMPERSONATE_CLIENT_KEY_PATH=%s\n", imperKeyPath)
	fmt.Printf("TEST_IMPERSONATION_USER_ID=%s\n", impersonatedUserID)
	fmt.Printf("TEST_IMPERSONATION_USER_SUBJECT=%s\n", impersonatedSubject)
}
