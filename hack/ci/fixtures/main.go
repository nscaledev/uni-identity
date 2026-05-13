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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

var (
	errAuth0TokenEndpoint = errors.New("auth0 token endpoint returned non-200")
	errAuth0MissingToken  = errors.New("auth0 response missing access_token")
)

// auth0MintCreds bundles the OAuth client credentials and DB connection used
// to mint password-realm tokens against a single Auth0 tenant.
type auth0MintCreds struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Realm        string
	Scope        string
}

// auth0Mint executes a password-realm grant against Auth0 and returns the raw
// access_token. When audience is empty, Auth0 issues an opaque token tied to
// the user — used to drive the /userinfo fallback fixture.
func auth0Mint(ctx context.Context, creds auth0MintCreds, audience, username, password string) (string, error) {
	body := map[string]string{
		"grant_type":    "http://auth0.com/oauth/grant-type/password-realm",
		"client_id":     creds.ClientID,
		"client_secret": creds.ClientSecret,
		"username":      username,
		"password":      password,
		"realm":         creds.Realm,
		"scope":         creds.Scope,
	}

	if audience != "" {
		body["audience"] = audience
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	url := "https://" + strings.TrimRight(creds.Domain, "/") + "/oauth/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 15 * time.Second}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %s: %s", errAuth0TokenEndpoint, resp.Status, strings.TrimSpace(string(raw)))
	}

	var result struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // Auth0 token response field name is RFC 6749.
	}

	if err := json.Unmarshal(raw, &result); err != nil {
		return "", err
	}

	if result.AccessToken == "" {
		return "", errAuth0MissingToken
	}

	return result.AccessToken, nil
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}

	return def
}

// auth0Env captures every Auth0-related environment variable the fixture
// script consumes. Reading them once up front keeps the contract in one
// place and lets the per-fixture helpers stay pure.
//
// Tokens that are minted by this script (AUTH0_VALID_JWT_TOKEN,
// AUTH0_WRONG_AUDIENCE_JWT_TOKEN, AUTH0_WRONG_ISSUER_JWT_TOKEN,
// AUTH0_OPAQUE_TOKEN, AUTH0_INACTIVE_USER_JWT_TOKEN) are intentionally not
// read — Auth0 tokens expire and need re-minting every run.
//
// AUTH0_EXPIRED_JWT_TOKEN is the exception: once an Auth0 token has expired
// it stays expired indefinitely, so the operator seeds it once via the
// hack/auth0 helper and this script just passes the value through.
//
// Recognised environment variables:
//
//	AUTH0_DOMAIN                       tenant domain (e.g. nscale-dev.uk.auth0.com)
//	AUTH0_AUDIENCE                     primary audience (matches --auth0-audience)
//	AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET
//	AUTH0_REALM                        defaults to Username-Password-Authentication
//	AUTH0_SCOPE                        defaults to "openid profile email identity:token:exchange"
//	AUTH0_USERNAME                     active user; also written as AUTH0_EXPECTED_SUBJECT
//	AUTH0_PASSWORD
//	AUTH0_INACTIVE_USERNAME, AUTH0_INACTIVE_PASSWORD
//	AUTH0_WRONG_AUDIENCE               distinct audience on the same tenant
//	AUTH0_WRONG_ISSUER_DOMAIN          separate tenant for wrong-issuer fixture
//	AUTH0_WRONG_ISSUER_CLIENT_ID, AUTH0_WRONG_ISSUER_CLIENT_SECRET
//	                                   (audience is shared with AUTH0_AUDIENCE)
//	AUTH0_EXPIRED_JWT_TOKEN            operator-seeded; passed through verbatim
type auth0Env struct {
	Domain       string
	Audience     string
	ClientID     string
	ClientSecret string
	Realm        string
	Scope        string

	Username string
	Password string

	InactiveUsername string
	InactivePassword string

	WrongAudience string

	WrongIssuerDomain       string
	WrongIssuerClientID     string
	WrongIssuerClientSecret string

	ExpiredJWTToken string
}

func loadAuth0Env() auth0Env {
	return auth0Env{
		Domain:                  strings.TrimSpace(os.Getenv("AUTH0_DOMAIN")),
		Audience:                os.Getenv("AUTH0_AUDIENCE"),
		ClientID:                os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret:            os.Getenv("AUTH0_CLIENT_SECRET"),
		Realm:                   envOrDefault("AUTH0_REALM", "Username-Password-Authentication"),
		Scope:                   envOrDefault("AUTH0_SCOPE", "openid profile email identity:token:exchange"),
		Username:                os.Getenv("AUTH0_USERNAME"),
		Password:                os.Getenv("AUTH0_PASSWORD"),
		InactiveUsername:        os.Getenv("AUTH0_INACTIVE_USERNAME"),
		InactivePassword:        os.Getenv("AUTH0_INACTIVE_PASSWORD"),
		WrongAudience:           os.Getenv("AUTH0_WRONG_AUDIENCE"),
		WrongIssuerDomain:       os.Getenv("AUTH0_WRONG_ISSUER_DOMAIN"),
		WrongIssuerClientID:     os.Getenv("AUTH0_WRONG_ISSUER_CLIENT_ID"),
		WrongIssuerClientSecret: os.Getenv("AUTH0_WRONG_ISSUER_CLIENT_SECRET"),
		ExpiredJWTToken:         os.Getenv("AUTH0_EXPIRED_JWT_TOKEN"),
	}
}

// mintAuth0Tokens produces fresh tokens for the fixture variables consumed by
// the Auth0 integration tests. Tokens are always re-minted — any AUTH0_*_TOKEN
// values present in the environment are intentionally ignored because Auth0
// tokens expire.
//
// All fixtures use the password-realm grant. The realm, scope, username, and
// password are shared across every fixture; only the inactive-user case
// substitutes a different username/password (against the same tenant), and
// the wrong-issuer case substitutes a different domain/client/audience
// (against the same realm and user credentials, mirrored in that tenant).
//
// Each fixture whose required configuration is missing — or whose mint call
// fails — is emitted with an empty value so the corresponding Ginkgo case
// Skips cleanly at runtime.
func mintAuth0Tokens(ctx context.Context) map[string]string {
	env := loadAuth0Env()

	out := map[string]string{
		"AUTH0_VALID_JWT_TOKEN":          "",
		"AUTH0_WRONG_AUDIENCE_JWT_TOKEN": "",
		"AUTH0_EXPIRED_JWT_TOKEN":        env.ExpiredJWTToken,
		"AUTH0_WRONG_ISSUER_JWT_TOKEN":   "",
		"AUTH0_OPAQUE_TOKEN":             "",
		"AUTH0_INACTIVE_USER_JWT_TOKEN":  "",
		"AUTH0_EXPECTED_SUBJECT":         env.Username,
	}

	if env.ExpiredJWTToken == "" {
		logf("AUTH0_EXPIRED_JWT_TOKEN not set; mint one via `go run ./hack/auth0` and export it before running fixtures")
	}

	if env.Domain == "" || env.ClientID == "" || env.ClientSecret == "" {
		logf("Auth0 minting skipped: AUTH0_DOMAIN / AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET not all set")

		return out
	}

	creds := auth0MintCreds{
		Domain:       env.Domain,
		ClientID:     env.ClientID,
		ClientSecret: env.ClientSecret,
		Realm:        env.Realm,
		Scope:        env.Scope,
	}

	mintPrimaryAudienceFixtures(ctx, env, creds, out)
	mintSameTenantVariantFixtures(ctx, env, creds, out)
	mintWrongIssuerFixture(ctx, env, creds, out)

	return out
}

// mintFixture is a small helper that does the per-token logging+error handling
// dance so each call site is a single line. It returns "" on any failure so
// the corresponding .env value is left blank and the Ginkgo case Skips.
func mintFixture(ctx context.Context, name, audience, username, password string, c auth0MintCreds) string {
	if username == "" || password == "" {
		logf("%s: skipped (no user credentials)", name)

		return ""
	}

	logf("Minting %s...", name)

	token, err := auth0Mint(ctx, c, audience, username, password)
	if err != nil {
		logf("  %s mint failed: %v", name, err)

		return ""
	}

	return token
}

// mintPrimaryAudienceFixtures mints the valid + inactive-user fixtures, both
// against the primary audience configured on the identity server.
func mintPrimaryAudienceFixtures(ctx context.Context, env auth0Env, creds auth0MintCreds, out map[string]string) {
	if env.Audience == "" {
		logf("AUTH0_AUDIENCE not set; skipping valid/inactive fixtures")

		return
	}

	out["AUTH0_VALID_JWT_TOKEN"] = mintFixture(ctx, "AUTH0_VALID_JWT_TOKEN", env.Audience, env.Username, env.Password, creds)
	out["AUTH0_INACTIVE_USER_JWT_TOKEN"] = mintFixture(ctx, "AUTH0_INACTIVE_USER_JWT_TOKEN", env.Audience, env.InactiveUsername, env.InactivePassword, creds)
}

// mintSameTenantVariantFixtures mints the wrong-audience + opaque fixtures.
// Both reuse the primary tenant credentials — only the audience parameter
// changes (and is empty for opaque).
func mintSameTenantVariantFixtures(ctx context.Context, env auth0Env, creds auth0MintCreds, out map[string]string) {
	if env.WrongAudience != "" {
		out["AUTH0_WRONG_AUDIENCE_JWT_TOKEN"] = mintFixture(ctx, "AUTH0_WRONG_AUDIENCE_JWT_TOKEN", env.WrongAudience, env.Username, env.Password, creds)
	} else {
		logf("AUTH0_WRONG_AUDIENCE not set; skipping wrong-audience fixture")
	}

	out["AUTH0_OPAQUE_TOKEN"] = mintFixture(ctx, "AUTH0_OPAQUE_TOKEN", "", env.Username, env.Password, creds)
}

// mintWrongIssuerFixture mints against a separate Auth0 tenant so the token
// carries an `iss` that does not match the identity server's configured
// issuer. Audience, realm, scope, username, and password are inherited from
// the primary creds — only the tenant-specific values (domain, client) come
// from the AUTH0_WRONG_ISSUER_* env vars. The wrong-issuer tenant must
// expose the same AUTH0_AUDIENCE identifier so the verifier reaches the
// issuer check before short-circuiting on aud.
func mintWrongIssuerFixture(ctx context.Context, env auth0Env, creds auth0MintCreds, out map[string]string) {
	if env.WrongIssuerDomain == "" || env.WrongIssuerClientID == "" || env.WrongIssuerClientSecret == "" {
		logf("AUTH0_WRONG_ISSUER_DOMAIN/CLIENT_ID/CLIENT_SECRET not all set; skipping wrong-issuer fixture")

		return
	}

	wiCreds := auth0MintCreds{
		Domain:       env.WrongIssuerDomain,
		ClientID:     env.WrongIssuerClientID,
		ClientSecret: env.WrongIssuerClientSecret,
		Realm:        creds.Realm,
		Scope:        creds.Scope,
	}

	out["AUTH0_WRONG_ISSUER_JWT_TOKEN"] = mintFixture(ctx, "AUTH0_WRONG_ISSUER_JWT_TOKEN",
		env.Audience, env.Username, env.Password, wiCreds)
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

	auth0Vars := mintAuth0Tokens(ctx)

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

	for _, k := range []string{
		"AUTH0_VALID_JWT_TOKEN",
		"AUTH0_WRONG_AUDIENCE_JWT_TOKEN",
		"AUTH0_EXPIRED_JWT_TOKEN",
		"AUTH0_WRONG_ISSUER_JWT_TOKEN",
		"AUTH0_OPAQUE_TOKEN",
		"AUTH0_INACTIVE_USER_JWT_TOKEN",
		"AUTH0_EXPECTED_SUBJECT",
	} {
		fmt.Printf("%s=%s\n", k, auth0Vars[k])
	}
}
