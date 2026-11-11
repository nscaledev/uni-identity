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

// Package fixturelib holds the identity API helpers shared by the CI fixture
// programs under hack/ci. Every helper exits the process on failure.
//
//nolint:forbidigo // stderr progress output and exit-on-error are intentional for CI tools
package fixturelib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func MustParseOrganizationID(orgID string) ids.OrganizationID {
	id, err := ids.ParseOrganizationID(orgID)
	if err != nil {
		Fatalf("invalid organization ID %q: %v", orgID, err)
	}

	return id
}

func Logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "==> "+format+"\n", args...)
}

func NewClientScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		Fatalf("failed to register core scheme: %v", err)
	}

	if err := unikornv1.AddToScheme(scheme); err != nil {
		Fatalf("failed to register identity scheme: %v", err)
	}

	return scheme
}

// IssueCert creates a cert-manager Certificate via controller-runtime and
// waits for the backing Secret to be ready. Returns the cert and key PEM bytes.
func IssueCert(ctx context.Context, k8s client.Client, namespace, name, cn string) ([]byte, []byte) {
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
		Fatalf("failed to create Certificate %s: %v", name, err)
	}

	Logf("Waiting for Certificate %s/%s to be ready...", namespace, name)

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
		Fatalf("Certificate %s/%s not ready: %v", namespace, name, err)
	}

	secret := &corev1.Secret{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name + "-tls"}, secret); err != nil {
		Fatalf("failed to read Secret %s-tls: %v", name, err)
	}

	return secret.Data["tls.crt"], secret.Data["tls.key"]
}

// NewAPIClient builds an openapi.ClientWithResponses that authenticates via mTLS.
// The certificate CN maps directly to an RBAC role — no bearer token is needed.
// An X-Principal header is injected on every request as required by the middleware.
func NewAPIClient(baseURL, caCertPath string, certPEM, keyPEM []byte) *openapi.ClientWithResponses {
	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		Fatalf("failed to read CA cert: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		Fatalf("failed to parse CA cert")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		Fatalf("failed to parse mTLS key pair: %v", err)
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
		Fatalf("failed to marshal principal: %v", err)
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
		Fatalf("failed to create API client: %v", err)
	}

	return ac
}

// FindRole returns the ID of a named role within an organization.
// platform-administrator and other protected roles are excluded from the API response.
func FindRole(roles *openapi.RolesResponse, name string) string {
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

// CreateGroup creates a group with the given role IDs assigned.
func CreateGroup(ctx context.Context, ac *openapi.ClientWithResponses, orgID, name string, roleIDs []string) string {
	Logf("Creating group %q...", name)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDGroupsWithResponse(ctx, MustParseOrganizationID(orgID), openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec: openapi.GroupSpec{
			RoleIDs:           roleIDs,
			ServiceAccountIDs: openapi.StringList{},
		},
	})
	if err != nil {
		Fatalf("failed to create group %q: %v", name, err)
	}

	if resp.JSON201 == nil {
		Fatalf("create group %q returned %s", name, resp.Status())
	}

	id := resp.JSON201.Metadata.Id
	Logf("  group %q ID: %s", name, id)

	return id
}

// CreateProject creates a project with the given group memberships and returns its ID.
func CreateProject(ctx context.Context, ac *openapi.ClientWithResponses, orgID, name string, groupIDs []string) string {
	Logf("Creating project %q...", name)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDProjectsWithResponse(ctx, MustParseOrganizationID(orgID), openapi.ProjectWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec:     openapi.ProjectSpec{GroupIDs: groupIDs},
	})
	if err != nil {
		Fatalf("failed to create project %q: %v", name, err)
	}

	if resp.JSON202 == nil {
		Fatalf("create project %q returned %s", name, resp.Status())
	}

	id := resp.JSON202.Metadata.Id
	Logf("  project %q ID: %s", name, id)

	return id
}

// CreateServiceAccount creates a service account in the given groups and returns its ID and token.
func CreateServiceAccount(ctx context.Context, ac *openapi.ClientWithResponses, orgID, name string, groupIDs []string) (string, string) {
	Logf("Creating service account %q...", name)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDServiceaccountsWithResponse(ctx, MustParseOrganizationID(orgID), openapi.ServiceAccountWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec:     openapi.ServiceAccountSpec{GroupIDs: groupIDs},
	})
	if err != nil {
		Fatalf("failed to create service account %q: %v", name, err)
	}

	if resp.JSON201 == nil {
		Fatalf("create service account %q returned %s", name, resp.Status())
	}

	id := resp.JSON201.Metadata.Id
	token := ""

	if resp.JSON201.Status.AccessToken != nil {
		token = *resp.JSON201.Status.AccessToken
	}

	Logf("  service account %q ID: %s", name, id)

	return id, token
}

// CreateUser creates an active user in the given groups and returns its organization user ID.
func CreateUser(ctx context.Context, ac *openapi.ClientWithResponses, orgID, subject string, groupIDs []string) string {
	Logf("Creating user %q...", subject)

	resp, err := ac.PostApiV1OrganizationsOrganizationIDUsersWithResponse(ctx, MustParseOrganizationID(orgID), openapi.UserWrite{
		Spec: openapi.UserSpec{
			GroupIDs: groupIDs,
			State:    openapi.Active,
			Subject:  subject,
		},
	})
	if err != nil {
		Fatalf("failed to create user %q: %v", subject, err)
	}

	if resp.JSON201 == nil {
		Fatalf("create user %q returned %s", subject, resp.Status())
	}

	id := resp.JSON201.Metadata.Id
	Logf("  user %q organization user ID: %s", subject, id)

	return id
}

func FindGlobalUserID(ctx context.Context, k8s client.Client, namespace, subject string) string {
	users := &unikornv1.UserList{}
	if err := k8s.List(ctx, users, client.InNamespace(namespace)); err != nil {
		Fatalf("failed to list global users: %v", err)
	}

	for _, user := range users.Items {
		if user.Spec.Subject == subject {
			return user.Name
		}
	}

	Fatalf("global user for subject %q not found", subject)

	return ""
}

// WaitForOrgNamespace polls until the organization controller has provisioned the backing namespace.
func WaitForOrgNamespace(ctx context.Context, k8s client.Client, namespace, orgID string) {
	Logf("Waiting for Organization %s to be provisioned...", orgID)

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
		Fatalf("Organization %s not provisioned: %v", orgID, err)
	}
}

// ResolveRoles lists organization roles and returns role IDs.
// - administrator is required.
// - user is required.
// - auditor is required.
func ResolveRoles(ctx context.Context, ac *openapi.ClientWithResponses, orgID string) (string, string, string) {
	Logf("Resolving role IDs...")

	rolesResp, err := ac.GetApiV1OrganizationsOrganizationIDRolesWithResponse(ctx, MustParseOrganizationID(orgID))
	if err != nil {
		Fatalf("failed to list roles: %v", err)
	}

	if rolesResp.JSON200 == nil {
		Fatalf("list roles returned %s", rolesResp.Status())
	}

	administratorRoleID := FindRole(rolesResp.JSON200, "administrator")
	if administratorRoleID == "" {
		Fatalf("administrator role not found in org %s", orgID)
	}

	userRoleID := FindRole(rolesResp.JSON200, "user")
	if userRoleID == "" {
		Fatalf("user role not found in org %s", orgID)
	}

	auditRoleID := FindRole(rolesResp.JSON200, "auditor")
	if auditRoleID == "" {
		Fatalf("auditor role not found in org %s", orgID)
	}

	Logf("  administrator role ID: %s", administratorRoleID)
	Logf("  user role ID: %s", userRoleID)
	Logf("  auditor role ID: %s", auditRoleID)

	return administratorRoleID, userRoleID, auditRoleID
}
