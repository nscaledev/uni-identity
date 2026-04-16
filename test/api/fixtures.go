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

//nolint:revive,staticcheck // dot imports are standard for Ginkgo/Gomega test code
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// uniqueName returns a name safe for concurrent or fast-sequential use:
// a timestamp for human readability plus a 4-byte random hex suffix to
// prevent collisions when multiple tests run within the same second.
func uniqueName(prefix string) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%s-%s-%s", prefix, time.Now().Format("20060102-150405"), hex.EncodeToString(b))
}

// OrganizationPayloadBuilder builds organization write payloads for testing.
type OrganizationPayloadBuilder struct {
	org identityopenapi.OrganizationWrite
}

// NewOrganizationPayload creates an empty organization payload builder.
func NewOrganizationPayload() *OrganizationPayloadBuilder {
	return &OrganizationPayloadBuilder{}
}

// FromRead initialises the builder from an OrganizationRead, preserving the existing
// spec so that updates don't accidentally overwrite required fields like OrganizationType.
func (b *OrganizationPayloadBuilder) FromRead(org identityopenapi.OrganizationRead) *OrganizationPayloadBuilder {
	b.org = identityopenapi.OrganizationWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: org.Metadata.Name,
		},
		Spec: org.Spec,
	}

	return b
}

// WithName sets the organization name.
func (b *OrganizationPayloadBuilder) WithName(name string) *OrganizationPayloadBuilder {
	b.org.Metadata.Name = name
	return b
}

// Build returns the typed OrganizationWrite struct.
func (b *OrganizationPayloadBuilder) Build() identityopenapi.OrganizationWrite {
	return b.org
}

// GroupPayloadBuilder builds group payloads for testing using type-safe OpenAPI structs.
type GroupPayloadBuilder struct {
	group identityopenapi.GroupWrite
}

// NewGroupPayload creates a new group payload builder with a unique name.
func NewGroupPayload() *GroupPayloadBuilder {
	return &GroupPayloadBuilder{
		group: identityopenapi.GroupWrite{
			Metadata: coreopenapi.ResourceWriteMetadata{
				Name: uniqueName("test-group"),
			},
			Spec: identityopenapi.GroupSpec{
				RoleIDs:           []string{},
				ServiceAccountIDs: []string{},
			},
		},
	}
}

// WithName sets the group name.
func (b *GroupPayloadBuilder) WithName(name string) *GroupPayloadBuilder {
	b.group.Metadata.Name = name
	return b
}

// WithRoleIDs sets the role IDs for the group.
func (b *GroupPayloadBuilder) WithRoleIDs(roleIDs []string) *GroupPayloadBuilder {
	b.group.Spec.RoleIDs = roleIDs
	return b
}

// WithServiceAccountIDs sets the service account IDs for the group.
func (b *GroupPayloadBuilder) WithServiceAccountIDs(serviceAccountIDs []string) *GroupPayloadBuilder {
	b.group.Spec.ServiceAccountIDs = serviceAccountIDs
	return b
}

// WithUserIDs sets the user IDs for the group.
func (b *GroupPayloadBuilder) WithUserIDs(userIDs []string) *GroupPayloadBuilder {
	b.group.Spec.UserIDs = &userIDs
	return b
}

// Build returns the typed group struct directly.
func (b *GroupPayloadBuilder) Build() identityopenapi.GroupWrite {
	return b.group
}

// findOrphanedGroupID attempts to find a group by name when the ID wasn't captured during creation.
// Returns empty string if not found.
func findOrphanedGroupID(ctx context.Context, client *APIClient, config *TestConfig, groupName string) string {
	GinkgoWriter.Printf("No group ID available, attempting to find group by name: %s\n", groupName)

	groups, listErr := client.ListGroups(ctx, config.OrgID)
	if listErr != nil {
		GinkgoWriter.Printf("Warning: Could not list groups for cleanup: %v\n", listErr)
		return ""
	}

	for _, group := range groups {
		if group.Metadata.Name == groupName {
			GinkgoWriter.Printf("Found orphaned group by name: %s (ID: %s)\n", groupName, group.Metadata.Id)
			return group.Metadata.Id
		}
	}

	GinkgoWriter.Printf("Skipping cleanup: group not found by name\n")

	return ""
}

// ServiceAccountPayloadBuilder builds service account payloads for testing.
type ServiceAccountPayloadBuilder struct {
	sa identityopenapi.ServiceAccountWrite
}

// NewServiceAccountPayload creates a new service account payload builder with a unique name.
func NewServiceAccountPayload() *ServiceAccountPayloadBuilder {
	return &ServiceAccountPayloadBuilder{
		sa: identityopenapi.ServiceAccountWrite{
			Metadata: coreopenapi.ResourceWriteMetadata{
				Name: uniqueName("test-sa"),
			},
			Spec: identityopenapi.ServiceAccountSpec{
				GroupIDs: []string{},
			},
		},
	}
}

// WithName sets the service account name.
func (b *ServiceAccountPayloadBuilder) WithName(name string) *ServiceAccountPayloadBuilder {
	b.sa.Metadata.Name = name
	return b
}

// WithGroupIDs sets the group IDs for the service account.
func (b *ServiceAccountPayloadBuilder) WithGroupIDs(groupIDs []string) *ServiceAccountPayloadBuilder {
	b.sa.Spec.GroupIDs = groupIDs
	return b
}

// Build returns the typed service account struct.
func (b *ServiceAccountPayloadBuilder) Build() identityopenapi.ServiceAccountWrite {
	return b.sa
}

// CreateServiceAccountWithCleanup creates a service account and schedules automatic cleanup.
func CreateServiceAccountWithCleanup(client *APIClient, ctx context.Context, config *TestConfig, payload identityopenapi.ServiceAccountWrite) (identityopenapi.ServiceAccountCreate, string) {
	var saID string

	DeferCleanup(func() {
		if saID == "" {
			return
		}

		GinkgoWriter.Printf("Cleaning up service account: %s\n", saID)

		if err := client.DeleteServiceAccount(ctx, config.OrgID, saID); err != nil {
			GinkgoWriter.Printf("Warning: Failed to delete service account %s: %v\n", saID, err)
		} else {
			GinkgoWriter.Printf("Successfully deleted service account: %s\n", saID)
		}
	})

	created, err := client.CreateServiceAccount(ctx, config.OrgID, payload)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create service account: %v", err))
	}

	saID = created.Metadata.Id

	GinkgoWriter.Printf("Created service account with ID: %s\n", saID)

	return *created, saID
}

// UserPayloadBuilder builds user payloads for testing.
type UserPayloadBuilder struct {
	user identityopenapi.UserWrite
}

// NewUserPayload creates a new user payload builder with a unique subject.
func NewUserPayload() *UserPayloadBuilder {
	return &UserPayloadBuilder{
		user: identityopenapi.UserWrite{
			Spec: identityopenapi.UserSpec{
				Subject:  uniqueName("test-user") + "@example.com",
				State:    "active",
				GroupIDs: []string{},
			},
		},
	}
}

// WithSubject sets the user subject (email).
func (b *UserPayloadBuilder) WithSubject(subject string) *UserPayloadBuilder {
	b.user.Spec.Subject = subject
	return b
}

// WithGroupIDs sets the group IDs for the user.
func (b *UserPayloadBuilder) WithGroupIDs(groupIDs []string) *UserPayloadBuilder {
	b.user.Spec.GroupIDs = groupIDs
	return b
}

// WithState sets the user state.
func (b *UserPayloadBuilder) WithState(state identityopenapi.UserState) *UserPayloadBuilder {
	b.user.Spec.State = state
	return b
}

// Build returns the typed user struct.
func (b *UserPayloadBuilder) Build() identityopenapi.UserWrite {
	return b.user
}

// CreateUserWithCleanup creates a user and schedules automatic cleanup.
func CreateUserWithCleanup(client *APIClient, ctx context.Context, config *TestConfig, payload identityopenapi.UserWrite) (identityopenapi.UserRead, string) {
	var userID string

	DeferCleanup(func() {
		if userID == "" {
			return
		}

		GinkgoWriter.Printf("Cleaning up user: %s\n", userID)

		if err := client.DeleteUser(ctx, config.OrgID, userID); err != nil {
			GinkgoWriter.Printf("Warning: Failed to delete user %s: %v\n", userID, err)
		} else {
			GinkgoWriter.Printf("Successfully deleted user: %s\n", userID)
		}
	})

	created, err := client.CreateUser(ctx, config.OrgID, payload)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create user: %v", err))
	}

	userID = created.Metadata.Id

	GinkgoWriter.Printf("Created user with ID: %s\n", userID)

	return *created, userID
}

// ProjectPayloadBuilder builds project payloads for testing.
type ProjectPayloadBuilder struct {
	project identityopenapi.ProjectWrite
}

// NewProjectPayload creates a new project payload builder with a unique name.
func NewProjectPayload() *ProjectPayloadBuilder {
	return &ProjectPayloadBuilder{
		project: identityopenapi.ProjectWrite{
			Metadata: coreopenapi.ResourceWriteMetadata{
				Name: uniqueName("test-project"),
			},
			Spec: identityopenapi.ProjectSpec{
				GroupIDs: []string{},
			},
		},
	}
}

// WithName sets the project name.
func (b *ProjectPayloadBuilder) WithName(name string) *ProjectPayloadBuilder {
	b.project.Metadata.Name = name
	return b
}

// WithGroupIDs sets the group IDs for the project.
func (b *ProjectPayloadBuilder) WithGroupIDs(groupIDs []string) *ProjectPayloadBuilder {
	b.project.Spec.GroupIDs = groupIDs
	return b
}

// Build returns the typed project struct.
func (b *ProjectPayloadBuilder) Build() identityopenapi.ProjectWrite {
	return b.project
}

// CreateProjectWithCleanup creates a project and schedules automatic cleanup.
// Project deletion is async (202), so cleanup polls until the project is gone.
func CreateProjectWithCleanup(client *APIClient, ctx context.Context, config *TestConfig, payload identityopenapi.ProjectWrite) (identityopenapi.ProjectRead, string) {
	var projectID string

	DeferCleanup(func() {
		if projectID == "" {
			return
		}

		GinkgoWriter.Printf("Cleaning up project: %s\n", projectID)

		if err := client.DeleteProject(ctx, config.OrgID, projectID); err != nil {
			GinkgoWriter.Printf("Warning: Failed to delete project %s: %v\n", projectID, err)
			return
		}

		Eventually(func() bool {
			_, err := client.GetProject(ctx, config.OrgID, projectID)
			return errors.Is(err, coreclient.ErrResourceNotFound)
		}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(BeTrue(),
			"project %s should be deleted", projectID,
		)

		GinkgoWriter.Printf("Successfully deleted project: %s\n", projectID)
	})

	created, err := client.CreateProject(ctx, config.OrgID, payload)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create project: %v", err))
	}

	projectID = created.Metadata.Id

	GinkgoWriter.Printf("Created project with ID: %s\n", projectID)

	return *created, projectID
}

// WaitForProjectProvisioned polls until the project reaches provisioned state.
// Projects are created asynchronously (202); mutations will conflict if the
// controller is still reconciling, so callers must wait before updating.
func WaitForProjectProvisioned(client *APIClient, ctx context.Context, config *TestConfig, projectID string) {
	Eventually(func() bool {
		project, err := client.GetProject(ctx, config.OrgID, projectID)
		if err != nil {
			return false
		}

		return project.Metadata.ProvisioningStatus == coreopenapi.ResourceProvisioningStatusProvisioned
	}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(BeTrue(),
		"project %s should reach provisioned state", projectID)
}

// WaitForProjectInACL polls until projectID appears in the caller's organization ACL.
// ACL propagation may lag project provisioning, so this must be called after
// WaitForProjectProvisioned. Returns the matching AclProject for further assertions.
func WaitForProjectInACL(callerClient *APIClient, ctx context.Context, config *TestConfig, projectID string) identityopenapi.AclProject {
	var found identityopenapi.AclProject

	Eventually(func() bool {
		acl, err := callerClient.GetOrganizationACL(ctx, config.OrgID)
		if err != nil || acl.Projects == nil {
			return false
		}

		for _, p := range *acl.Projects {
			if p.Id == projectID {
				found = p
				return true
			}
		}

		return false
	}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(BeTrue(),
		"project %s should appear in organization ACL", projectID)

	return found
}

// WaitForProjectRemovedFromACL polls until projectID is no longer present in the
// caller's organization ACL.
func WaitForProjectRemovedFromACL(callerClient *APIClient, ctx context.Context, config *TestConfig, projectID string) {
	Eventually(func() bool {
		acl, err := callerClient.GetOrganizationACL(ctx, config.OrgID)
		Expect(err).NotTo(HaveOccurred())

		if acl.Projects == nil {
			return true
		}

		for _, p := range *acl.Projects {
			if p.Id == projectID {
				return false
			}
		}

		return true
	}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(BeTrue(),
		"project %s should be removed from organization ACL", projectID)
}

// Oauth2ProviderPayloadBuilder builds OAuth2 provider payloads for testing.
type Oauth2ProviderPayloadBuilder struct {
	provider identityopenapi.Oauth2ProviderWrite
}

// NewOauth2ProviderPayload creates a new OAuth2 provider payload builder with a unique name.
func NewOauth2ProviderPayload() *Oauth2ProviderPayloadBuilder {
	providerType := identityopenapi.Google
	suffix := uniqueName("test-provider")

	return &Oauth2ProviderPayloadBuilder{
		provider: identityopenapi.Oauth2ProviderWrite{
			Metadata: coreopenapi.ResourceWriteMetadata{
				Name: suffix,
			},
			Spec: identityopenapi.Oauth2ProviderSpec{
				ClientID: suffix,
				Issuer:   "https://accounts.google.com",
				Type:     &providerType,
			},
		},
	}
}

// WithName sets the provider name.
func (b *Oauth2ProviderPayloadBuilder) WithName(name string) *Oauth2ProviderPayloadBuilder {
	b.provider.Metadata.Name = name
	return b
}

// WithClientID sets the client ID.
func (b *Oauth2ProviderPayloadBuilder) WithClientID(clientID string) *Oauth2ProviderPayloadBuilder {
	b.provider.Spec.ClientID = clientID
	return b
}

// Build returns the typed OAuth2 provider struct.
func (b *Oauth2ProviderPayloadBuilder) Build() identityopenapi.Oauth2ProviderWrite {
	return b.provider
}

// CreateOauth2ProviderWithCleanup creates an OAuth2 provider and schedules automatic cleanup.
func CreateOauth2ProviderWithCleanup(client *APIClient, ctx context.Context, config *TestConfig, payload identityopenapi.Oauth2ProviderWrite) (identityopenapi.Oauth2ProviderRead, string) {
	var providerID string

	DeferCleanup(func() {
		if providerID == "" {
			return
		}

		GinkgoWriter.Printf("Cleaning up oauth2provider: %s\n", providerID)

		if err := client.DeleteOauth2Provider(ctx, config.OrgID, providerID); err != nil {
			GinkgoWriter.Printf("Warning: Failed to delete oauth2provider %s: %v\n", providerID, err)
		} else {
			GinkgoWriter.Printf("Successfully deleted oauth2provider: %s\n", providerID)
		}
	})

	created, err := client.CreateOauth2Provider(ctx, config.OrgID, payload)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create oauth2provider: %v", err))
	}

	providerID = created.Metadata.Id

	GinkgoWriter.Printf("Created oauth2provider with ID: %s\n", providerID)

	return *created, providerID
}

// CreateGroupWithCleanup creates a group and schedules automatic cleanup.
// Accepts a typed struct for type safety (or use Build() from the builder).
func CreateGroupWithCleanup(client *APIClient, ctx context.Context, config *TestConfig, payload identityopenapi.GroupWrite) (identityopenapi.GroupRead, string) {
	var groupID string

	groupName := payload.Metadata.Name

	// Schedule cleanup FIRST - ensures cleanup runs even if creation fails
	DeferCleanup(func() {
		if groupID == "" {
			groupID = findOrphanedGroupID(ctx, client, config, groupName)
			if groupID == "" {
				return
			}
		}

		GinkgoWriter.Printf("Cleaning up group: %s\n", groupID)

		deleteErr := client.DeleteGroup(ctx, config.OrgID, groupID)
		if deleteErr != nil {
			GinkgoWriter.Printf("Warning: Failed to delete group %s: %v\n", groupID, deleteErr)
		} else {
			GinkgoWriter.Printf("Successfully deleted group: %s\n", groupID)
		}
	})

	group, err := client.CreateGroup(ctx, config.OrgID, payload)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create group: %v", err))
	}

	groupID = group.Metadata.Id

	GinkgoWriter.Printf("Created group with ID: %s\n", groupID)

	return *group, groupID
}
