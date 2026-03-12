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

package webhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/auth0/go-auth0/v2/management"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	apierrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/auth0"
	auth0webhook "github.com/unikorn-cloud/identity/pkg/auth0/webhook"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const DefaultTolerance = 5 * time.Minute

var (
	ErrUnsupportedAuth0EventType         = fmt.Errorf("unsupported auth0 event type")
	ErrNoAuth0ResourceID                 = fmt.Errorf("missing resource id")
	ErrUnexpectedKubernetesResourceCount = fmt.Errorf("unexpected kubernetes resource count")
)

type Auth0MissingMetadataError struct {
	ResourceType string
	ResourceID   string
	Key          string
}

func NewAuth0MissingMetadataError(resourceType, resourceID, key string) *Auth0MissingMetadataError {
	return &Auth0MissingMetadataError{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Key:          key,
	}
}

func (e *Auth0MissingMetadataError) Error() string {
	return fmt.Sprintf("auth %s %q has no metadata %q", e.ResourceType, e.ResourceID, e.Key)
}

type Auth0MigrationWebhookHandler struct {
	kubeClient    client.Client
	webhookSecret string
}

func NewAuth0MigrationWebhookHandler(kubeClient client.Client, webhookSecret string) *Auth0MigrationWebhookHandler {
	return &Auth0MigrationWebhookHandler{
		kubeClient:    kubeClient,
		webhookSecret: webhookSecret,
	}
}

func (h *Auth0MigrationWebhookHandler) Handle(r *http.Request) error {
	header := r.Header.Get("X-Auth0-Signature")

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	event, err := auth0webhook.ConstructEvent(payload, header, h.webhookSecret)
	if err != nil {
		return apierrors.OAuth2InvalidRequest(err.Error()).WithError(err)
	}

	ctx := r.Context()

	switch event.Type {
	case "organization.created":
		return h.HandleOrganizationCreated(ctx, event)
	case "user.created":
		return h.HandleUserCreated(ctx, event)
	case "organization.member.added":
		return h.HandleOrganizationMemberAdded(ctx, event)
	default:
		return ErrUnsupportedAuth0EventType
	}
}

func parseAuth0EventDataObject[T any](event *auth0.Event) (*T, error) {
	var object T
	if err := json.Unmarshal(event.Data.Object, &object); err != nil {
		return nil, apierrors.OAuth2InvalidRequest("failed to parse event data object").WithError(err)
	}

	return &object, nil
}

func readAuth0ResourceID(id *string) string {
	if id == nil {
		return ""
	}

	return *id
}

func readAuth0OrganizationMetadata(metadata *map[string]*string, key string) string {
	if metadata == nil {
		return ""
	}

	value, ok := (*metadata)[key]
	if !ok || value == nil {
		return ""
	}

	return *value
}

func (h *Auth0MigrationWebhookHandler) isLikelyStaleCache(event *auth0.Event) bool {
	return time.Since(event.Time) < DefaultTolerance
}

//nolint:cyclop
func (h *Auth0MigrationWebhookHandler) HandleOrganizationCreated(ctx context.Context, event *auth0.Event) error {
	object, err := parseAuth0EventDataObject[management.Organization](event)
	if err != nil {
		return err
	}

	if value := readAuth0OrganizationMetadata(object.Metadata, auth0.MetadataKeyManagedBy); value != auth0.MetadataValueManagedByMigrationController {
		return nil
	}

	auth0ResourceID := readAuth0ResourceID(object.ID)
	if auth0ResourceID == "" {
		return fmt.Errorf("auth0 organization: %w", ErrNoAuth0ResourceID)
	}

	namespace := readAuth0OrganizationMetadata(object.Metadata, auth0.MetadataKeyUniAuth0OrganizationNamespace)
	if namespace == "" {
		return NewAuth0MissingMetadataError("organization", auth0ResourceID, auth0.MetadataKeyUniAuth0OrganizationNamespace)
	}

	name := readAuth0OrganizationMetadata(object.Metadata, auth0.MetadataKeyUniAuth0OrganizationName)
	if name == "" {
		return NewAuth0MissingMetadataError("organization", auth0ResourceID, auth0.MetadataKeyUniAuth0OrganizationName)
	}

	objectKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	var auth0Organization identityv1.Auth0Organization
	if err = h.kubeClient.Get(ctx, objectKey, &auth0Organization); err != nil {
		if kerrors.IsNotFound(err) && !h.isLikelyStaleCache(event) {
			return nil
		}

		return fmt.Errorf("failed to get auth0 organization %q in namespace %q: %w", name, namespace, err)
	}

	updated := auth0Organization.DeepCopy()
	updated.Labels[auth0.LabelKeyAuth0OrganizationID] = auth0ResourceID

	if err = h.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(&auth0Organization, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("failed to patch metadata for auth0 organization %q in namespace %q: %w", name, namespace, err)
	}

	patched := updated.DeepCopy()
	updated.Status.OrganizationID = auth0ResourceID

	if err = h.kubeClient.Status().Patch(ctx, updated, client.MergeFromWithOptions(patched, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("failed to patch status for auth0 organization %q in namespace %q: %w", name, namespace, err)
	}

	return nil
}

func readAuth0UserAppMetadata(metadata *map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}

	raw, ok := (*metadata)[key]
	if !ok {
		return ""
	}

	value, ok := raw.(string)
	if !ok {
		return ""
	}

	return value
}

//nolint:cyclop
func (h *Auth0MigrationWebhookHandler) HandleUserCreated(ctx context.Context, event *auth0.Event) error {
	object, err := parseAuth0EventDataObject[management.UserResponseSchema](event)
	if err != nil {
		return err
	}

	if value := readAuth0UserAppMetadata(object.AppMetadata, auth0.MetadataKeyManagedBy); value != auth0.MetadataValueManagedByMigrationController {
		return nil
	}

	auth0ResourceID := readAuth0ResourceID(object.UserID)
	if auth0ResourceID == "" {
		return fmt.Errorf("auth0 user: %w", ErrNoAuth0ResourceID)
	}

	auth0UserResourceProvider, auth0UserResourceProviderID, err := auth0.ParseUserID(auth0ResourceID)
	if err != nil {
		return fmt.Errorf("auth0 user %q: %w", auth0ResourceID, err)
	}

	namespace := readAuth0UserAppMetadata(object.AppMetadata, auth0.MetadataKeyUniAuth0UserNamespace)
	if namespace == "" {
		return NewAuth0MissingMetadataError("user", auth0ResourceID, auth0.MetadataKeyUniAuth0UserNamespace)
	}

	name := readAuth0UserAppMetadata(object.AppMetadata, auth0.MetadataKeyUniAuth0UserName)
	if name == "" {
		return NewAuth0MissingMetadataError("user", auth0ResourceID, auth0.MetadataKeyUniAuth0UserName)
	}

	objectKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	var auth0User identityv1.Auth0User
	if err = h.kubeClient.Get(ctx, objectKey, &auth0User); err != nil {
		if kerrors.IsNotFound(err) && !h.isLikelyStaleCache(event) {
			return nil
		}

		return fmt.Errorf("failed to get auth0 user %q in namespace %q: %w", name, namespace, err)
	}

	updated := auth0User.DeepCopy()
	updated.Labels[auth0.LabelKeyAuth0UserProvider] = auth0UserResourceProvider
	updated.Labels[auth0.LabelKeyAuth0UserProviderID] = auth0UserResourceProviderID

	if err = h.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(&auth0User, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("failed to patch metadata for auth0 user %q in namespace %q: %w", name, namespace, err)
	}

	patched := updated.DeepCopy()
	updated.Status.UserID = auth0ResourceID

	if err = h.kubeClient.Status().Patch(ctx, updated, client.MergeFromWithOptions(patched, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("failed to patch status for auth0 user %q in namespace %q: %w", name, namespace, err)
	}

	return nil
}

//nolint:cyclop
func (h *Auth0MigrationWebhookHandler) HandleOrganizationMemberAdded(ctx context.Context, event *auth0.Event) error {
	object, err := parseAuth0EventDataObject[auth0.Membership](event)
	if err != nil {
		return err
	}

	auth0OrganizationResourceID := readAuth0ResourceID(object.Organization.ID)
	if auth0OrganizationResourceID == "" {
		return fmt.Errorf("auth0 membership organization: %w", ErrNoAuth0ResourceID)
	}

	auth0UserResourceID := readAuth0ResourceID(object.User.UserID)
	if auth0UserResourceID == "" {
		return fmt.Errorf("auth0 membership user: %w", ErrNoAuth0ResourceID)
	}

	auth0UserResourceProvider, auth0UserResourceProviderID, err := auth0.ParseUserID(auth0UserResourceID)
	if err != nil {
		return fmt.Errorf("auth0 membership user %q: %w", auth0UserResourceID, err)
	}

	auth0Organization, err := h.findAuth0OrganizationByAuth0ResourceID(ctx, auth0OrganizationResourceID)
	if err != nil {
		return fmt.Errorf("failed to find auth0 organization with resource id %q: %w", auth0OrganizationResourceID, err)
	}

	organizationID, ok := auth0Organization.Labels[coreconstants.OrganizationLabel]
	if !ok || organizationID == "" {
		return identityv1.NewMissingLabelError("auth organization", auth0Organization.Name, coreconstants.OrganizationLabel)
	}

	auth0User, err := h.findAuth0UserByAuth0ResourceID(ctx, auth0UserResourceProvider, auth0UserResourceProviderID)
	if err != nil {
		return fmt.Errorf("failed to find auth0 user with resource id %q: %w", auth0UserResourceID, err)
	}

	userID, ok := auth0User.Labels[coreconstants.UserLabel]
	if !ok || userID == "" {
		return identityv1.NewMissingLabelError("auth user", auth0User.Name, coreconstants.UserLabel)
	}

	auth0OrganizationMember, err := h.findAuth0OrganizationMemberByOrganizationAndUser(ctx, organizationID, userID)
	if err != nil {
		return fmt.Errorf("failed to find auth0 organization member for organization %q and user %q: %w", organizationID, userID, err)
	}

	updated := auth0OrganizationMember.DeepCopy()
	updated.Status.OrganizationID = auth0OrganizationResourceID
	updated.Status.UserID = auth0UserResourceID

	if err = h.kubeClient.Status().Patch(ctx, updated, client.MergeFromWithOptions(auth0OrganizationMember, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("failed to patch status for auth0 organization member for organization %q and user %q: %w", organizationID, userID, err)
	}

	return nil
}

func (h *Auth0MigrationWebhookHandler) findAuth0OrganizationByAuth0ResourceID(ctx context.Context, auth0OrganizationResourceID string) (*identityv1.Auth0Organization, error) {
	listOptions := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{
			auth0.LabelKeyAuth0OrganizationID: auth0OrganizationResourceID,
		}),
	}

	var auth0OrganizationList identityv1.Auth0OrganizationList
	if err := h.kubeClient.List(ctx, &auth0OrganizationList, &listOptions); err != nil {
		return nil, err
	}

	if len(auth0OrganizationList.Items) != 1 {
		return nil, ErrUnexpectedKubernetesResourceCount
	}

	return &auth0OrganizationList.Items[0], nil
}

func (h *Auth0MigrationWebhookHandler) findAuth0UserByAuth0ResourceID(ctx context.Context, auth0UserResourceProvider, auth0UserResourceProviderID string) (*identityv1.Auth0User, error) {
	listOptions := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{
			auth0.LabelKeyAuth0UserProvider:   auth0UserResourceProvider,
			auth0.LabelKeyAuth0UserProviderID: auth0UserResourceProviderID,
		}),
	}

	var auth0UserList identityv1.Auth0UserList
	if err := h.kubeClient.List(ctx, &auth0UserList, &listOptions); err != nil {
		return nil, err
	}

	if len(auth0UserList.Items) != 1 {
		return nil, ErrUnexpectedKubernetesResourceCount
	}

	return &auth0UserList.Items[0], nil
}

func (h *Auth0MigrationWebhookHandler) findAuth0OrganizationMemberByOrganizationAndUser(ctx context.Context, organizationID, userID string) (*identityv1.Auth0OrganizationMember, error) {
	listOptions := client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{
			coreconstants.OrganizationLabel: organizationID,
			coreconstants.UserLabel:         userID,
		}),
	}

	var auth0OrganizationMemberList identityv1.Auth0OrganizationMemberList
	if err := h.kubeClient.List(ctx, &auth0OrganizationMemberList, &listOptions); err != nil {
		return nil, err
	}

	if len(auth0OrganizationMemberList.Items) != 1 {
		return nil, ErrUnexpectedKubernetesResourceCount
	}

	return &auth0OrganizationMemberList.Items[0], nil
}
