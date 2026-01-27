/*
Copyright 2025 the Unikorn Authors.
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

package serviceaccounts

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Options struct {
	// defaultDuration is the length of time an access token lives for if not
	// specified.
	defaultDuration time.Duration
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.defaultDuration, "default-service-account-token-lifetime", time.Hour*24*90, "Default service account token lifetime, defaults to 90 days")
}

// Client is responsible for service account management.
type Client struct {
	// client is the Kubernetes client.
	client client.Client
	// namespace is the namespace the identity service is running in.
	namespace string
	// commonOptions contains shared handler configuration (issuer, hostname, etc.).
	issuer common.IssuerValue
	// oauth2 is used to issue access tokens.
	oauth2 *oauth2.Authenticator
	// options are any deployment defaults.
	options *Options
}

// New creates a new service account client.
func New(client client.Client, namespace string, issuer common.IssuerValue, oauth2 *oauth2.Authenticator, options *Options) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		issuer:    issuer,
		oauth2:    oauth2,
		options:   options,
	}
}

// convert converts from Kubernetes into OpenAPI for normal read requests.
func convert(in *unikornv1.ServiceAccount, groups *unikornv1.GroupList) *openapi.ServiceAccountRead {
	out := &openapi.ServiceAccountRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.ServiceAccountSpec{
			GroupIDs: make(openapi.GroupIDs, 0, len(groups.Items)),
		},
		Status: openapi.ServiceAccountStatus{
			Expiry: in.Spec.Expiry.Time,
		},
	}

	for _, group := range groups.Items {
		if slices.Contains(group.Spec.ServiceAccountIDs, in.Name) {
			out.Spec.GroupIDs = append(out.Spec.GroupIDs, group.Name)
		}
	}

	return out
}

// convertCreate converts from Kubernetes into OpenAPi for create/update requests that
// have extra information e.g. the access token.
func convertCreate(in *unikornv1.ServiceAccount, groups *unikornv1.GroupList) *openapi.ServiceAccountCreate {
	temp := convert(in, groups)

	out := &openapi.ServiceAccountCreate{
		Metadata: temp.Metadata,
		Spec:     temp.Spec,
		Status:   temp.Status,
	}

	out.Status.AccessToken = &in.Spec.AccessToken

	return out
}

// convertList converts a list of Kubernetes objects into OpenAPI ones.
func convertList(in *unikornv1.ServiceAccountList, groups *unikornv1.GroupList) openapi.ServiceAccounts {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.ServiceAccount) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(openapi.ServiceAccounts, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i], groups)
	}

	return out
}

// generateAccessToken generates a service account token for the given service account.
func (c *Client) generateAccessToken(ctx context.Context, organization *organizations.Meta, serviceAccountID string) (*oauth2.Tokens, error) {
	issueInfo := &oauth2.IssueInfo{
		Issuer:   c.issuer.URL,
		Audience: c.issuer.Hostname,
		Subject:  serviceAccountID,
		Type:     oauth2.TokenTypeServiceAccount,
		ServiceAccount: &oauth2.ServiceAccountClaims{
			OrganizationID: organization.ID,
		},
		// TODO: allow the client to override this, but keep it capped to
		// some server controlled value.
		Duration: &c.options.defaultDuration,
	}

	tokens, err := c.oauth2.Issue(ctx, issueInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to issue access token", err)
	}

	return tokens, nil
}

// generate takes an API request and generates a new Kubernetes resource for it, including
// a new access token.
func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.ServiceAccountWrite) (*unikornv1.ServiceAccount, error) {
	out := &unikornv1.ServiceAccount{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, organization.Namespace).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.ServiceAccountSpec{
			Tags: conversion.GenerateTagList(in.Metadata.Tags),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	tokens, err := c.generateAccessToken(ctx, organization, out.Name)
	if err != nil {
		return nil, err
	}

	out.Spec.Expiry = &metav1.Time{Time: tokens.Expiry}
	out.Spec.AccessToken = tokens.AccessToken

	return out, nil
}

// get retrieves the service account.
func (c *Client) get(ctx context.Context, organization *organizations.Meta, serviceAccountID string) (*unikornv1.ServiceAccount, error) {
	result := &unikornv1.ServiceAccount{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: serviceAccountID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to get service account", err)
	}

	return result, nil
}

// listGroups returns an exhaustive list of all groups a service account can be a member of.
func (c *Client) listGroups(ctx context.Context, organization *organizations.Meta) (*unikornv1.GroupList, error) {
	result := &unikornv1.GroupList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list groups", err)
	}

	return result, nil
}

// updateGroups takes a user name and a requested list of groups and adds to
// the groups it should be a member of and removes itself from groups it shouldn't.
func (c *Client) updateGroups(ctx context.Context, serviceAccountID string, groupIDs openapi.GroupIDs, groups *unikornv1.GroupList) error {
	for i := range groups.Items {
		current := &groups.Items[i]

		updated := current.DeepCopy()

		if slices.Contains(groupIDs, current.Name) {
			// Add to a group where it should be a member but isn't.
			if slices.Contains(current.Spec.ServiceAccountIDs, serviceAccountID) {
				continue
			}

			updated.Spec.ServiceAccountIDs = append(updated.Spec.ServiceAccountIDs, serviceAccountID)
		} else {
			// Remove from any groups its a member of but shouldn't be.
			if !slices.Contains(current.Spec.ServiceAccountIDs, serviceAccountID) {
				continue
			}

			updated.Spec.ServiceAccountIDs = slices.DeleteFunc(updated.Spec.ServiceAccountIDs, func(id string) bool {
				return id == serviceAccountID
			})
		}

		if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
			return fmt.Errorf("%w: failed to patch group", err)
		}
	}

	return nil
}

// Create makes a new service account and issues an access token.
func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.ServiceAccountWrite) (*openapi.ServiceAccountCreate, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	resource, err := c.generate(ctx, organization, request)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to generate service account", err)
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, fmt.Errorf("%w: failed to create service account", err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, resource.Name, request.Spec.GroupIDs, groups); err != nil {
		return nil, err
	}

	return convertCreate(resource, groups), nil
}

// Get retrieves information about a service account.
func (c *Client) Get(ctx context.Context, organizationID, serviceAccountID string) (*openapi.ServiceAccountRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		return nil, err
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	return convert(result, groups), nil
}

// List retrieves information about all service accounts in the organization.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.ServiceAccounts, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.ServiceAccountList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list service accounts", err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	return convertList(result, groups), nil
}

// Update modifies any metadata for the service account if it exists.  If a matching account
// doesn't exist it raises an error.
func (c *Client) Update(ctx context.Context, organizationID, serviceAccountID string, request *openapi.ServiceAccountWrite) (*openapi.ServiceAccountRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		return nil, err
	}

	required, err := c.generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator); err != nil {
		return nil, fmt.Errorf("%w: failed to merge metadata", err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	// Preserve the access token etc. across metadata updates.
	updated.Spec.Expiry = current.Spec.Expiry
	updated.Spec.AccessToken = current.Spec.AccessToken

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, fmt.Errorf("%w: failed to patch group", err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, serviceAccountID, request.Spec.GroupIDs, groups); err != nil {
		return nil, err
	}

	return convert(updated, groups), nil
}

// Rotate is a special version of Update where everything about the resource is preserved
// with the exception of the access token.
func (c *Client) Rotate(ctx context.Context, organizationID, serviceAccountID string) (*openapi.ServiceAccountCreate, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		return nil, err
	}

	tokens, err := c.generateAccessToken(ctx, organization, serviceAccountID)
	if err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Spec.Expiry = &metav1.Time{Time: tokens.Expiry}
	updated.Spec.AccessToken = tokens.AccessToken

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, fmt.Errorf("%w: failed to patch group", err)
	}

	c.oauth2.InvalidateToken(ctx, current.Spec.AccessToken)

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	return convertCreate(updated, groups), nil
}

// Delete removes the service account and revokes the access token.
func (c *Client) Delete(ctx context.Context, organizationID, serviceAccountID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: failed to get service account for delete", err)
	}

	// Unlink the service account from any groups that reference it.
	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return err
	}

	if err := c.updateGroups(ctx, serviceAccountID, nil, groups); err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: failed to delete service account", err)
	}

	c.oauth2.InvalidateToken(ctx, resource.Spec.AccessToken)

	return nil
}
