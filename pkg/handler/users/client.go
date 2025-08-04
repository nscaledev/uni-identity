/*
Copyright 2025 the Unikorn Authors.

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

package users

import (
	"context"
	goerrors "errors"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/html"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrConfiguration = goerrors.New("configuration error")

	ErrReference = goerrors.New("resource reference error")
)

type Options struct {
	// emailVerification defines whether to send an email notification.
	emailVerification bool
	// emailVerificationTokenDuration defines how long the email token lives for.
	emailVerificationTokenDuration time.Duration
	// emailVerificationTemplateConfigMap allows the administrator to define the
	// welcome email template and subject string.
	emailVerificationTemplateConfigMap string
	// smtpServer is the host:port of the SMTP server.
	smtpServer string
	// smtpCredentialsSecret is the username/password secret
	// to connect to SMTP as.
	smtpCredentialsSecret string
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.BoolVar(&o.emailVerification, "user-email-verification", false, "Whether to enable user creation email notifications and verification.")
	f.DurationVar(&o.emailVerificationTokenDuration, "user-email-verification-token-duration", 24*time.Hour, "How long the user has to sign up before the token is revoked.")
	f.StringVar(&o.emailVerificationTemplateConfigMap, "user-email-verification-template-configmap", "", "ConfigMap containing subject and template for email account verification.")
	f.StringVar(&o.smtpServer, "smtp-server", "", "SMTP server host:port.")
	f.StringVar(&o.smtpCredentialsSecret, "smtp-credentials-secret", "unikorn-smtp-credentials", "Secret containing username and password keys for SMTP verification.")
}

// Client is responsible for user management.
type Client struct {
	// host is the hostname of this service.
	host string
	// client is the Kubernetes client.
	client client.Client
	// namespace is the namespace the identity service is running in.
	namespace string
	// issuer for creating signup tokens.
	issuer *jose.JWTIssuer
	pdp    rbac.PolicyDecisionPoint
	// options are any options to be passed to the handler.
	options *Options
}

// New creates a new user client.
func New(host string, client client.Client, namespace string, issuer *jose.JWTIssuer, pdp rbac.PolicyDecisionPoint, options *Options) *Client {
	return &Client{
		host:      host,
		client:    client,
		namespace: namespace,
		issuer:    issuer,
		pdp:       pdp,
		options:   options,
	}
}

// listGroups returns an exhaustive list of all groups a user can be a member of.
func (c *Client) listGroups(ctx context.Context, organization *organizations.Meta) (*unikornv1.GroupList, error) {
	result := &unikornv1.GroupList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list groups").WithError(err)
	}

	return result, nil
}

// updateGroups takes a user name and a requested list of groups and adds to
// the groups it should be a member of and removes itself from groups it shouldn't.
func (c *Client) updateGroups(ctx context.Context, userID string, groupIDs openapi.GroupIDs, groups *unikornv1.GroupList) error {
	for i := range groups.Items {
		current := &groups.Items[i]

		updated := current.DeepCopy()

		if slices.Contains(groupIDs, current.Name) {
			// Add to a group where it should be a member but isn't.
			if slices.Contains(current.Spec.UserIDs, userID) {
				continue
			}

			updated.Spec.UserIDs = append(updated.Spec.UserIDs, userID)
		} else {
			// Remove from any groups its a member of but shouldn't be.
			if !slices.Contains(current.Spec.UserIDs, userID) {
				continue
			}

			updated.Spec.UserIDs = slices.DeleteFunc(updated.Spec.UserIDs, func(id string) bool {
				return id == userID
			})
		}

		if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
			return errors.OAuth2ServerError("failed to patch group").WithError(err)
		}
	}

	return nil
}

func (c *Client) get(ctx context.Context, organization *organizations.Meta, userID string) (*unikornv1.OrganizationUser, error) {
	result := &unikornv1.OrganizationUser{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: userID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get user").WithError(err)
	}

	return result, nil
}

func generateUserState(in openapi.UserState) unikornv1.UserState {
	switch in {
	case openapi.Active:
		return unikornv1.UserStateActive
	case openapi.Pending:
		return unikornv1.UserStatePending
	case openapi.Suspended:
		return unikornv1.UserStateSuspended
	}

	return ""
}

func (c *Client) generateGlobalUser(ctx context.Context, in *openapi.UserWrite) (*unikornv1.User, error) {
	metadata := &coreopenapi.ResourceWriteMetadata{
		Name: constants.UndefinedName,
	}

	out := &unikornv1.User{
		ObjectMeta: conversion.NewObjectMetadata(metadata, c.namespace).Get(),
		Spec: unikornv1.UserSpec{
			Subject: in.Spec.Subject,
			State:   unikornv1.UserStateActive,
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	if in.Metadata != nil {
		out.Spec.Tags = conversion.GenerateTagList(in.Metadata.Tags)
	}

	return out, nil
}

func generateOrganizationUser(ctx context.Context, organization *organizations.Meta, in *openapi.UserWrite, userID string) (*unikornv1.OrganizationUser, error) {
	metadata := &coreopenapi.ResourceWriteMetadata{
		Name: constants.UndefinedName,
	}

	out := &unikornv1.OrganizationUser{
		ObjectMeta: conversion.NewObjectMetadata(metadata, organization.Namespace).WithOrganization(organization.ID).WithLabel(constants.UserLabel, userID).Get(),
		Spec: unikornv1.OrganizationUserSpec{
			State: generateUserState(in.Spec.State),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

func convertUserState(in unikornv1.UserState) openapi.UserState {
	switch in {
	case unikornv1.UserStateActive:
		return openapi.Active
	case unikornv1.UserStatePending:
		return openapi.Pending
	case unikornv1.UserStateSuspended:
		return openapi.Suspended
	}

	return ""
}

func convert(in *unikornv1.OrganizationUser, user *unikornv1.User, groups *unikornv1.GroupList) *openapi.UserRead {
	out := &openapi.UserRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.UserSpec{
			Subject:  user.Spec.Subject,
			State:    convertUserState(in.Spec.State),
			GroupIDs: make(openapi.GroupIDs, 0, len(groups.Items)),
		},
	}

	var lastActive *metav1.Time

	for _, session := range user.Spec.Sessions {
		if session.LastAuthentication == nil {
			continue
		}

		if lastActive == nil {
			lastActive = session.LastAuthentication
			continue
		}

		if session.LastAuthentication.After(lastActive.Time) {
			lastActive = session.LastAuthentication
		}
	}

	if lastActive != nil {
		out.Status.LastActive = &lastActive.Time
	}

	for _, group := range groups.Items {
		if slices.Contains(group.Spec.UserIDs, in.Name) {
			out.Spec.GroupIDs = append(out.Spec.GroupIDs, group.Name)
		}
	}

	return out
}

func convertList(in *unikornv1.OrganizationUserList, users *unikornv1.UserList, groups *unikornv1.GroupList) (openapi.Users, error) {
	out := make(openapi.Users, len(in.Items))

	for i := range in.Items {
		index := slices.IndexFunc(users.Items, func(user unikornv1.User) bool {
			return user.Name == in.Items[i].Labels[constants.UserLabel]
		})

		if index < 0 {
			return nil, errors.OAuth2ServerError("failed to lookup user")
		}

		out[i] = *convert(&in.Items[i], &users.Items[index], groups)
	}

	slices.SortStableFunc(out, func(a, b openapi.UserRead) int {
		return strings.Compare(a.Spec.Subject, b.Spec.Subject)
	})

	return out, nil
}

type SignupClaims struct {
	jwt.Claims `json:",inline"`

	UserID string `json:"unikorn:uid"`
}

// issueSignupToken creates a time limited, single use token that's valid for email account
// verification.
func (c *Client) issueSignupToken(ctx context.Context, user *unikornv1.User) (string, error) {
	claims := &SignupClaims{
		Claims: jwt.Claims{
			Issuer:  "https://" + c.host,
			Subject: user.Spec.Subject,
			Audience: []string{
				user.Spec.Subject,
			},
			Expiry:   jwt.NewNumericDate(time.Now().Add(c.options.emailVerificationTokenDuration)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		UserID: user.Name,
	}

	token, err := c.issuer.EncodeJWEToken(ctx, claims, jose.TokenTypeUserSignupToken)
	if err != nil {
		return "", err
	}

	return token, nil
}

func handleErrorFallback(w http.ResponseWriter, r *http.Request, short, message string) {
	log := log.FromContext(r.Context())

	body, err := html.Error(short, message)
	if err != nil {
		log.Info("user: failed to render error page")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusInternalServerError)

	if _, err := w.Write(body); err != nil {
		log.Info("user: failed to write HTML response")
		return
	}
}

// handleError routes the error to the correct page for the registered client.
func (c *Client) handleError(w http.ResponseWriter, r *http.Request, cli *unikornv1.OAuth2Client, short, message string) {
	log := log.FromContext(r.Context())

	if cli.Spec.ErrorURI == nil {
		handleErrorFallback(w, r, short, message)
		return
	}

	query := url.Values{}
	query.Set("error", short)
	query.Set("message", message)

	url, err := url.Parse(*cli.Spec.ErrorURI)
	if err != nil {
		log.Error(err, "failed to parse error URI", "clientID", cli.Name)
		handleErrorFallback(w, r, short, message)

		return
	}

	url.RawQuery = query.Encode()

	http.Redirect(w, r, url.String(), http.StatusFound)
}

// Signup is called when a user clicks on the email verification link, it verifies the token is
// valid, and transitions the user into an active state.
func (c *Client) Signup(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	tokenRaw := query.Get("token")
	clientID := query.Get("clientID")

	cli := &unikornv1.OAuth2Client{}

	if err := c.client.Get(r.Context(), client.ObjectKey{Namespace: c.namespace, Name: clientID}, cli); err != nil {
		handleErrorFallback(w, r, "user signup failure", "unable to lookup oauth2 client")

		return
	}

	claims := &SignupClaims{}

	if err := c.issuer.DecodeJWEToken(r.Context(), tokenRaw, claims, jose.TokenTypeUserSignupToken); err != nil {
		// TODO: has it expired?  Issue a new one!
		c.handleError(w, r, cli, "user signup failure", "error decoding token")
		return
	}

	user := &unikornv1.User{}

	if err := c.client.Get(r.Context(), client.ObjectKey{Namespace: c.namespace, Name: claims.UserID}, user); err != nil {
		c.handleError(w, r, cli, "user signup failure", "error looking up user")
		return
	}

	user.Spec.State = unikornv1.UserStateActive
	user.Spec.Signup = nil

	if err := c.client.Update(r.Context(), user); err != nil {
		c.handleError(w, r, cli, "user signup failure", "error activating user")
		return
	}

	if cli.Spec.HomeURI == nil {
		c.handleError(w, r, cli, "user signup error", "user active but client redirect not set")
		return
	}

	http.Redirect(w, r, *cli.Spec.HomeURI, http.StatusFound)
}

func (c *Client) getGlobalUserByID(ctx context.Context, id string) (*unikornv1.User, error) {
	user := &unikornv1.User{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: id}, user); err != nil {
		return nil, errors.OAuth2ServerError("failed to get user").WithError(err)
	}

	return user, nil
}

func (c *Client) getGlobalUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	users := &unikornv1.UserList{}

	if err := c.client.List(ctx, users, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list users").WithError(err)
	}

	index := slices.IndexFunc(users.Items, func(user unikornv1.User) bool {
		return user.Spec.Subject == subject
	})

	if index < 0 {
		return nil, ErrReference
	}

	return &users.Items[index], nil
}

func (c *Client) getOrCreateGlobalUser(ctx context.Context, request *openapi.UserWrite) (*unikornv1.User, error) {
	user, err := c.getGlobalUser(ctx, request.Spec.Subject)
	if err == nil {
		return user, nil
	}

	if !goerrors.Is(err, ErrReference) {
		return nil, errors.OAuth2ServerError("failed to create global user").WithError(err)
	}

	resource, err := c.generateGlobalUser(ctx, request)
	if err != nil {
		return nil, err
	}

	if c.options.emailVerification {
		token, err := c.issueSignupToken(ctx, resource)
		if err != nil {
			return nil, errors.OAuth2ServerError("failed to create user sigup token").WithError(err)
		}

		// Force new signups into a pending state.
		resource.Spec.State = unikornv1.UserStatePending

		resource.Spec.Signup = &unikornv1.UserSignup{
			Token: token,
		}
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("failed to create user").WithError(err)
	}

	return resource, nil
}

// Create makes a new user.  This creates a new user in an organization, but they
// reference a unique user resource, so we need to get or create the underlying record
// first, then add to the organization.
func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.UserWrite) (*openapi.UserRead, error) {
	// Any accounts that aren't email based must use kubectl-unikorn to create them,
	// e.g. users for unikorn services.
	if _, err := mail.ParseAddress(request.Spec.Subject); err != nil {
		return nil, errors.OAuth2InvalidRequest("subject address invalid").WithError(err)
	}

	user, err := c.getOrCreateGlobalUser(ctx, request)
	if err != nil {
		return nil, err
	}

	// Create the organization user.
	organization, err := organizations.New(c.client, c.namespace, c.pdp).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	resource, err := generateOrganizationUser(ctx, organization, request, user.Name)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("failed to create organization user").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, resource.Name, request.Spec.GroupIDs, groups); err != nil {
		return nil, err
	}

	return convert(resource, user, groups), nil
}

// List retrieves information about all users in the organization.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.Users, error) {
	organization, err := organizations.New(c.client, c.namespace, c.pdp).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	users := &unikornv1.UserList{}

	if err := c.client.List(ctx, users, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list users").WithError(err)
	}

	result := &unikornv1.OrganizationUserList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list users").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	return convertList(result, users, groups)
}

// Update modifies any metadata for the user if it exists.  If a matching account
// doesn't exist it raises an error.
func (c *Client) Update(ctx context.Context, organizationID, userID string, request *openapi.UserWrite) (*openapi.UserRead, error) {
	organization, err := organizations.New(c.client, c.namespace, c.pdp).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, err := c.get(ctx, organization, userID)
	if err != nil {
		return nil, err
	}

	user, err := c.getGlobalUserByID(ctx, current.Labels[constants.UserLabel])
	if err != nil {
		return nil, err
	}

	required, err := generateOrganizationUser(ctx, organization, request, current.Labels[constants.UserLabel])
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator); err != nil {
		return nil, errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch group").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, userID, request.Spec.GroupIDs, groups); err != nil {
		return nil, err
	}

	// Reload post update...
	if groups, err = c.listGroups(ctx, organization); err != nil {
		return nil, err
	}

	return convert(updated, user, groups), nil
}

// Delete removes the user and revokes the access token.
func (c *Client) Delete(ctx context.Context, organizationID, userID string) error {
	organization, err := organizations.New(c.client, c.namespace, c.pdp).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization, userID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to get user for delete").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return err
	}

	if err := c.updateGroups(ctx, userID, nil, groups); err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete user").WithError(err)
	}

	return nil
}
