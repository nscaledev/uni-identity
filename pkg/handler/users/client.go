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

package users

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/pflag"
	gomail "gopkg.in/gomail.v2"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/html"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
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
	// commonOptions contains shared handler configuration (issuer, hostname, etc.).
	issuer common.IssuerValue
	// client is the Kubernetes client.
	client client.Client
	// namespace is the namespace the identity service is running in.
	namespace string
	// jwtIssuer for creating signup tokens.
	jwtIssuer *jose.JWTIssuer
	// options are any options to be passed to the handler.
	options *Options
}

// New creates a new user client.
func New(client client.Client, namespace string, jwtIssuer *jose.JWTIssuer, issuer common.IssuerValue, options *Options) *Client {
	return &Client{
		issuer:    issuer,
		client:    client,
		namespace: namespace,
		jwtIssuer: jwtIssuer,
		options:   options,
	}
}

// listGroups returns an exhaustive list of all groups a user can be a member of.
func (c *Client) listGroups(ctx context.Context, organization *organizations.Meta) (*unikornv1.GroupList, error) {
	result := &unikornv1.GroupList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list groups", err)
	}

	return result, nil
}

// removeFromGroup removes the UserID and subject records if they are present.
func removeFromGroup(subject unikornv1.GroupSubject, orgUserID string, updated *unikornv1.Group) bool {
	var needsPatching bool

	userIDs := slices.DeleteFunc(updated.Spec.UserIDs, func(id string) bool {
		return id == orgUserID
	})
	if len(userIDs) != len(updated.Spec.UserIDs) {
		updated.Spec.UserIDs = userIDs
		needsPatching = true
	}

	subjects := slices.DeleteFunc(updated.Spec.Subjects, func(sub unikornv1.GroupSubject) bool {
		return sub.ID == subject.ID && sub.Issuer == subject.Issuer
	})
	if len(subjects) != len(updated.Spec.Subjects) {
		updated.Spec.Subjects = subjects
		needsPatching = true
	}

	return needsPatching
}

// addToGroup adds the Subject and userID if not present.
func addToGroup(subject unikornv1.GroupSubject, orgUserID string, updated *unikornv1.Group) bool {
	var needsPatching bool
	// Add to a group where it should be a member but isn't.
	if !slices.Contains(updated.Spec.UserIDs, orgUserID) {
		updated.Spec.UserIDs = append(updated.Spec.UserIDs, orgUserID)
		needsPatching = true
	}

	if !slices.Contains(updated.Spec.Subjects, subject) {
		updated.Spec.Subjects = append(updated.Spec.Subjects, subject)
		needsPatching = true
	}

	return needsPatching
}

// updateGroups takes a user name and a requested list of groups and adds to
// the groups it should be a member of and removes itself from groups it shouldn't.
func (c *Client) updateGroups(ctx context.Context, globalUserID, orgUserID string, groupIDs openapi.GroupIDs, groups *unikornv1.GroupList) error {
	// find the subject, so we can add/remove that as well
	var user unikornv1.User
	if err := c.client.Get(ctx, client.ObjectKey{Name: globalUserID, Namespace: c.namespace}, &user); err != nil {
		return err
	}

	subject := unikornv1.GroupSubject{
		ID:     user.Spec.Subject,
		Email:  user.Spec.Subject,
		Issuer: "", // Issuer empty for local users
	}

	for i := range groups.Items {
		current := &groups.Items[i]
		updated := current.DeepCopy()

		var needsPatching bool

		if slices.Contains(groupIDs, current.Name) {
			needsPatching = addToGroup(subject, orgUserID, updated)
		} else {
			needsPatching = removeFromGroup(subject, orgUserID, updated)
		}

		if needsPatching {
			if err := c.client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
				return fmt.Errorf("%w: failed to patch group", err)
			}
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

		return nil, fmt.Errorf("%w: failed to get user", err)
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
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
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
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
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
			return nil, fmt.Errorf("%w: failed to lookup user", coreerrors.ErrConsistency)
		}

		out[i] = *convert(&in.Items[i], &users.Items[index], groups)
	}

	slices.SortStableFunc(out, func(a, b openapi.UserRead) int {
		return strings.Compare(a.Spec.Subject, b.Spec.Subject)
	})

	return out, nil
}

const (
	defaultEmailVerificationSubject = "Welcome to Unikorn Cloud!"
)

type emailConfiguration struct {
	subject string
	body    string
}

// getEmailVerification returns either the user defined subject and body,
// which allows branding and marketing, or a default fallback.
func (c *Client) getEmailVerification(ctx context.Context, verifyLink string) (*emailConfiguration, error) {
	if c.options.emailVerificationTemplateConfigMap == "" {
		defaultEmailVerificationBody, err := html.WelcomeEmail(verifyLink)
		if err != nil {
			return nil, err
		}

		out := &emailConfiguration{
			subject: defaultEmailVerificationSubject,
			body:    string(defaultEmailVerificationBody),
		}

		return out, nil
	}

	configMap := &corev1.ConfigMap{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: c.options.emailVerificationTemplateConfigMap}, configMap); err != nil {
		return nil, err
	}

	subject, ok := configMap.Data["subject"]
	if !ok {
		return nil, fmt.Errorf("%w: user verification email configmap missing subject", ErrConfiguration)
	}

	templateData, ok := configMap.Data["template"]
	if !ok {
		return nil, fmt.Errorf("%w: user verification email configmap missing template", ErrConfiguration)
	}

	t, err := template.New("welcome").Parse(templateData)
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"verifyLink": verifyLink,
	}

	body := &bytes.Buffer{}

	if err := t.Execute(body, data); err != nil {
		return nil, err
	}

	out := &emailConfiguration{
		subject: subject,
		body:    body.String(),
	}

	return out, nil
}

type smtpConfiguration struct {
	host     string
	port     int
	username string
	password string
}

// getSMTPConfiguration verifies and loads SMTP configuration.
func (c *Client) getSMTPConfiguration(ctx context.Context) (*smtpConfiguration, error) {
	host, portStr, err := net.SplitHostPort(c.options.smtpServer)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: c.options.smtpCredentialsSecret}, secret); err != nil {
		return nil, err
	}

	username, ok := secret.Data["username"]
	if !ok {
		return nil, fmt.Errorf("%w: smtp secret missing username", ErrConfiguration)
	}

	password, ok := secret.Data["password"]
	if !ok {
		return nil, fmt.Errorf("%w: smtp secret missing password", ErrConfiguration)
	}

	out := &smtpConfiguration{
		host:     host,
		port:     port,
		username: string(username),
		password: string(password),
	}

	return out, nil
}

// notifyGlobalUserCreation sends an email to the user asking them to click a link in order to
// verify themselves.
func (c *Client) notifyGlobalUserCreation(ctx context.Context, user *unikornv1.User) error {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return err
	}

	verifyLink := fmt.Sprintf("%s/api/v1/signup?token=%s&clientID=%s", c.issuer.URL, user.Spec.Signup.Token, info.ClientID)

	email, err := c.getEmailVerification(ctx, verifyLink)
	if err != nil {
		return err
	}

	smtp, err := c.getSMTPConfiguration(ctx)
	if err != nil {
		return err
	}

	m := gomail.NewMessage()
	m.SetHeader("From", smtp.username)
	m.SetAddressHeader("To", user.Spec.Subject, "New User")
	m.SetHeader("Subject", email.subject)
	m.SetBody("text/html", email.body)

	if err := gomail.NewDialer(smtp.host, smtp.port, smtp.username, smtp.password).DialAndSend(m); err != nil {
		return err
	}

	return nil
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
			Issuer:  c.issuer.URL,
			Subject: user.Spec.Subject,
			Audience: []string{
				user.Spec.Subject,
			},
			Expiry:   jwt.NewNumericDate(time.Now().Add(c.options.emailVerificationTokenDuration)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		UserID: user.Name,
	}

	token, err := c.jwtIssuer.EncodeJWEToken(ctx, claims, jose.TokenTypeUserSignupToken)
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

	if err := c.jwtIssuer.DecodeJWEToken(r.Context(), tokenRaw, claims, jose.TokenTypeUserSignupToken); err != nil {
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
		return nil, fmt.Errorf("%w: failed to get user", err)
	}

	return user, nil
}

func (c *Client) getGlobalUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	users := &unikornv1.UserList{}

	if err := c.client.List(ctx, users, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list users", err)
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
	log := log.FromContext(ctx)

	user, err := c.getGlobalUser(ctx, request.Spec.Subject)
	if err == nil {
		return user, nil
	}

	if !goerrors.Is(err, ErrReference) {
		return nil, fmt.Errorf("%w: failed to create global user", err)
	}

	resource, err := c.generateGlobalUser(ctx, request)
	if err != nil {
		return nil, err
	}

	if c.options.emailVerification {
		token, err := c.issueSignupToken(ctx, resource)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to create user sigup token", err)
		}

		// Force new signups into a pending state.
		resource.Spec.State = unikornv1.UserStatePending

		resource.Spec.Signup = &unikornv1.UserSignup{
			Token: token,
		}
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, fmt.Errorf("%w: failed to create user", err)
	}

	if c.options.emailVerification {
		if err := c.notifyGlobalUserCreation(ctx, resource); err != nil {
			// TODO: perhaps consider deleting the user immediately.
			log.Error(err, "failed to send user creation notification")
		}
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
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	resource, err := generateOrganizationUser(ctx, organization, request, user.Name)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, fmt.Errorf("%w: failed to create organization user", err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, user.Name, resource.Name, request.Spec.GroupIDs, groups); err != nil {
		return nil, err
	}

	return convert(resource, user, groups), nil
}

// List retrieves information about all users in the organization.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.Users, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	users := &unikornv1.UserList{}

	if err := c.client.List(ctx, users, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list users", err)
	}

	result := &unikornv1.OrganizationUserList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, fmt.Errorf("%w: failed to list users", err)
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
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
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
		return nil, fmt.Errorf("%w: failed to merge metadata", err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, fmt.Errorf("%w: failed to patch group", err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, user.Name, userID, request.Spec.GroupIDs, groups); err != nil {
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
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization, userID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: failed to get user for delete", err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return err
	}

	if err := c.updateGroups(ctx, resource.Labels[constants.UserLabel], userID, nil, groups); err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: failed to delete user", err)
	}

	return nil
}
