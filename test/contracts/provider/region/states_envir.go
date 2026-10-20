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

package region_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// errUnknownState reports a state name a handler doesn't seed, so a typo fails instead of passing empty.
var errUnknownState = errors.New("unknown provider state")

// Provider states named by the nscale-environments (Envir) consumer pact.
const (
	StateCallerHasProjectAccess = "the caller has access to a project in the organization"
	StateServiceAccountBearer   = "the bearer belongs to a service account in the organization"
	StateUserBearer             = "the bearer belongs to a user in the organization"
	StateSystemBearer           = "the bearer belongs to a system client"
	StateOrganizationNoProject  = "the organization exists without the project"
	StateNoAutomationIdentity   = "the organization has no Envir automation identity"
	StateAutomationGroupOnly    = "the Envir automation group exists without a service account"
	StateAutomationAccountBound = "the Envir automation service account is bound to its group"
	StateExpiredBearer          = "the bearer's token has expired"
	defaultEnvirOrganizationID  = "9a8c6370-4065-4d4a-9da0-7678df40cd9d"
	defaultEnvirProjectID       = "e36c058a-8eba-4f5b-91f4-f6ffb983795c"
	serviceAccountTokenLifetime = time.Hour
)

// envirBearer is the token an Envir state issued; the request filter presents it in place of the
// pact's example bearer on userinfo and /api/v1/acl, and its presence routes /api/v1/acl through
// production authentication and RBAC rather than the mock ACL. Each state sets it on setup and
// clears it on teardown; verification is serial (-p 1), so one value is enough.
//
//nolint:gochecknoglobals
var envirBearer = &bearerState{}

type bearerState struct {
	lock  sync.Mutex
	token string
}

func (s *bearerState) set(token string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.token = token
}

func (s *bearerState) get() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.token
}

// automationParams are the ids, name and owner tag of the identity Envir provisions.
type automationParams struct {
	organizationID   string
	groupID          string
	serviceAccountID string
	roleID           string
	name             string
	tag              unikornv1core.Tag
}

func readAutomationParams(params map[string]any) automationParams {
	p := unwrapPactParams(params)

	return automationParams{
		organizationID:   getStringParam(p, "organizationID", defaultEnvirOrganizationID),
		groupID:          getStringParam(p, "groupID", "5c1d9a2e-7b3f-4e8a-9d6c-2f4b8e1a7c30"),
		serviceAccountID: getStringParam(p, "serviceAccountID", "8e2f4a6c-1d3b-4f5e-a7c9-0b2d4f6e8a1c"),
		roleID:           getStringParam(p, "roleID", "f7a67bc1-6851-4ae1-8e35-43164d5870c1"),
		name:             getStringParam(p, "name", "envir-automation"),
		tag: unikornv1core.Tag{
			Name:  getStringParam(p, "tagName", "envir.nscale.com/owner"),
			Value: getStringParam(p, "tagValue", "resource-manager"),
		},
	}
}

// SetupTokenIssuer installs a signing key and returns the JWT issuer and authenticator, so the
// handlers that issue or verify tokens (service account creation, userinfo) run for real.
func SetupTokenIssuer(ctx context.Context, k8sClient client.Client, issuer common.IssuerValue) (*jose.JWTIssuer, *oauth2.Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signingKey := &unikornv1.SigningKey{ObjectMeta: metav1.ObjectMeta{Namespace: TestNamespace, Name: jose.SigningKeyName}}

	// Create or replace in place: deleting and recreating would race the asynchronous deletion.
	if _, err := controllerutil.CreateOrUpdate(ctx, k8sClient, signingKey, func() error {
		signingKey.Spec.PrivateKeys = []unikornv1.PrivateKey{{PEM: pemKey}}

		return nil
	}); err != nil {
		return nil, nil, err
	}

	jwtIssuer := jose.NewJWTIssuer(k8sClient, TestNamespace, &jose.Options{})
	options := &oauth2.Options{AccessTokenDuration: time.Hour, TokenCacheSize: 16, CodeCacheSize: 16}

	users := userdb.NewUserDatabase(k8sClient, TestNamespace)

	authenticator, err := oauth2.New(options, TestNamespace, issuer, k8sClient, k8sClient, jwtIssuer, users, nil)
	if err != nil {
		return nil, nil, err
	}

	return jwtIssuer, authenticator, nil
}

// setupEnvirOrganization clears whatever an earlier run of the state left behind, including after a
// skipped teardown, then creates the organization afresh, so setup never depends on order or history.
func (sm *StateManager) setupEnvirOrganization(ctx context.Context, orgID string) error {
	if err := sm.cleanupEnvirOrganization(ctx, orgID); err != nil {
		return err
	}

	return sm.setupOrganization(ctx, orgID)
}

// cleanupEnvirOrganization removes the groups and service accounts an Envir state seeded or an
// interaction created, then the organization.
func (sm *StateManager) cleanupEnvirOrganization(ctx context.Context, orgID string) error {
	namespace := sm.getOrganizationNamespace(ctx, orgID)

	if err := sm.client.DeleteAllOf(ctx, &unikornv1.ServiceAccount{}, client.InNamespace(namespace)); err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete service accounts in %s: %w", namespace, err)
	}

	if err := sm.client.DeleteAllOf(ctx, &unikornv1.Group{}, client.InNamespace(namespace)); err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete groups in %s: %w", namespace, err)
	}

	return sm.cleanupOrganization(ctx, orgID)
}

// aclRoleScopes is what the ACL state's role grants: something in the organization and in the
// project, so both carry endpoints in the caller's ACL.
//
//nolint:gochecknoglobals
var aclRoleScopes = unikornv1.RoleScopes{
	Organization: []unikornv1.RoleScope{{Name: "identity:projects", Operations: []unikornv1.Operation{unikornv1.Read}}},
	Project:      []unikornv1.RoleScope{{Name: "identity:serviceaccounts", Operations: []unikornv1.Operation{unikornv1.Read}}},
}

// HandleCallerHasProjectAccess seeds a caller whose ACL production RBAC computes: a service account
// holding a real token, in a group whose role grants organization and project scopes, with the
// group linked to the project. /api/v1/acl then runs real authentication and RBAC for that bearer.
func (sm *StateManager) HandleCallerHasProjectAccess(ctx context.Context, setup bool, params map[string]any, authenticator *oauth2.Authenticator, issuer common.IssuerValue) error {
	p := readAutomationParams(params)
	projectID := getStringParam(unwrapPactParams(params), "projectID", defaultEnvirProjectID)

	if !setup {
		envirBearer.set("")

		if err := sm.deleteRole(ctx, p.roleID); err != nil {
			return err
		}

		return sm.cleanupEnvirOrganization(ctx, p.organizationID)
	}

	if err := sm.setupEnvirOrganization(ctx, p.organizationID); err != nil {
		return err
	}

	if err := sm.setupProject(ctx, p.organizationID, projectID); err != nil {
		return err
	}

	if err := sm.createRole(ctx, p.roleID, aclRoleScopes); err != nil {
		return err
	}

	token, err := sm.createServiceAccountWithToken(ctx, p, authenticator, issuer, serviceAccountTokenLifetime)
	if err != nil {
		return err
	}

	if err := sm.createGroup(ctx, p, []string{p.serviceAccountID}); err != nil {
		return err
	}

	if err := sm.linkGroupToProject(ctx, p.organizationID, projectID, p.groupID); err != nil {
		return err
	}

	envirBearer.set(token)

	return nil
}

func (sm *StateManager) linkGroupToProject(ctx context.Context, orgID, projectID, groupID string) error {
	project := &unikornv1.Project{}
	if err := sm.client.Get(ctx, client.ObjectKey{Namespace: sm.getOrganizationNamespace(ctx, orgID), Name: projectID}, project); err != nil {
		return fmt.Errorf("failed to read project %s: %w", projectID, err)
	}

	project.Spec.GroupIDs = []string{groupID}

	if err := sm.client.Update(ctx, project); err != nil {
		return fmt.Errorf("failed to link group %s to project %s: %w", groupID, projectID, err)
	}

	return nil
}

// HandleExpiredBearer seeds the service account as HandleServiceAccountBearer does, but its token,
// signed by the real issuer, expired an hour ago, so userinfo rejects it as it rejects any expired token.
func (sm *StateManager) HandleExpiredBearer(ctx context.Context, setup bool, params map[string]any, authenticator *oauth2.Authenticator, issuer common.IssuerValue) error {
	p := readAutomationParams(params)

	if !setup {
		envirBearer.set("")

		return sm.cleanupEnvirOrganization(ctx, p.organizationID)
	}

	if err := sm.setupEnvirOrganization(ctx, p.organizationID); err != nil {
		return err
	}

	token, err := sm.createServiceAccountWithToken(ctx, p, authenticator, issuer, -time.Hour)
	if err != nil {
		return err
	}

	envirBearer.set(token)

	return nil
}

// HandleServiceAccountBearer creates a service account holding a token issued the way service
// account creation issues one, and hands that token to the verifier's request filter.
func (sm *StateManager) HandleServiceAccountBearer(ctx context.Context, setup bool, params map[string]any, authenticator *oauth2.Authenticator, issuer common.IssuerValue) error {
	p := readAutomationParams(params)

	if !setup {
		envirBearer.set("")

		return sm.cleanupEnvirOrganization(ctx, p.organizationID)
	}

	if err := sm.setupEnvirOrganization(ctx, p.organizationID); err != nil {
		return err
	}

	token, err := sm.createServiceAccountWithToken(ctx, p, authenticator, issuer, serviceAccountTokenLifetime)
	if err != nil {
		return err
	}

	envirBearer.set(token)

	return nil
}

// createServiceAccountWithToken creates the service account holding a token issued the way service
// account creation issues one, and returns the token. A negative lifetime issues an expired token.
func (sm *StateManager) createServiceAccountWithToken(ctx context.Context, p automationParams, authenticator *oauth2.Authenticator, issuer common.IssuerValue, lifetime time.Duration) (string, error) {
	tokens, err := authenticator.Issue(ctx, &oauth2.IssueInfo{
		Issuer:         issuer.URL,
		Audience:       issuer.Hostname,
		Subject:        p.serviceAccountID,
		Type:           oauth2.TokenTypeServiceAccount,
		ServiceAccount: &oauth2.ServiceAccountClaims{OrganizationID: p.organizationID},
		Duration:       &lifetime,
	})
	if err != nil {
		return "", fmt.Errorf("failed to issue service account token: %w", err)
	}

	if err := sm.createServiceAccount(ctx, p, tokens.AccessToken, tokens.Expiry); err != nil {
		return "", err
	}

	return tokens.AccessToken, nil
}

func (sm *StateManager) HandleOrganizationWithoutProject(ctx context.Context, setup bool, params map[string]any) error {
	orgID := getStringParam(unwrapPactParams(params), "organizationID", defaultEnvirOrganizationID)

	if !setup {
		return sm.cleanupEnvirOrganization(ctx, orgID)
	}

	return sm.setupEnvirOrganization(ctx, orgID)
}

// HandleAutomationIdentity seeds the organization and the role Envir's automation group holds,
// then the group and service account as far as the named state goes.
func (sm *StateManager) HandleAutomationIdentity(ctx context.Context, state string, setup bool, params map[string]any) error {
	p := readAutomationParams(params)

	if !setup {
		if err := sm.deleteRole(ctx, p.roleID); err != nil {
			return err
		}

		return sm.cleanupEnvirOrganization(ctx, p.organizationID)
	}

	if err := sm.setupEnvirOrganization(ctx, p.organizationID); err != nil {
		return err
	}

	if err := sm.createRole(ctx, p.roleID, unikornv1.RoleScopes{}); err != nil {
		return err
	}

	switch state {
	case StateAutomationGroupOnly:
		return sm.createGroup(ctx, p, nil)
	case StateAutomationAccountBound:
		if err := sm.createServiceAccount(ctx, p, "", time.Now().Add(serviceAccountTokenLifetime)); err != nil {
			return err
		}

		return sm.createGroup(ctx, p, []string{p.serviceAccountID})
	case StateNoAutomationIdentity:
		return nil
	}

	return fmt.Errorf("%w: %q is not an Envir automation state", errUnknownState, state)
}

// organizationScopedMeta names a resource the way uni-identity's create path does: the id is the
// object name, the display name and organization are labels.
func (sm *StateManager) organizationScopedMeta(ctx context.Context, orgID, id, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: sm.getOrganizationNamespace(ctx, orgID),
		Name:      id,
		Labels: map[string]string{
			constants.NameLabel:         name,
			constants.OrganizationLabel: orgID,
		},
	}
}

func (sm *StateManager) createServiceAccount(ctx context.Context, p automationParams, token string, expiry time.Time) error {
	account := &unikornv1.ServiceAccount{
		ObjectMeta: sm.organizationScopedMeta(ctx, p.organizationID, p.serviceAccountID, p.name),
		Spec: unikornv1.ServiceAccountSpec{
			Tags:        unikornv1core.TagList{p.tag},
			AccessToken: token,
			Expiry:      &metav1.Time{Time: expiry},
		},
	}

	if err := sm.client.Create(ctx, account); err != nil {
		return fmt.Errorf("failed to create service account %s: %w", p.serviceAccountID, err)
	}

	return nil
}

func (sm *StateManager) createGroup(ctx context.Context, p automationParams, serviceAccountIDs []string) error {
	group := &unikornv1.Group{
		ObjectMeta: sm.organizationScopedMeta(ctx, p.organizationID, p.groupID, p.name),
		Spec: unikornv1.GroupSpec{
			Tags:              unikornv1core.TagList{p.tag},
			RoleIDs:           []string{p.roleID},
			ServiceAccountIDs: serviceAccountIDs,
		},
	}

	if err := sm.client.Create(ctx, group); err != nil {
		return fmt.Errorf("failed to create group %s: %w", p.groupID, err)
	}

	return nil
}

// createRole seeds an unprotected role, so any caller may grant it, with exactly the given scopes;
// a role an earlier run left behind is overwritten rather than reused as it was.
func (sm *StateManager) createRole(ctx context.Context, roleID string, scopes unikornv1.RoleScopes) error {
	role := &unikornv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: sm.namespace, Name: roleID}}

	if _, err := controllerutil.CreateOrUpdate(ctx, sm.client, role, func() error {
		role.Labels = map[string]string{constants.NameLabel: "envir-automation"}
		role.Spec = unikornv1.RoleSpec{Scopes: scopes}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to create role %s: %w", roleID, err)
	}

	return nil
}

func (sm *StateManager) deleteRole(ctx context.Context, roleID string) error {
	role := &unikornv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: sm.namespace, Name: roleID}}
	if err := sm.client.Delete(ctx, role); err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete role %s: %w", roleID, err)
	}

	return nil
}

// HandleUserBearer seeds an active member of the organization whose session holds a federated access
// token, as login leaves it, and hands that token to the verifier's request filter.
func (sm *StateManager) HandleUserBearer(ctx context.Context, setup bool, params map[string]any, authenticator *oauth2.Authenticator, issuer common.IssuerValue) error {
	p := unwrapPactParams(params)
	orgID := getStringParam(p, "organizationID", defaultEnvirOrganizationID)
	userID := getStringParam(p, "userID", "3f9b2c1d-4e5a-4b6c-8d7e-9f0a1b2c3d4e")
	subject := getStringParam(p, "subject", "envir-user@example.com")

	if !setup {
		envirBearer.set("")

		return sm.cleanupUserBearer(ctx, orgID, userID)
	}

	// The user lives in the shared namespace, not the organization's, so clear it explicitly.
	if err := sm.cleanupUserBearer(ctx, orgID, userID); err != nil {
		return err
	}

	if err := sm.setupOrganization(ctx, orgID); err != nil {
		return err
	}

	token, err := sm.createUserSession(ctx, userID, subject, authenticator, issuer)
	if err != nil {
		return err
	}

	if err := sm.addOrganizationMember(ctx, orgID, userID); err != nil {
		return err
	}

	envirBearer.set(token)

	return nil
}

// createUserSession creates an active user and records a session holding a federated token issued
// for it. Issuing reads the user, so it must exist first; login records the token afterwards too.
func (sm *StateManager) createUserSession(ctx context.Context, userID, subject string, authenticator *oauth2.Authenticator, issuer common.IssuerValue) (string, error) {
	const clientID = "envir-contract"

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: sm.namespace, Name: userID},
		Spec:       unikornv1.UserSpec{Subject: subject, State: unikornv1.UserStateActive},
	}

	if err := sm.client.Create(ctx, user); err != nil {
		return "", fmt.Errorf("failed to create user %s: %w", userID, err)
	}

	tokens, err := authenticator.Issue(ctx, &oauth2.IssueInfo{
		Issuer:   issuer.URL,
		Audience: issuer.Hostname,
		Subject:  subject,
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			ClientID: clientID,
			UserID:   userID,
			Provider: "contract-test",
			Scope:    oauth2.NewScope("openid email"),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to issue user token: %w", err)
	}

	if err := sm.client.Get(ctx, client.ObjectKeyFromObject(user), user); err != nil {
		return "", fmt.Errorf("failed to read user %s: %w", userID, err)
	}

	user.Spec.Sessions = []unikornv1.UserSession{{ClientID: clientID, AccessToken: tokens.AccessToken}}

	if err := sm.client.Update(ctx, user); err != nil {
		return "", fmt.Errorf("failed to record session for user %s: %w", userID, err)
	}

	return tokens.AccessToken, nil
}

// addOrganizationMember makes the user one "in the organization": userinfo lists it in orgIds.
func (sm *StateManager) addOrganizationMember(ctx context.Context, orgID, userID string) error {
	membership := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: sm.getOrganizationNamespace(ctx, orgID),
			Name:      userID,
			Labels: map[string]string{
				constants.OrganizationLabel: orgID,
				constants.UserLabel:         userID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
	}

	if err := sm.client.Create(ctx, membership); err != nil {
		return fmt.Errorf("failed to add user %s to organization %s: %w", userID, orgID, err)
	}

	return nil
}

func (sm *StateManager) cleanupUserBearer(ctx context.Context, orgID, userID string) error {
	user := &unikornv1.User{ObjectMeta: metav1.ObjectMeta{Namespace: sm.namespace, Name: userID}}
	if err := sm.client.Delete(ctx, user); err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete user %s: %w", userID, err)
	}

	namespace := sm.getOrganizationNamespace(ctx, orgID)
	if err := sm.client.DeleteAllOf(ctx, &unikornv1.OrganizationUser{}, client.InNamespace(namespace)); err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete organization users in %s: %w", namespace, err)
	}

	return sm.cleanupEnvirOrganization(ctx, orgID)
}

// HandleSystemBearer hands the verifier a service token, as the client_credentials grant issues
// one to a system client; it is verified by signature alone.
func (sm *StateManager) HandleSystemBearer(ctx context.Context, setup bool, params map[string]any, authenticator *oauth2.Authenticator, issuer common.IssuerValue) error {
	if !setup {
		envirBearer.set("")

		return nil
	}

	tokens, err := authenticator.Issue(ctx, &oauth2.IssueInfo{
		Issuer:   issuer.URL,
		Audience: issuer.Hostname,
		Subject:  getStringParam(unwrapPactParams(params), "subject", "envir-resource-manager"),
		Type:     oauth2.TokenTypeService,
		Service:  &oauth2.ServiceClaims{X509Thumbprint: "contract-test"},
	})
	if err != nil {
		return fmt.Errorf("failed to issue system token: %w", err)
	}

	envirBearer.set(tokens.AccessToken)

	return nil
}
