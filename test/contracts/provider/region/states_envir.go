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
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"time"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Provider states named by the nscale-environments (Envir) consumer pact.
const (
	StateCallerHasProjectAccess = "the caller has access to a project in the organization"
	StateServiceAccountBearer   = "the bearer belongs to a service account in the organization"
	StateOrganizationNoProject  = "the organization exists without the project"
	StateNoAutomationIdentity   = "the organization has no Envir automation identity"
	StateAutomationGroupOnly    = "the Envir automation group exists without a service account"
	StateAutomationAccountBound = "the Envir automation service account is bound to its group"
	defaultEnvirOrganizationID  = "9a8c6370-4065-4d4a-9da0-7678df40cd9d"
	defaultEnvirProjectID       = "e36c058a-8eba-4f5b-91f4-f6ffb983795c"
	serviceAccountTokenLifetime = time.Hour
)

// envirAuth carries what the Envir states hand to the request path: the organization and project
// the mock ACL must grant on /api/v1/acl, and the bearer the verifier substitutes on userinfo.
//
//nolint:gochecknoglobals
var envirAuth = &envirAuthState{}

type envirAuthState struct {
	lock           sync.Mutex
	organizationID string
	projectID      string
	bearer         string
}

func (s *envirAuthState) set(organizationID, projectID, bearer string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.organizationID, s.projectID, s.bearer = organizationID, projectID, bearer
}

func (s *envirAuthState) get() (string, string, string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.organizationID, s.projectID, s.bearer
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
func SetupTokenIssuer(ctx context.Context, k8sClient client.Client, issuer common.IssuerValue) (*oauth2.Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	signingKey := &unikornv1.SigningKey{
		ObjectMeta: metav1.ObjectMeta{Namespace: TestNamespace, Name: jose.SigningKeyName},
		Spec: unikornv1.SigningKeySpec{
			PrivateKeys: []unikornv1.PrivateKey{{PEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}},
		},
	}

	if err := k8sClient.Delete(ctx, signingKey); err != nil && !kerrors.IsNotFound(err) {
		return nil, err
	}

	if err := k8sClient.Create(ctx, signingKey); err != nil {
		return nil, err
	}

	jwtIssuer := jose.NewJWTIssuer(k8sClient, TestNamespace, &jose.Options{})
	options := &oauth2.Options{AccessTokenDuration: time.Hour, TokenCacheSize: 16, CodeCacheSize: 16}

	return oauth2.New(options, TestNamespace, issuer, k8sClient, k8sClient, jwtIssuer, nil, nil)
}

func (sm *StateManager) HandleCallerHasProjectAccess(ctx context.Context, setup bool, params map[string]any) error {
	p := unwrapPactParams(params)
	orgID := getStringParam(p, "organizationID", defaultEnvirOrganizationID)
	projectID := getStringParam(p, "projectID", defaultEnvirProjectID)

	if !setup {
		envirAuth.set("", "", "")

		return sm.cleanupOrganization(ctx, orgID)
	}

	if err := sm.setupOrganization(ctx, orgID); err != nil {
		return err
	}

	envirAuth.set(orgID, projectID, "")

	return sm.setupProject(ctx, orgID, projectID)
}

// HandleServiceAccountBearer creates a service account holding a token issued the way service
// account creation issues one, and hands that token to the verifier's request filter.
func (sm *StateManager) HandleServiceAccountBearer(ctx context.Context, setup bool, params map[string]any, authenticator *oauth2.Authenticator, issuer common.IssuerValue) error {
	p := readAutomationParams(params)

	if !setup {
		envirAuth.set("", "", "")

		return sm.cleanupOrganization(ctx, p.organizationID)
	}

	if err := sm.setupOrganization(ctx, p.organizationID); err != nil {
		return err
	}

	lifetime := serviceAccountTokenLifetime

	tokens, err := authenticator.Issue(ctx, &oauth2.IssueInfo{
		Issuer:         issuer.URL,
		Audience:       issuer.Hostname,
		Subject:        p.serviceAccountID,
		Type:           oauth2.TokenTypeServiceAccount,
		ServiceAccount: &oauth2.ServiceAccountClaims{OrganizationID: p.organizationID},
		Duration:       &lifetime,
	})
	if err != nil {
		return fmt.Errorf("failed to issue service account token: %w", err)
	}

	if err := sm.createServiceAccount(ctx, p, tokens.AccessToken, tokens.Expiry); err != nil {
		return err
	}

	envirAuth.set("", "", tokens.AccessToken)

	return nil
}

func (sm *StateManager) HandleOrganizationWithoutProject(ctx context.Context, setup bool, params map[string]any) error {
	orgID := getStringParam(unwrapPactParams(params), "organizationID", defaultEnvirOrganizationID)

	if !setup {
		return sm.cleanupOrganization(ctx, orgID)
	}

	return sm.setupOrganization(ctx, orgID)
}

// HandleAutomationIdentity seeds the organization and the role Envir's automation group holds,
// then the group and service account as far as the named state goes.
func (sm *StateManager) HandleAutomationIdentity(ctx context.Context, state string, setup bool, params map[string]any) error {
	p := readAutomationParams(params)

	if !setup {
		if err := sm.deleteRole(ctx, p.roleID); err != nil {
			return err
		}

		return sm.cleanupOrganization(ctx, p.organizationID)
	}

	if err := sm.setupOrganization(ctx, p.organizationID); err != nil {
		return err
	}

	if err := sm.createRole(ctx, p.roleID); err != nil {
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
	}

	return nil
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

// createRole seeds an unprotected role with no scopes, so any caller may grant it.
func (sm *StateManager) createRole(ctx context.Context, roleID string) error {
	role := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: sm.namespace,
			Name:      roleID,
			Labels:    map[string]string{constants.NameLabel: "envir-automation"},
		},
	}

	if err := sm.client.Create(ctx, role); err != nil && !kerrors.IsAlreadyExists(err) {
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

// envirClientCertificate returns a self-signed certificate for Envir's service client, URL-escaped
// as the ingress forwards it in Ssl-Client-Cert. uni-identity binds the issued token to it.
//
//nolint:gochecknoglobals
var envirClientCertificate = sync.OnceValue(func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "envir-resource-manager"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	return url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
})
