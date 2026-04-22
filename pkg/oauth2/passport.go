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

package oauth2

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// PassportTTL is the lifetime of a passport token.
	PassportTTL = 2 * time.Minute

	// PassportType distinguishes passport tokens from access tokens.
	PassportType = "passport"

	// PassportIssuer is the issuer claim value for passport tokens.
	PassportIssuer = "uni-identity"

	// PassportSourceUNI indicates the source token was a UNI access token.
	PassportSourceUNI = "uni"
)

// PassportClaims defines the JWT claims for a passport token.
type PassportClaims struct {
	jwt.Claims `json:",inline"`

	// Type distinguishes passports from access tokens.
	Type string `json:"typ"`
	// Acctype is the account type: "user", "service", or "system".
	Acctype openapi.AuthClaimsAcctype `json:"acctype"`
	// Source identifies which IdP issued the original token.
	Source string `json:"source"`
	// Email is the user's email address, if available.
	Email string `json:"email,omitempty"`
	// OrgIDs is the list of organization IDs the subject is authorized for.
	//nolint:tagliatelle
	OrgIDs []string `json:"org_ids"`
	// OrgID is the current organization context from the exchange request.
	//nolint:tagliatelle
	OrgID string `json:"org_id,omitempty"`
	// ProjectID is the current project context from the exchange request.
	//nolint:tagliatelle
	ProjectID string `json:"project_id,omitempty"`
	// Actor is the end-user identifier for principal propagation and audit.
	Actor string `json:"actor"`
	// ACL is the organization-scoped ACL structure.
	ACL *openapi.Acl `json:"acl"`
}

// Exchange validates a source access token, resolves identity and ACL,
// and returns a signed passport JWT.
func (a *Authenticator) Exchange(ctx context.Context, r *http.Request) (*openapi.ExchangeResult, error) {
	log := log.FromContext(ctx)

	token, err := extractBearerToken(r)
	if err != nil {
		log.Info("passport exchange failed: missing or invalid authorization header")

		return nil, err
	}

	options, err := parseExchangeRequest(r)
	if err != nil {
		log.Info("passport exchange failed: malformed request body")

		return nil, err
	}

	userinfo, _, err := a.GetUserinfo(ctx, r, token)
	if err != nil {
		log.Info("passport exchange failed: token validation failed")

		return nil, normalizeExchangeUserinfoError(err)
	}

	authz := userinfo.HttpsunikornCloudOrgauthz

	// Set up authorization context so rbac.GetACL can read it.
	authCtx := authorization.NewContext(ctx, &authorization.Info{
		Token:    token,
		Userinfo: userinfo,
	})

	organizationID, projectID := requestedScope(options)

	if err := validateOrganizationScope(authz, organizationID); err != nil {
		log.Info("passport exchange denied: organization not in scope",
			"acctype", authz.Acctype,
			"organizationID", organizationID,
		)

		return nil, err
	}

	acl, err := a.rbac.GetACL(authCtx, organizationID)
	if err != nil {
		log.Error(err, "passport exchange failed: ACL computation failed",
			"acctype", authz.Acctype,
			"organizationID", organizationID,
		)

		return nil, fmt.Errorf("%w: failed to compute ACL", err)
	}

	if err := a.validateProjectScope(ctx, acl, organizationID, projectID); err != nil {
		return nil, err
	}

	now := time.Now()
	passportID := uuid.New().String()

	claims := &PassportClaims{
		Claims: jwt.Claims{
			ID:        passportID,
			Issuer:    PassportIssuer,
			Subject:   userinfo.Sub,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(PassportTTL)),
		},
		Type:      PassportType,
		Acctype:   authz.Acctype,
		Source:    PassportSourceUNI,
		OrgIDs:    authz.OrgIds,
		OrgID:     organizationID,
		ProjectID: projectID,
		Actor:     userinfo.Sub,
		ACL:       acl,
	}

	if userinfo.Email != nil {
		claims.Email = *userinfo.Email
	}

	passport, err := a.jwtIssuer.EncodeJWT(ctx, claims)
	if err != nil {
		log.Error(err, "passport exchange failed: signing failed",
			"passportID", passportID,
		)

		return nil, fmt.Errorf("failed to mint passport: %w", err)
	}

	log.Info("passport exchanged",
		"acctype", authz.Acctype,
		"source", PassportSourceUNI,
		"organizationID", organizationID,
		"passportID", passportID,
	)

	result := &openapi.ExchangeResult{
		Passport:  passport,
		ExpiresIn: int(PassportTTL.Seconds()),
	}

	return result, nil
}

func validateOrganizationScope(authz *openapi.AuthClaims, organizationID string) error {
	if organizationID == "" {
		return nil
	}

	if authz == nil || !slices.Contains(authz.OrgIds, organizationID) {
		return errors.OAuth2AccessDenied("organization not in scope")
	}

	return nil
}

func requestedScope(options *openapi.ExchangeRequestOptions) (string, string) {
	var organizationID string
	if options.OrganizationId != nil {
		organizationID = *options.OrganizationId
	}

	var projectID string
	if options.ProjectId != nil {
		projectID = *options.ProjectId
	}

	return organizationID, projectID
}

func normalizeExchangeUserinfoError(err error) error {
	var oauthErr *errors.Error
	if goerrors.As(err, &oauthErr) {
		return err
	}

	if coreerrors.IsAccessDenied(err) {
		return errors.OAuth2AccessDenied("token validation failed").WithError(err)
	}

	return err
}

// extractBearerToken extracts the Bearer token from the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.OAuth2AccessDenied("authorization header not set")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", errors.OAuth2InvalidRequest("authorization header malformed")
	}

	if !strings.EqualFold(parts[0], "bearer") {
		return "", errors.OAuth2InvalidRequest("authorization scheme not allowed")
	}

	return parts[1], nil
}

// parseExchangeRequest parses the form-encoded request body into ExchangeRequestOptions.
func parseExchangeRequest(r *http.Request) (*openapi.ExchangeRequestOptions, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse form data: " + err.Error())
	}

	options := &openapi.ExchangeRequestOptions{}

	if v := r.Form.Get("organizationId"); v != "" {
		options.OrganizationId = &v
	}

	if v := r.Form.Get("projectId"); v != "" {
		options.ProjectId = &v
	}

	return options, nil
}

// projectInACL returns true if projectID appears in the ACL's project list.
func projectInACL(projectID string, acl *openapi.Acl) bool {
	if acl == nil || acl.Projects == nil {
		return false
	}

	for _, p := range *acl.Projects {
		if p.Id == projectID {
			return true
		}
	}

	return false
}

// hasBroaderScope returns true if the ACL carries a global or organization-level
// grant that, per the scope-confinement rule, implicitly covers project scope.
func hasBroaderScope(acl *openapi.Acl, organizationID string) bool {
	if acl == nil {
		return false
	}

	if acl.Global != nil && len(*acl.Global) > 0 {
		return true
	}

	if organizationID == "" || acl.Organization == nil || acl.Organization.Id != organizationID {
		return false
	}

	return acl.Organization.Endpoints != nil && len(*acl.Organization.Endpoints) > 0
}

// validateProjectScope authorises the passport's requested project scope.
// A request is accepted if the project is present in the subject's ACL, or
// if a broader (global/organization) grant covers it — in which case the
// project must be verified to belong to the requested organization to prevent
// scope injection via untrusted request parameters.
func (a *Authenticator) validateProjectScope(ctx context.Context, acl *openapi.Acl, organizationID, projectID string) error {
	if projectID == "" {
		return nil
	}

	if projectInACL(projectID, acl) {
		return nil
	}

	if !hasBroaderScope(acl, organizationID) {
		return errors.OAuth2AccessDenied("project not in scope")
	}

	ok, err := a.projectInOrganization(ctx, organizationID, projectID)
	if err != nil {
		return fmt.Errorf("failed to verify project membership: %w", err)
	}

	if !ok {
		return errors.OAuth2AccessDenied("project not in scope")
	}

	return nil
}

// projectInOrganization reports whether a project with the given ID exists in
// the organization's backing namespace.
func (a *Authenticator) projectInOrganization(ctx context.Context, organizationID, projectID string) (bool, error) {
	var org unikornv1.Organization
	if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: organizationID}, &org); err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}

		return false, err
	}

	if org.Status.Namespace == "" {
		return false, nil
	}

	var project unikornv1.Project
	if err := a.client.Get(ctx, client.ObjectKey{Namespace: org.Status.Namespace, Name: projectID}, &project); err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}
