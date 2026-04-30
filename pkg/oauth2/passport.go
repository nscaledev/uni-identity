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
	"mime"
	"net/http"
	"net/url"
	"slices"
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

// ActorClaim is the RFC 8693 section 4.1 "act" claim. It identifies the
// acting party in a delegation chain and is omitted when no delegation has
// occurred. Non-identity claims (exp, nbf, aud) are not meaningful here per
// the RFC and are deliberately not included.
type ActorClaim struct {
	// Subject identifies the acting party.
	Subject string `json:"sub"`
	// Act nests the previous actor when a delegation chain is in play.
	Act *ActorClaim `json:"act,omitempty"`
}

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
	// Actor expresses delegation per RFC 8693 section 4.1; omitted when the
	// passport's subject is itself the acting party.
	Actor *ActorClaim `json:"act,omitempty"`
}

// TokenExchange implements RFC 8693 OAuth 2.0 Token Exchange for UNI passports.
// It validates the source access token provided in subject_token, resolves
// identity, and returns a signed passport in the access_token field. The ACL
// is fetched only to authorise the requested org/project scope; it is not
// embedded in the passport — downstream services continue to fetch ACL via
// the existing remote authoriser path keyed off passport-verified identity.
func (a *Authenticator) TokenExchange(_ http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	ctx := r.Context()
	log := log.FromContext(ctx)

	options, audience, err := parseAndValidateTokenExchangeRequest(r)
	if err != nil {
		log.Info("passport exchange failed: invalid token-exchange request")

		return nil, err
	}

	subjectToken := *options.SubjectToken

	userinfo, _, err := a.GetUserinfo(ctx, r, subjectToken)
	if err != nil {
		log.Info("passport exchange failed: token validation failed")

		return nil, normalizeExchangeUserinfoError(err)
	}

	authz := userinfo.HttpsunikornCloudOrgauthz

	// Set up authorization context so rbac.GetACL can read it.
	authCtx := authorization.NewContext(ctx, &authorization.Info{
		Token:    subjectToken,
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
			Audience:  audience,
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

	result := &openapi.Token{
		TokenType:       "Bearer",
		AccessToken:     passport,
		ExpiresIn:       int(PassportTTL.Seconds()),
		IssuedTokenType: stringPtr(PassportIssuedTokenType()),
	}

	return result, nil
}

func validateOrganizationScope(authz *openapi.AuthClaims, organizationID string) error {
	if organizationID == "" {
		return nil
	}

	// GetUserinfo normally populates authz for valid UNI tokens, but keep the
	// nil guard so malformed or partially mocked callers still fail closed.
	if authz == nil {
		return errors.OAuth2InvalidTarget("organization not in scope")
	}

	// System principals do not carry explicit organization memberships in OrgIds.
	// Their effective scope is derived from RBAC's system-account path instead.
	if authz.Acctype == openapi.System {
		return nil
	}

	if !slices.Contains(authz.OrgIds, organizationID) {
		return errors.OAuth2InvalidTarget("organization not in scope")
	}

	return nil
}

func requestedScope(options *openapi.TokenRequestOptions) (string, string) {
	if options == nil {
		return "", ""
	}

	var organizationID string
	if options.XOrganizationId != nil {
		organizationID = *options.XOrganizationId
	}

	var projectID string
	if options.XProjectId != nil {
		projectID = *options.XProjectId
	}

	return organizationID, projectID
}

// requestedAudience builds the JWT aud claim from the RFC 8693 audience and
// resource parameters. Resource values must be absolute URIs without a fragment
// (RFC 8693 section 2.1, RFC 3986 section 4.3); audience values are opaque
// logical names. Duplicates between the two are removed so the aud claim is a
// stable set.
func requestedAudience(options *openapi.TokenRequestOptions) (jwt.Audience, error) {
	if options == nil {
		return nil, nil
	}

	var audience jwt.Audience

	add := func(v string) {
		if v == "" || slices.Contains(audience, v) {
			return
		}

		audience = append(audience, v)
	}

	if options.Resource != nil && *options.Resource != "" {
		u, err := url.Parse(*options.Resource)
		if err != nil || !u.IsAbs() || u.Fragment != "" {
			return nil, errors.OAuth2InvalidTarget("resource must be an absolute URI without a fragment")
		}

		add(*options.Resource)
	}

	if options.Audience != nil {
		add(*options.Audience)
	}

	return audience, nil
}

// parseAndValidateTokenExchangeRequest is the single entry point for
// processing an RFC 8693 token-exchange request: it parses the form body,
// validates the required parameters, and resolves the requested audience.
func parseAndValidateTokenExchangeRequest(r *http.Request) (*openapi.TokenRequestOptions, jwt.Audience, error) {
	options, err := parseTokenExchangeRequest(r)
	if err != nil {
		return nil, nil, err
	}

	if err := validateTokenExchangeRequest(options); err != nil {
		return nil, nil, err
	}

	audience, err := requestedAudience(options)
	if err != nil {
		return nil, nil, err
	}

	return options, audience, nil
}

func validateTokenExchangeRequest(options *openapi.TokenRequestOptions) error {
	if options == nil {
		return errors.OAuth2InvalidRequest("token exchange request not parsed")
	}

	if err := validateSubjectToken(options); err != nil {
		return err
	}

	return validateRequestedTokenType(options)
}

func validateSubjectToken(options *openapi.TokenRequestOptions) error {
	if options.SubjectToken == nil || *options.SubjectToken == "" {
		return errors.OAuth2InvalidRequest("subject_token must be specified")
	}

	if options.SubjectTokenType == nil || *options.SubjectTokenType == "" {
		return errors.OAuth2InvalidRequest("subject_token_type must be specified")
	}

	if *options.SubjectTokenType != AccessTokenSubjectTokenType() {
		return errors.OAuth2InvalidRequest("subject_token_type is not supported")
	}

	return nil
}

func validateRequestedTokenType(options *openapi.TokenRequestOptions) error {
	if options.RequestedTokenType == nil || *options.RequestedTokenType == "" {
		return nil
	}

	// RFC 8693 section 2.1: when the registered access_token URI is requested,
	// the AS picks the issued token type at its discretion. We honour that by
	// accepting it as a synonym for the server default alongside the explicit
	// passport URI.
	switch *options.RequestedTokenType {
	case PassportIssuedTokenType(), AccessTokenSubjectTokenType():
		return nil
	default:
		return errors.OAuth2InvalidRequest("requested_token_type is not supported")
	}
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

// parseTokenExchangeRequest parses the form-encoded token request into
// TokenRequestOptions and rejects request shapes we deliberately don't support.
//
// RFC 8693 §2.1 requires the request body to be
// application/x-www-form-urlencoded; we enforce that explicitly so a caller
// can't smuggle params via a query string under a JSON Content-Type. The
// actor_token path is rejected because Phase 2 has no delegation flow — once
// the spec MUSTs validation when actor_token is present, silently dropping
// it would be a conformance gap.
//
// Note: audience and resource may appear multiple times per RFC 8693 §2.1,
// but the typed model and form lookup here take only the first instance.
// Multi-value support is a future extension.
func parseTokenExchangeRequest(r *http.Request) (*openapi.TokenRequestOptions, error) {
	if err := assertFormContentType(r); err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse form data: " + err.Error())
	}

	if r.Form.Get("actor_token") != "" || r.Form.Get("actor_token_type") != "" {
		return nil, errors.OAuth2InvalidRequest("actor_token is not supported")
	}

	options := &openapi.TokenRequestOptions{
		GrantType: r.Form.Get("grant_type"),
	}

	for _, mapping := range []struct {
		name string
		dest **string
	}{
		{"subject_token", &options.SubjectToken},
		{"subject_token_type", &options.SubjectTokenType},
		{"requested_token_type", &options.RequestedTokenType},
		{"audience", &options.Audience},
		{"resource", &options.Resource},
		{"x_organization_id", &options.XOrganizationId},
		{"x_project_id", &options.XProjectId},
	} {
		if v := r.Form.Get(mapping.name); v != "" {
			value := v
			*mapping.dest = &value
		}
	}

	return options, nil
}

// assertFormContentType enforces RFC 8693 §2.1's content-type requirement.
// An empty Content-Type is tolerated to keep tests that build requests by
// hand without setting headers exercising the same path.
func assertFormContentType(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return nil
	}

	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return errors.OAuth2InvalidRequest("Content-Type must be application/x-www-form-urlencoded")
	}

	return nil
}

func stringPtr(value string) *string {
	return &value
}

func PassportIssuedTokenType() string {
	return "urn:nscale:params:oauth:token-type:passport"
}

func AccessTokenSubjectTokenType() string {
	return "urn:ietf:params:oauth:token-type:access_token"
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

	// The narrowest and safest path is an explicit project grant already present
	// in the computed ACL. In that case we can trust the scope immediately.
	if projectInACL(projectID, acl) {
		return nil
	}

	// A broader org/global grant may still legitimately embed a project-scoped
	// passport, but only if the requested project actually belongs to the scoped
	// organization. Without that membership check, callers could inject an
	// arbitrary project ID into the passport claims.
	if !hasBroaderScope(acl, organizationID) {
		return errors.OAuth2InvalidTarget("project not in scope")
	}

	ok, err := a.projectInOrganization(ctx, organizationID, projectID)
	if err != nil {
		return fmt.Errorf("failed to verify project membership: %w", err)
	}

	if !ok {
		return errors.OAuth2InvalidTarget("project not in scope")
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
