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
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/util"

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
}

// Exchange validates a caller's credentials, resolves identity, and returns a
// signed passport JWT. Two authentication modes are accepted:
//
//   - Bearer: an end-user access token in the Authorization header.
//   - mTLS + impersonation: a service client cert plus an X-Impersonate: true
//     header and an X-Principal header carrying the impersonated user. This
//     mints a passport on the user's behalf; the requested org/project scope
//     is authorised against the user ∩ service ACL intersection (confused-
//     deputy prevention), but the ACL itself is not embedded in the passport.
//
// A service calling over mTLS WITHOUT the impersonation header is refused:
// autonomous service-to-service traffic does not receive a passport.
func (a *Authenticator) Exchange(ctx context.Context, r *http.Request) (*openapi.ExchangeResult, error) {
	log := log.FromContext(ctx)

	options, err := parseExchangeRequest(r)
	if err != nil {
		log.Info("passport exchange failed: malformed request body")

		return nil, err
	}

	if !hasHTTPAuthorization(r) {
		return a.exchangeImpersonated(ctx, r, options)
	}

	return a.exchangeBearer(ctx, r, options)
}

// hasHTTPAuthorization reports whether the request carries a bearer token.
func hasHTTPAuthorization(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}

// exchangeBearer is the end-user path: the caller presents an access token
// which is introspected to produce the passport.
func (a *Authenticator) exchangeBearer(ctx context.Context, r *http.Request, options *openapi.ExchangeRequestOptions) (*openapi.ExchangeResult, error) {
	log := log.FromContext(ctx)

	token, err := extractBearerToken(r)
	if err != nil {
		log.Info("passport exchange failed: missing or invalid authorization header")

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

	var email string
	if userinfo.Email != nil {
		email = *userinfo.Email
	}

	return a.mintPassport(ctx, passportIdentity{
		subject: userinfo.Sub,
		actor:   userinfo.Sub,
		acctype: authz.Acctype,
		email:   email,
		orgIDs:  authz.OrgIds,
	}, organizationID, projectID)
}

// resolveImpersonation validates the mTLS client certificate and impersonation
// headers, extracting the service identity and the impersonated principal. All
// negative paths fail closed with the appropriate OAuth2 error.
func resolveImpersonation(ctx context.Context, r *http.Request) (context.Context, string, *principal.Principal, error) {
	log := log.FromContext(ctx)

	certRaw, err := util.GetClientCertificateHeader(r.Header)
	if err != nil {
		log.Info("passport exchange failed: no bearer token and no client certificate")

		return nil, "", nil, errors.OAuth2AccessDenied("authorization required").WithError(err)
	}

	cert, err := util.GetClientCertificate(certRaw)
	if err != nil {
		log.Info("passport exchange failed: invalid client certificate")

		return nil, "", nil, errors.OAuth2AccessDenied("invalid client certificate").WithError(err)
	}

	serviceIdentity := cert.Subject.CommonName

	if r.Header.Get(principal.ImpersonateHeader) != "true" {
		log.Info("passport exchange denied: mTLS caller without impersonation flag",
			"serviceIdentity", serviceIdentity,
		)

		return nil, serviceIdentity, nil, errors.OAuth2InvalidRequest("impersonation flag required for mTLS exchange")
	}

	impersonatedCtx, err := principal.ExtractFromRequest(ctx, r)
	if err != nil {
		log.Info("passport exchange denied: invalid principal header",
			"serviceIdentity", serviceIdentity,
			"error", err.Error(),
		)

		return nil, serviceIdentity, nil, errors.OAuth2AccessDenied("invalid principal header").WithError(err)
	}

	// Belt and braces: principal.ExtractFromRequest only propagates the
	// impersonation flag when the header is present and literally "true".
	if !principal.ImpersonateFromContext(impersonatedCtx) {
		log.Info("passport exchange denied: impersonation context not established",
			"serviceIdentity", serviceIdentity,
		)

		return nil, serviceIdentity, nil, errors.OAuth2AccessDenied("impersonation context not established")
	}

	p, err := principal.FromContext(impersonatedCtx)
	if err != nil || p == nil || p.Actor == "" {
		log.Info("passport exchange denied: impersonation principal missing actor",
			"serviceIdentity", serviceIdentity,
		)

		return nil, serviceIdentity, nil, errors.OAuth2AccessDenied("principal actor required")
	}

	return impersonatedCtx, serviceIdentity, p, nil
}

// exchangeImpersonated is the service-to-user path: a system service presents
// its mTLS client certificate plus the impersonated principal via headers.
// Any ambiguity in the principal fails closed — the passport is only minted
// when the impersonation signal is explicit and the actor unambiguous.
func (a *Authenticator) exchangeImpersonated(ctx context.Context, r *http.Request, options *openapi.ExchangeRequestOptions) (*openapi.ExchangeResult, error) {
	log := log.FromContext(ctx)

	impersonatedCtx, serviceIdentity, p, err := resolveImpersonation(ctx, r)
	if err != nil {
		return nil, err
	}

	// Present the CALLING SERVICE as the authenticated subject so rbac.GetACL
	// takes the system-account + impersonation branch and returns the
	// intersection of the user's and service's ACLs. The intersection is used
	// only to authorise the requested project scope below — it is not embedded
	// in the passport.
	authCtx := authorization.NewContext(impersonatedCtx, &authorization.Info{
		SystemAccount: true,
		Userinfo: &openapi.Userinfo{
			Sub: serviceIdentity,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.System,
			},
		},
	})

	organizationID, projectID := requestedScope(options)

	if err := validateImpersonatedOrganizationScope(p, organizationID); err != nil {
		log.Info("passport exchange denied: organization not in principal scope",
			"serviceIdentity", serviceIdentity,
			"actor", p.Actor,
			"organizationID", organizationID,
		)

		return nil, err
	}

	acl, err := a.rbac.GetACL(authCtx, organizationID)
	if err != nil {
		log.Error(err, "passport exchange failed: intersected ACL computation failed",
			"serviceIdentity", serviceIdentity,
			"actor", p.Actor,
			"organizationID", organizationID,
		)

		return nil, fmt.Errorf("%w: failed to compute ACL", err)
	}

	if err := a.validateProjectScope(ctx, acl, organizationID, projectID); err != nil {
		return nil, err
	}

	return a.mintPassport(ctx, passportIdentity{
		subject:         p.Actor,
		actor:           p.Actor,
		acctype:         openapi.User,
		orgIDs:          p.OrganizationIDs,
		impersonated:    true,
		serviceIdentity: serviceIdentity,
	}, organizationID, projectID)
}

// passportIdentity bundles the subject details used to mint a passport, letting
// the bearer and mTLS flows share a single signing helper.
type passportIdentity struct {
	subject         string
	actor           string
	acctype         openapi.AuthClaimsAcctype
	email           string
	orgIDs          []string
	impersonated    bool
	serviceIdentity string
}

// mintPassport builds the passport claims from the provided identity and the
// authorised scope, signs the JWT, logs the issuance, and returns the result.
func (a *Authenticator) mintPassport(ctx context.Context, id passportIdentity, organizationID, projectID string) (*openapi.ExchangeResult, error) {
	log := log.FromContext(ctx)

	now := time.Now()
	passportID := uuid.New().String()

	claims := &PassportClaims{
		Claims: jwt.Claims{
			ID:        passportID,
			Issuer:    PassportIssuer,
			Subject:   id.subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(PassportTTL)),
		},
		Type:      PassportType,
		Acctype:   id.acctype,
		Source:    PassportSourceUNI,
		Email:     id.email,
		OrgIDs:    id.orgIDs,
		OrgID:     organizationID,
		ProjectID: projectID,
		Actor:     id.actor,
	}

	passport, err := a.jwtIssuer.EncodeJWT(ctx, claims)
	if err != nil {
		log.Error(err, "passport exchange failed: signing failed",
			"passportID", passportID,
		)

		return nil, fmt.Errorf("failed to mint passport: %w", err)
	}

	logKVs := []any{
		"acctype", id.acctype,
		"source", PassportSourceUNI,
		"organizationID", organizationID,
		"passportID", passportID,
	}

	if id.impersonated {
		logKVs = append(logKVs,
			"impersonated", true,
			"serviceIdentity", id.serviceIdentity,
			"actor", id.actor,
		)
	}

	log.Info("passport exchanged", logKVs...)

	return &openapi.ExchangeResult{
		Passport:  passport,
		ExpiresIn: int(PassportTTL.Seconds()),
	}, nil
}

// validateImpersonatedOrganizationScope rejects exchanges scoped to an
// organization the impersonated principal does not belong to. Impersonation
// can only narrow — it must not widen — access.
func validateImpersonatedOrganizationScope(p *principal.Principal, organizationID string) error {
	if organizationID == "" {
		return nil
	}

	if !slices.Contains(p.OrganizationIDs, organizationID) {
		return errors.OAuth2AccessDenied("organization not in scope")
	}

	return nil
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
