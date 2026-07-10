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
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
	"github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// PassportTTL is the lifetime of a passport token. Sized to cover the
	// worst-case operational lifetime of a request that uses it: three
	// downstream hops at 15s per-hop API timeout plus 15s grace for clock
	// skew and tail latency.
	PassportTTL = 60 * time.Second

	// PassportType distinguishes passport tokens from access tokens.
	PassportType = "passport"

	// PassportIssuer is the issuer claim value for passport tokens.
	PassportIssuer = "uni-identity"

	// PassportSourceUNI indicates the source token was a UNI access token.
	// It aliases constants.UNISentinel so all existing references continue to compile.
	PassportSourceUNI = constants.UNISentinel
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
	// SrcIss is the issuer URL (verbatim, as the IdP emits it) that authenticated
	// the subject, or the PassportSourceUNI sentinel for UNI-local tokens. It is
	// the security-load-bearing issuer for the platform-admin match; Source
	// stays a coarse audit label.
	//nolint:tagliatelle
	SrcIss string `json:"src_iss"`
	// Actor expresses delegation per RFC 8693 section 4.1; omitted when the
	// passport's subject is itself the acting party.
	Actor *ActorClaim `json:"act,omitempty"`
}

// TokenExchange implements RFC 8693 OAuth 2.0 Token Exchange for UNI passports
// when invoked via the OAuth 2.0 token endpoint. It parses the form body and
// hands off to ExchangePassport; non-handler callers should use that directly.
func (a *Authenticator) TokenExchange(_ http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	options, err := parseTokenExchangeRequest(r)
	if err != nil {
		log.FromContext(r.Context()).Info("passport exchange failed: malformed request body")

		return nil, err
	}

	return a.ExchangePassport(r.Context(), options)
}

// ExchangePassport runs the RFC 8693 token-exchange flow against pre-parsed
// request options. It validates the source access token, resolves identity,
// authorises the requested org/project scope, and returns a signed passport
// in the access_token field. The ACL is fetched only to authorise the
// requested scope; it is not embedded in the passport — downstream services
// continue to fetch ACL via the existing remote authoriser path keyed off
// passport-verified identity.
//
// This is the entry point for in-process callers that already hold typed
// TokenRequestOptions and don't need form parsing. The HTTP handler reaches
// it via TokenExchange.
func (a *Authenticator) ExchangePassport(ctx context.Context, options *openapi.TokenRequestOptions) (*openapi.Token, error) {
	log := log.FromContext(ctx)

	if err := validateTokenExchangeRequest(options); err != nil {
		log.Info("passport exchange failed: invalid token-exchange request")

		return nil, err
	}

	audience, err := requestedAudience(options)
	if err != nil {
		log.Info("passport exchange failed: invalid resource URI")

		return nil, err
	}

	// GetUserinfo's signature requires *http.Request to construct
	// WWW-Authenticate metadata on AccessDenied. The non-handler entry
	// path doesn't have a real request, so synthesise one carrying the
	// active context.
	request := (&http.Request{Header: make(http.Header)}).WithContext(ctx)

	subjectToken := *options.SubjectToken

	res, err := a.dispatchUserinfo(ctx, request, subjectToken, dispatchSurfaceExchange)
	if err != nil {
		log.Info("passport exchange failed: token validation failed")

		return nil, normalizeExchangeUserinfoError(err)
	}

	authz := res.Userinfo.HttpsunikornCloudOrgauthz

	// Set up authorization context so rbac.GetACL can read it.
	authCtx := authorization.NewContext(ctx, &authorization.Info{
		Token:    subjectToken,
		Userinfo: res.Userinfo,
		SrcIss:   res.SrcIss,
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
		if goerrors.Is(err, rbac.ErrNotInOrganization) {
			log.Info("passport exchange denied: organization not in scope",
				"acctype", authz.Acctype,
				"organizationID", organizationID,
			)

			return nil, errors.OAuth2InvalidScope("organization not in scope").WithError(err)
		}

		log.Error(err, "passport exchange failed: ACL computation failed",
			"acctype", authz.Acctype,
			"organizationID", organizationID,
		)

		return nil, fmt.Errorf("failed to compute ACL: %w", err)
	}

	if err := a.validateProjectScope(ctx, acl, organizationID, projectID); err != nil {
		return nil, err
	}

	return a.mintPassport(ctx, res.Userinfo, res.Claims, res.Source, audience, organizationID, projectID)
}

const (
	// dispatchSurfaceBearer and dispatchSurfaceExchange label the entry points
	// that share dispatchUserinfo, tagging the unroutable metric and log so a
	// firing alert can be triaged to the affected traffic. Both direct-bearer
	// call sites — the local authorizer (/api/v1/*) and the OIDC userinfo
	// endpoint (/oauth2/v2/userinfo) — report "bearer"; token exchange reports
	// "exchange".
	dispatchSurfaceBearer   = "bearer"
	dispatchSurfaceExchange = "exchange"
)

// dispatchResult is the resolved identity for a bearer token.
type dispatchResult struct {
	Userinfo *openapi.Userinfo
	Claims   *Claims
	Source   string // passport audit label (provider name or PassportSourceUNI)
	SrcIss   string // issuer URL (verbatim), or the UNI sentinel
}

// dispatchUserinfo resolves a bearer token to userinfo and claims, routing on
// the JOSE header: UNI access tokens are JWEs (an "enc" header) and resolve
// through the local userinfo path; a JWS is an external access token from a
// trusted OAuth2Provider and is dispatched to the matching per-provider
// validator. The result also reports which path produced it via Source and
// SrcIss.
//
// Routing on the header rather than counting dots means an upstream switch to a
// non-JWS access token can no longer silently misroute every external token to
// the UNI path: a bearer that is neither a JWE nor a JWS is rejected outright
// and counted, so a token-format change surfaces as an alertable signal instead
// of a scatter of generic 401s.
//
// surface names the entry point (bearer or exchange) for the unroutable metric
// and log. It is the single dispatch point shared by the token-exchange
// endpoint and the local-authorizer bearer path, so the two cannot drift.
func (a *Authenticator) dispatchUserinfo(ctx context.Context, r *http.Request, token, surface string) (*dispatchResult, error) {
	if token == "" {
		return nil, coreerrors.AccessDenied(r, "empty bearer token")
	}

	isJWE, err := bearerTokenIsJWE(token)
	if err != nil {
		a.unroutableTokens.Add(ctx, 1, metric.WithAttributes(attribute.String("surface", surface)))

		log.FromContext(ctx).Info("rejecting unroutable bearer token", "surface", surface, "error", err)

		return nil, coreerrors.AccessDenied(r, "unrecognized bearer token format").WithError(err)
	}

	if !isJWE {
		rawIss, err := peekIssuer(token)
		if err != nil {
			a.unroutableTokens.Add(ctx, 1, metric.WithAttributes(attribute.String("surface", surface), attribute.String("reason", "unparseable_iss")))

			return nil, coreerrors.AccessDenied(r, "unparseable token issuer").WithError(err)
		}

		res, err := a.validatorForIssuer(ctx, rawIss)
		if goerrors.Is(err, ErrUnknownIssuer) {
			a.unroutableTokens.Add(ctx, 1, metric.WithAttributes(attribute.String("surface", surface), attribute.String("reason", "unknown_issuer")))

			return nil, coreerrors.AccessDenied(r, "untrusted token issuer")
		}

		if err != nil {
			return nil, a.handleValidatorError(ctx, r, err, surface)
		}

		ui, claims, err := a.externalUserinfo(ctx, r, token, rawIss, res.Trust, res.Validator)
		if err != nil {
			return nil, err
		}

		return &dispatchResult{Userinfo: ui, Claims: claims, Source: res.ProviderName, SrcIss: rawIss}, nil
	}

	ui, claims, err := a.GetUserinfo(ctx, r, token)
	if err != nil {
		return nil, err
	}

	return &dispatchResult{Userinfo: ui, Claims: claims, Source: PassportSourceUNI, SrcIss: PassportSourceUNI}, nil
}

// handleValidatorError returns the appropriate error response for validatorForIssuer failures.
// If the provider cache is not yet synced, it returns 503 Service Unavailable (transient).
// Otherwise, it returns 401 Unauthorized (issuer not trusted).
func (a *Authenticator) handleValidatorError(ctx context.Context, r *http.Request, err error, surface string) error {
	if goerrors.Is(err, ErrCacheNotReady) {
		log.FromContext(ctx).Info("provider cache not ready", "surface", surface)
		return errors.OAuth2ServiceUnavailable("identity service warming up").WithError(err)
	}

	return coreerrors.AccessDenied(r, "issuer trust unavailable").WithError(err)
}

// GetUserinfoFromBearer resolves an external or UNI bearer token presented
// directly — to the local authorizer (/api/v1/...) or to the OIDC userinfo
// endpoint (/oauth2/v2/userinfo) — without the token-exchange round-trip. It
// shares dispatchUserinfo with the exchange path and returns the
// src_iss alongside userinfo and claims.
func (a *Authenticator) GetUserinfoFromBearer(ctx context.Context, r *http.Request, token string) (*openapi.Userinfo, *Claims, string, error) {
	res, err := a.dispatchUserinfo(ctx, r, token, dispatchSurfaceBearer)
	if err != nil {
		return nil, nil, "", err
	}

	return res.Userinfo, res.Claims, res.SrcIss, nil
}

// errUnrecognizedToken is returned by bearerTokenIsJWE when a bearer token is
// neither a JWS nor a JWE — its JOSE header is absent, unparseable, or
// inconsistent with the compact-serialization segment count.
var errUnrecognizedToken = goerrors.New("bearer token is neither a JWS nor a JWE")

var (
	// errTokenTooFewSegments is returned by peekIssuer when the compact
	// token has fewer than two dot-separated segments.
	errTokenTooFewSegments = goerrors.New("token has fewer than 2 segments")

	// errPayloadTooLarge is returned by peekIssuer when the decoded
	// JWT payload exceeds the size bound.
	errPayloadTooLarge = goerrors.New("JWT payload exceeds size limit")

	// errMissingIssClaim is returned by peekIssuer when the JWT payload
	// does not contain a non-empty "iss" claim.
	errMissingIssClaim = goerrors.New("token has no iss claim")
)

// bearerTokenIsJWE reports whether token is a JWE (a UNI access token) rather
// than a JWS (an Auth0 access token) by inspecting the protected JOSE header: a
// JWE carries an "enc" content-encryption header, a JWS does not, and both carry
// "alg". JOSE header names are case-sensitive (RFC 7515 §4), and the header type
// is cross-checked against the segment count (JWS has 3 segments, JWE has 5) so
// a stray header member cannot misroute a token. It returns errUnrecognizedToken
// when the token is neither, which the dispatcher treats as unroutable.
func bearerTokenIsJWE(token string) (bool, error) {
	header, _, ok := strings.Cut(token, ".")
	if !ok {
		return false, fmt.Errorf("%w: not a compact JOSE serialization", errUnrecognizedToken)
	}

	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return false, fmt.Errorf("%w: undecodable header: %w", errUnrecognizedToken, err)
	}

	// encoding/json matches keys case-insensitively, but JOSE header names are
	// case-sensitive, so decode to raw members and test exact keys.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false, fmt.Errorf("%w: unparseable header: %w", errUnrecognizedToken, err)
	}

	if _, ok := parsed["alg"]; !ok {
		return false, fmt.Errorf("%w: header has no alg", errUnrecognizedToken)
	}

	_, isJWE := parsed["enc"]

	segments := strings.Count(token, ".") + 1

	switch {
	case isJWE && segments != 5:
		return false, fmt.Errorf("%w: JWE header with %d segments", errUnrecognizedToken, segments)
	case !isJWE && segments != 3:
		return false, fmt.Errorf("%w: JWS header with %d segments", errUnrecognizedToken, segments)
	}

	return isJWE, nil
}

// peekIssuer extracts the "iss" claim verbatim from the payload of a
// compact-serialized JWT (JWS) without signature verification. It reads segment
// index 1 (0-based) — the payload — which is distinct from bearerTokenIsJWE,
// which reads segment index 0 (the JOSE header). The decoded payload is bounded
// at 8 KiB to limit allocations. Returns an error when the token is not
// splittable, the payload is not base64url-decodable, or the JSON does not
// contain a non-empty "iss" string. The issuer is used as-is for provider
// dispatch (exact string match against spec.issuer) — no normalization.
func peekIssuer(token string) (string, error) {
	const maxPayloadBytes = 8 * 1024

	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return "", errTokenTooFewSegments
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload base64 decode: %w", err)
	}

	if len(raw) > maxPayloadBytes {
		return "", errPayloadTooLarge
	}

	var payload struct {
		Iss string `json:"iss"`
	}

	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("payload JSON: %w", err)
	}

	if payload.Iss == "" {
		return "", errMissingIssClaim
	}

	return payload.Iss, nil
}

// externalUserinfo validates an external bearer token using the supplied
// validator, resolves UNI organization membership, and builds the userinfo and
// source-claims pair. It is the single implementation for all bearer-trust
// paths; dispatchUserinfo wires it for every JWS path via validatorForIssuer.
//
// When the email is not found in the UNI user database (ErrResourceReference)
// and trust.AllowExternalIdentity is true, the subject is accepted with an
// empty orgIds slice — RBAC decides what it can reach. If AllowExternalIdentity
// is false, the request is rejected with the same error message as the prior
// unconditional rejection, preserving the existing wire contract.
//
// sourceClaims.Issuer is stamped with rawIss (the verbatim issuer the IdP
// emitted, as resolved by validatorForIssuer) so that srcIssForSource can compute
// the correct src_iss for the resulting passport regardless of which provider
// produced the claims.
func (a *Authenticator) externalUserinfo(ctx context.Context, r *http.Request, token, rawIss string, trust *unikornv1.BearerTrustSpec, v *auth0.Validator) (*openapi.Userinfo, *Claims, error) {
	user, err := v.Validate(ctx, token)
	if err != nil {
		return nil, nil, coreerrors.AccessDenied(r, "token validation failed").WithError(err)
	}

	// UNI remains authoritative for active user state and organization
	// membership. Claimed orgIds from the external token are discarded.
	orgIDs, err := a.userdb.GetOrganizationIDs(ctx, user.Email)
	if err != nil {
		if goerrors.Is(err, userdb.ErrResourceReference) {
			if !trust.AllowExternalIdentity {
				return nil, nil, errors.OAuth2AccessDenied("user identity not found or inactive").WithError(err)
			}

			orgIDs = nil // accepted with no memberships; authority decided by RBAC
		} else {
			return nil, nil, fmt.Errorf("%w: failed to query organization IDs", err)
		}
	}

	// orgIds is a non-nullable array in the userinfo OpenAPI schema; a nil slice
	// serializes to JSON null and fails response validation (panic → 502). An
	// external identity with no UNI memberships must surface as an empty list.
	if orgIDs == nil {
		orgIDs = []string{}
	}

	verified := true
	email := user.Email

	userinfo := &openapi.Userinfo{
		Sub:           user.Email,
		Email:         &email,
		EmailVerified: &verified,
		HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
			Acctype: openapi.User,
			OrgIds:  orgIDs,
		},
	}

	sourceClaims := &Claims{
		Claims: jwt.Claims{
			Subject:  user.Email,
			Issuer:   rawIss,
			Audience: jwt.Audience{trust.Audience},
			Expiry:   jwt.NewNumericDate(user.Expiry),
		},
	}

	return userinfo, sourceClaims, nil
}

// srcIssForSource resolves the src_iss stamped on a passport. The UNI-local path
// uses a fixed sentinel (a UNI access token's iss is not guaranteed to be an HTTPS
// URL); external paths use the verbatim issuer already resolved by the dispatcher.
func srcIssForSource(rawIssuer, source string) string {
	if source == PassportSourceUNI {
		return PassportSourceUNI
	}

	return rawIssuer
}

// mintPassport encodes the signed passport once scope authorisation has
// completed. It also enforces the source-token expiry precondition: a passport
// with expires_in ≤ 0 would be internally inconsistent, so the exchange fails
// closed when the source token's exp is already at or before now.
func (a *Authenticator) mintPassport(ctx context.Context, userinfo *openapi.Userinfo, sourceClaims *Claims, source string, audience jwt.Audience, organizationID, projectID string) (*openapi.Token, error) {
	log := log.FromContext(ctx)

	now := time.Now()

	expiry, err := passportExpiry(now, sourceClaims)
	if err != nil {
		log.Info("passport exchange failed: source token already expired")

		return nil, errors.OAuth2AccessDenied("token validation failed").WithError(err)
	}

	passportID := uuid.New().String()
	authz := userinfo.HttpsunikornCloudOrgauthz

	claims := &PassportClaims{
		Claims: jwt.Claims{
			ID:        passportID,
			Issuer:    PassportIssuer,
			Subject:   userinfo.Sub,
			Audience:  audience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(expiry),
		},
		Type:      PassportType,
		Acctype:   authz.Acctype,
		Source:    source,
		SrcIss:    srcIssForSource(sourceClaims.Issuer, source),
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
		"source", source,
		"organizationID", organizationID,
		"passportID", passportID,
	)

	return &openapi.Token{
		TokenType:       "Bearer",
		AccessToken:     passport,
		ExpiresIn:       int(expiry.Sub(now).Seconds()),
		IssuedTokenType: stringPtr(PassportIssuedTokenType()),
	}, nil
}

// passportExpiry returns the passport's exp claim, capped at the source token
// expiry per the PRD rule that a passport must not outlive the credential it
// was minted from. It fails closed when the source token's exp is already at
// or before now: GetUserinfo may accept such a token via verification leeway,
// but a passport with expires_in <= 0 is internally inconsistent and would be
// rejected by downstream middleware regardless.
func passportExpiry(now time.Time, sourceClaims *Claims) (time.Time, error) {
	expiry := now.Add(PassportTTL)

	if sourceClaims == nil || sourceClaims.Expiry == nil {
		return expiry, nil
	}

	sourceExpiry := sourceClaims.Expiry.Time()
	if !sourceExpiry.After(now) {
		return time.Time{}, ErrSourceTokenExpired
	}

	if sourceExpiry.Before(expiry) {
		return sourceExpiry, nil
	}

	return expiry, nil
}

// validateOrganizationScope rejects an exchange request whose scoped
// organization is not reachable by the calling principal. Every rejection
// path returns OAuth2InvalidScope (HTTP 400, RFC 6749 §5.2); the remote
// middleware projects that to 403 forbidden at the API edge.
func validateOrganizationScope(authz *openapi.AuthClaims, organizationID string) error {
	if organizationID == "" {
		return nil
	}

	// GetUserinfo normally populates authz for valid UNI tokens, but keep the
	// nil guard so malformed or partially mocked callers fail closed with
	// invalid_scope rather than panicking.
	if authz == nil {
		return errors.OAuth2InvalidScope("organization not in scope")
	}

	// System and user principals defer to RBAC and are not rejected here:
	//   - System principals do not carry explicit organization memberships
	//     in OrgIds; their effective scope is derived from RBAC's
	//     system-account path.
	//   - User principals defer to RBAC because platform-administrator
	//     subjects are authorised even when they are not members of the
	//     scoped organization. Ordinary users outside the organization are
	//     rejected downstream by rbac.GetACL (ErrNotInOrganization), which
	//     the ExchangePassport caller re-wraps as OAuth2InvalidScope — so
	//     the resulting wire response is identical to the early reject
	//     below.
	if authz.Acctype == openapi.System || authz.Acctype == openapi.User {
		return nil
	}

	// Service accounts and other non-system/user principals carry an explicit
	// organization membership list, so we can reject early on a mismatch
	// without consulting RBAC. Same wire response (invalid_scope) as the
	// deferred RBAC path above.
	if !slices.Contains(authz.OrgIds, organizationID) {
		return errors.OAuth2InvalidScope("organization not in scope")
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
			return nil, errors.OAuth2InvalidRequest("resource must be an absolute URI without a fragment")
		}

		add(*options.Resource)
	}

	if options.Audience != nil {
		add(*options.Audience)
	}

	return audience, nil
}

func validateTokenExchangeRequest(options *openapi.TokenRequestOptions) error {
	if options == nil {
		return errors.OAuth2InvalidRequest("token exchange request not parsed")
	}

	if err := validateSubjectToken(options); err != nil {
		return err
	}

	if err := validateRequestedScope(options); err != nil {
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

func validateRequestedScope(options *openapi.TokenRequestOptions) error {
	if options.XProjectId == nil || *options.XProjectId == "" {
		return nil
	}

	if options.XOrganizationId == nil || *options.XOrganizationId == "" {
		return errors.OAuth2InvalidRequest("x_organization_id must be specified when x_project_id is specified")
	}

	return nil
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
// actor_token path is rejected because delegation is not supported here; silently
// dropping it would be a conformance gap.
//
// Note: audience and resource may appear multiple times per RFC 8693 §2.1,
// but the typed model and form lookup here take only the first instance.
// Multi-value support is a future extension.
func parseTokenExchangeRequest(r *http.Request) (*openapi.TokenRequestOptions, error) {
	if err := assertFormContentType(r); err != nil {
		return nil, err
	}

	if err := rejectTokenExchangeQueryParameters(r); err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse form data: " + err.Error())
	}

	form := r.PostForm

	if form.Get("actor_token") != "" || form.Get("actor_token_type") != "" {
		return nil, errors.OAuth2InvalidRequest("actor_token is not supported")
	}

	options := &openapi.TokenRequestOptions{
		GrantType: form.Get("grant_type"),
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
		if v := form.Get(mapping.name); v != "" {
			value := v
			*mapping.dest = &value
		}
	}

	return options, nil
}

func rejectTokenExchangeQueryParameters(r *http.Request) error {
	query := r.URL.Query()

	for _, name := range []string{
		"grant_type",
		"subject_token",
		"subject_token_type",
		"requested_token_type",
		"audience",
		"resource",
		"x_organization_id",
		"x_project_id",
		"actor_token",
		"actor_token_type",
	} {
		if query.Has(name) {
			return errors.OAuth2InvalidRequest(name + " must be supplied in the form body")
		}
	}

	return nil
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

	if organizationID == "" {
		return errors.OAuth2InvalidRequest("x_organization_id must be specified when x_project_id is specified")
	}

	// A project-scoped passport is accepted only when ACL proves the caller can
	// use the project or a broader grant covers it, and the project belongs to
	// the requested organization. Without the membership check, callers could
	// inject an arbitrary project ID into the passport claims.
	if !projectInACL(projectID, acl) && !hasBroaderScope(acl, organizationID) {
		return errors.OAuth2InvalidScope("project not in scope")
	}

	ok, err := a.projectInOrganization(ctx, organizationID, projectID)
	if err != nil {
		return fmt.Errorf("failed to verify project membership: %w", err)
	}

	if !ok {
		return errors.OAuth2InvalidScope("project not in scope")
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
