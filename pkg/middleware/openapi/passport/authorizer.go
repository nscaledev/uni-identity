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

package passport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	apierrors "github.com/unikorn-cloud/core/pkg/server/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	openapiinterfaces "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	remoteauthorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	identityoauth2 "github.com/unikorn-cloud/identity/pkg/oauth2"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// jwksDefaultTTL is the default TTL for the JWKS cache.
	jwksDefaultTTL = 5 * time.Minute
	// jwksHTTPTimeout is the timeout for JWKS fetch requests.
	jwksHTTPTimeout = 5 * time.Second
	// passportClaimsCacheSize is the default entry limit for cached passport claims.
	passportClaimsCacheSize = 4096
	// passportClaimsCacheDefaultTTL is used when claims do not include expiry.
	passportClaimsCacheDefaultTTL = 5 * time.Minute
)

//nolint:gochecknoglobals
var (
	passportVerificationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_passport_verification_total",
			Help: "Total number of passport token verification attempts.",
		},
		[]string{"result"},
	)

	passportAuthorizerTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_passport_authorizer_total",
			Help: "Total authorization requests handled by the passport authorizer, by method.",
		},
		[]string{"method"},
	)
)

// Authorizer implements openapi.Authorizer. It verifies passport JWTs locally
// and falls back to the remote authorizer for all other tokens.
type Authorizer struct {
	verifier    *Verifier
	remote      openapiinterfaces.Authorizer
	claimsCache *cache.LRUExpireCache
}

var _ openapiinterfaces.Authorizer = &Authorizer{}

// NewAuthorizer builds a passport Authorizer from Kubernetes client and options.
// It constructs the identity HTTP client, JWKS cache, verifier, and remote authorizer
// using the same pattern as the remote authorizer.
func NewAuthorizer(kubeClient client.Client, identityOptions *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*Authorizer, error) {
	remote, err := remoteauthorizer.NewAuthorizer(kubeClient, identityOptions, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("passport: failed to create remote authorizer: %w", err)
	}

	baseClient, err := identityclient.New(kubeClient, identityOptions, clientOptions).HTTPClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("passport: failed to create identity HTTP client: %w", err)
	}

	baseClient.Timeout = jwksHTTPTimeout

	var (
		jwksURI   = strings.TrimRight(identityOptions.Host(), "/") + "/oauth2/v2/jwks"
		jwksCache = NewJWKSCache(baseClient, jwksURI, jwksDefaultTTL)
		verifier  = NewVerifier(jwksCache)
	)

	return &Authorizer{
		verifier:    verifier,
		remote:      remote,
		claimsCache: cache.NewLRUExpireCache(passportClaimsCacheSize),
	}, nil
}

// claimsTTL derives the cache TTL from verified token claims.
func claimsTTL(claims *identityoauth2.PassportClaims) time.Duration {
	if claims == nil || claims.Expiry == nil {
		return passportClaimsCacheDefaultTTL
	}

	return time.Until(claims.Expiry.Time())
}

func (a *Authorizer) cacheClaims(rawToken string, claims *identityoauth2.PassportClaims) {
	ttl := claimsTTL(claims)
	if ttl <= 0 {
		return
	}

	a.claimsCache.Add(rawToken, claims, ttl)
}

func (a *Authorizer) claimsFromCache(rawToken string) (*identityoauth2.PassportClaims, bool, error) {
	value, ok := a.claimsCache.Get(rawToken)
	if !ok {
		return nil, false, nil
	}

	claims, ok := value.(*identityoauth2.PassportClaims)
	if !ok {
		return nil, false, ErrClaimsCacheEntryType
	}

	return claims, true, nil
}

// getBearerToken extracts the bearer token from the Authorization header.
func getBearerToken(input *openapi3filter.AuthenticationInput) (string, error) {
	r := input.RequestValidationInput.Request

	header := r.Header.Get("Authorization")
	if header == "" {
		return "", apierrors.AccessDenied(r, "authorization header missing")
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", apierrors.AccessDenied(r, "authorization header malformed")
	}

	if !strings.EqualFold(parts[0], "bearer") {
		return "", apierrors.AccessDenied(r, "authorization scheme not allowed").WithValues("scheme", parts[0])
	}

	return parts[1], nil
}

// Authorize implements openapi.Authorizer.
// Passport tokens are verified locally; all others are delegated to the remote authorizer.
func (a *Authorizer) Authorize(input *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	r := input.RequestValidationInput.Request

	rawToken, err := getBearerToken(input)
	if err != nil {
		return nil, err
	}

	claims, err := a.verifier.Verify(r.Context(), rawToken)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotPassport):
			passportAuthorizerTotal.WithLabelValues("remote").Inc()
			return a.remote.Authorize(input)

		case errors.Is(err, ErrPassportExpired):
			passportVerificationTotal.WithLabelValues("expired").Inc()
			return nil, apierrors.AccessDenied(r, "passport token has expired").WithValues("auth_method", "passport")

		case errors.Is(err, ErrPassportInvalidSig):
			passportVerificationTotal.WithLabelValues("invalid_signature").Inc()
			return nil, apierrors.AccessDenied(r, "passport token has an invalid signature").WithValues("auth_method", "passport")

		case errors.Is(err, ErrJWKSUnavailable):
			passportVerificationTotal.WithLabelValues("jwks_unavailable").Inc()
			// Token is confirmed as a passport; the remote authorizer cannot validate it either.
			// Return a server error rather than 401 to avoid misleading the client.
			// TODO: use errors.HTTPServiceUnavailable once the core package exposes it.
			return nil, fmt.Errorf("identity: JWKS unavailable: %w", err)

		default:
			return nil, fmt.Errorf("identity: passport verification failed: %w", err)
		}
	}

	passportVerificationTotal.WithLabelValues("success").Inc()
	passportAuthorizerTotal.WithLabelValues("passport").Inc()

	a.cacheClaims(rawToken, claims)

	var email *string
	if e := claims.Email; e != "" {
		email = &e
	}

	info := &authorization.Info{
		Token: rawToken,
		Userinfo: &identityapi.Userinfo{
			Sub:   claims.Subject,
			Email: email,
			HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{
				Acctype: claims.Acctype,
				OrgIds:  claims.OrgIDs,
			},
		},
	}

	return info, nil
}

// GetACL implements openapi.Authorizer.
// For passport tokens the ACL is embedded in the token payload — no network call needed.
// For all other tokens the remote authorizer is used.
func (a *Authorizer) GetACL(ctx context.Context, organizationID string) (*identityapi.Acl, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	cachedClaims, ok, err := a.claimsFromCache(info.Token)
	if err != nil {
		return nil, err
	}

	if ok {
		return cachedClaims.ACL, nil
	}

	if !isPassport(info.Token) {
		return a.remote.GetACL(ctx, organizationID)
	}

	// Re-parse payload without signature verification — already verified in Authorize().
	var parsedClaims identityoauth2.PassportClaims
	if err := parseJWTPayload(info.Token, &parsedClaims); err != nil {
		return nil, fmt.Errorf("passport: failed to re-parse JWT payload: %w", err)
	}

	a.cacheClaims(info.Token, &parsedClaims)

	return parsedClaims.ACL, nil
}
