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
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	apierrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	openapiinterfaces "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityoauth2 "github.com/unikorn-cloud/identity/pkg/oauth2"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// defaultJWKSCacheTTL is the default TTL for the JWKS cache.
	defaultJWKSCacheTTL = 5 * time.Minute
	// defaultJWKSTimeout is the timeout for JWKS fetch requests.
	defaultJWKSTimeout = 5 * time.Second
	// defaultExchangeTimeout is the timeout for token exchange requests.
	defaultExchangeTimeout = 5 * time.Second
)

// Options controls timeout and cache settings for the passport authorizer.
// Zero values use package defaults.
//
// ExchangeTimeout controls the HTTP timeout used when exchanging a non-passport
// bearer token for a passport at /oauth2/v2/token.
//
// This is configurable programmatically by constructing the authorizer via
// NewAuthorizerWithOptions. There is intentionally no global flag at this layer;
// embedding services can surface this through their own configuration surface if
// required.
type Options struct {
	JWKSCacheTTL    time.Duration
	JWKSTimeout     time.Duration
	ExchangeTimeout time.Duration
}

func (o *Options) withDefaults() *Options {
	if o == nil {
		return &Options{
			JWKSCacheTTL:    defaultJWKSCacheTTL,
			JWKSTimeout:     defaultJWKSTimeout,
			ExchangeTimeout: defaultExchangeTimeout,
		}
	}

	out := *o

	if out.JWKSCacheTTL <= 0 {
		out.JWKSCacheTTL = defaultJWKSCacheTTL
	}

	if out.JWKSTimeout <= 0 {
		out.JWKSTimeout = defaultJWKSTimeout
	}

	if out.ExchangeTimeout <= 0 {
		out.ExchangeTimeout = defaultExchangeTimeout
	}

	return &out
}

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

	passportExchangeTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_passport_exchange_total",
			Help: "Total raw token exchange attempts performed by passport middleware.",
		},
		[]string{"result"},
	)

	passportExchangeDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name: "identity_passport_exchange_duration_seconds",
			Help: "Latency of token exchange calls performed by passport middleware.",
		},
	)
)

// Authorizer implements openapi.Authorizer.
// It verifies passport JWTs locally and exchanges non-passport bearer tokens.
type Authorizer struct {
	verifier *Verifier
	// uni handles ACL lookup and non-passport/degraded authorization paths.
	// This is intentionally interface-typed so callers can swap implementations.
	uni      openapiinterfaces.Authorizer
	exchange exchanger
}

var _ openapiinterfaces.Authorizer = &Authorizer{}

var (
	errUniAuthorizerRequired = errors.New("passport: uni authorizer is required")
	errHTTPClientRequired    = errors.New("passport: http client is required")
	errIdentityHostRequired  = errors.New("passport: identity host is required")
)

// NewAuthorizer builds a passport Authorizer.
//
// uni is required because passport middleware still relies on a non-passport
// authorizer for ACL lookup and degraded-mode fallback when token exchange is
// temporarily unavailable.
func NewAuthorizer(httpClient *http.Client, identityHost string, uni openapiinterfaces.Authorizer, options *Options) (*Authorizer, error) {
	if uni == nil {
		return nil, errUniAuthorizerRequired
	}

	if httpClient == nil {
		return nil, errHTTPClientRequired
	}

	if strings.TrimSpace(identityHost) == "" {
		return nil, errIdentityHostRequired
	}

	options = options.withDefaults()

	jwksHTTPClient := *httpClient
	jwksHTTPClient.Timeout = options.JWKSTimeout

	exchangeHTTPClient := *httpClient
	exchangeHTTPClient.Timeout = options.ExchangeTimeout

	var (
		host      = strings.TrimRight(identityHost, "/")
		jwksURI   = host + "/oauth2/v2/jwks"
		tokenURL  = host + "/oauth2/v2/token"
		jwksCache = NewJWKSCache(&jwksHTTPClient, jwksURI, options.JWKSCacheTTL)
		verifier  = NewVerifier(jwksCache)
	)

	return &Authorizer{
		verifier: verifier,
		uni:      uni,
		exchange: newExchangeClient(&exchangeHTTPClient, tokenURL),
	}, nil
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

func newExchangeOptionsFromInput(input *openapi3filter.AuthenticationInput) *exchangeOptions {
	if input == nil || input.RequestValidationInput == nil || input.RequestValidationInput.PathParams == nil {
		return nil
	}

	return &exchangeOptions{
		organizationID: input.RequestValidationInput.PathParams["organizationID"],
		projectID:      input.RequestValidationInput.PathParams["projectID"],
	}
}

func authorizationInfoFromPassport(passportToken, sourceToken string, claims *identityoauth2.PassportClaims) *authorization.Info {
	var email *string
	if e := claims.Email; e != "" {
		email = &e
	}

	return &authorization.Info{
		Token:    sourceToken,
		Passport: passportToken,
		Userinfo: &identityapi.Userinfo{
			Sub:   claims.Subject,
			Email: email,
			HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{
				Acctype: claims.Acctype,
				OrgIds:  claims.OrgIDs,
			},
		},
	}
}

func handlePassportVerificationError(r *http.Request, err error) error {
	switch {
	case errors.Is(err, ErrPassportExpired):
		passportVerificationTotal.WithLabelValues("expired").Inc()
		return apierrors.AccessDenied(r, "passport token has expired").WithValues("auth_method", "passport")

	case errors.Is(err, ErrPassportInvalidSig):
		passportVerificationTotal.WithLabelValues("invalid_signature").Inc()
		return apierrors.AccessDenied(r, "passport token has an invalid signature").WithValues("auth_method", "passport")

	case errors.Is(err, ErrJWKSUnavailable):
		passportVerificationTotal.WithLabelValues("jwks_unavailable").Inc()
		// Do not return the raw upstream/JWKS error string to callers.
		// We log details server-side and return a generic internal failure.
		log.FromContext(r.Context()).Error(err, "passport verification unavailable due to JWKS fetch/refresh failure", "auth_method", "passport")

		return fmt.Errorf("%w: passport verification temporarily unavailable", ErrJWKSUnavailable)

	default:
		return fmt.Errorf("identity: passport verification failed: %w", err)
	}
}

func (a *Authorizer) timedExchange(ctx context.Context, sourceToken string, options *exchangeOptions) (string, error) {
	start := time.Now()
	passportToken, err := a.exchange.Exchange(ctx, sourceToken, options)
	duration := time.Since(start).Seconds()
	passportExchangeDuration.Observe(duration)

	return passportToken, err
}

// Authorize implements openapi.Authorizer.
func (a *Authorizer) Authorize(input *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	r := input.RequestValidationInput.Request

	rawToken, err := getBearerToken(input)
	if err != nil {
		return nil, err
	}

	logger := log.FromContext(r.Context())

	claims, err := a.verifier.Verify(r.Context(), rawToken)
	if err == nil {
		passportVerificationTotal.WithLabelValues("success").Inc()
		passportAuthorizerTotal.WithLabelValues("passport").Inc()

		return authorizationInfoFromPassport(rawToken, "", claims), nil
	}

	if !errors.Is(err, ErrNotPassport) {
		return nil, handlePassportVerificationError(r, err)
	}

	exchangeOpts := newExchangeOptionsFromInput(input)

	passportToken, err := a.timedExchange(r.Context(), rawToken, exchangeOpts)
	if err != nil {
		switch {
		case errors.Is(err, ErrExchangeUnauthorized):
			passportExchangeTotal.WithLabelValues("unauthorized").Inc()
			logger.Info("passport exchange rejected source token", "auth_method", "exchange")

			return nil, apierrors.AccessDenied(r, "token is invalid or has expired").WithValues("auth_method", "exchange")

		case errors.Is(err, ErrExchangeUnavailable):
			passportExchangeTotal.WithLabelValues("fallback").Inc()
			passportAuthorizerTotal.WithLabelValues("remote_fallback").Inc()
			// Fallback is not an authorization bypass.
			//
			// The legacy remote path still performs full token validation and ACL
			// retrieval against identity. We use it only for exchange availability
			// failures to preserve availability while keeping fail-closed semantics for
			// invalid credentials (ErrExchangeUnauthorized and passport verification
			// errors never fall back).
			logger.Info("passport exchange unavailable, using legacy authorization fallback", "auth_method", "remote_fallback", "fallback_reason", "exchange_unavailable")

			return a.uni.Authorize(input)

		default:
			passportExchangeTotal.WithLabelValues("error").Inc()
			logger.Error(err, "passport exchange failed", "auth_method", "exchange")

			return nil, fmt.Errorf("identity: token exchange failed: %w", err)
		}
	}

	passportExchangeTotal.WithLabelValues("success").Inc()

	claims, err = a.verifier.Verify(r.Context(), passportToken)
	if err != nil {
		return nil, handlePassportVerificationError(r, err)
	}

	passportVerificationTotal.WithLabelValues("success").Inc()
	passportAuthorizerTotal.WithLabelValues("passport").Inc()

	return authorizationInfoFromPassport(passportToken, rawToken, claims), nil
}

// GetACL implements openapi.Authorizer.
func (a *Authorizer) GetACL(ctx context.Context, organizationID string) (*identityapi.Acl, error) {
	return a.uni.GetACL(ctx, organizationID)
}
