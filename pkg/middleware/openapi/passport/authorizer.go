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
	uni           openapiinterfaces.Authorizer
	tokenExchange TokenExchange
}

var _ openapiinterfaces.Authorizer = &Authorizer{}

var (
	errVerifierRequired      = errors.New("passport: verifier is required")
	errUniAuthorizerRequired = errors.New("passport: uni authorizer is required")
	errTokenExchangeRequired = errors.New("passport: token exchange is required")
)

// NewAuthorizer builds a passport Authorizer from explicit dependencies.
func NewAuthorizer(verifier *Verifier, uni openapiinterfaces.Authorizer, tokenExchange TokenExchange) (*Authorizer, error) {
	if verifier == nil {
		return nil, errVerifierRequired
	}

	if uni == nil {
		return nil, errUniAuthorizerRequired
	}

	if tokenExchange == nil {
		return nil, errTokenExchangeRequired
	}

	return &Authorizer{
		verifier:      verifier,
		uni:           uni,
		tokenExchange: tokenExchange,
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

func newTokenExchangeOptionsFromInput(input *openapi3filter.AuthenticationInput) *tokenExchangeOptions {
	if input == nil || input.RequestValidationInput == nil || input.RequestValidationInput.PathParams == nil {
		return nil
	}

	return &tokenExchangeOptions{
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

func (a *Authorizer) timedTokenExchange(ctx context.Context, sourceToken string, options *tokenExchangeOptions) (string, error) {
	start := time.Now()
	passportToken, err := a.tokenExchange.Exchange(ctx, sourceToken, options)
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

	tokenExchangeOpts := newTokenExchangeOptionsFromInput(input)

	passportToken, err := a.timedTokenExchange(r.Context(), rawToken, tokenExchangeOpts)
	if err != nil {
		switch {
		case errors.Is(err, ErrTokenExchangeUnauthorized):
			passportExchangeTotal.WithLabelValues("unauthorized").Inc()
			logger.Info("passport exchange rejected source token", "auth_method", "exchange")

			return nil, apierrors.AccessDenied(r, "token is invalid or has expired").WithValues("auth_method", "exchange")

		case errors.Is(err, ErrTokenExchangeUnavailable):
			passportExchangeTotal.WithLabelValues("fallback").Inc()
			passportAuthorizerTotal.WithLabelValues("remote_fallback").Inc()
			// Fallback is not an authorization bypass.
			//
			// The legacy remote path still performs full token validation and ACL
			// retrieval against identity. We use it only for exchange availability
			// failures to preserve availability while keeping fail-closed semantics for
			// invalid credentials (ErrTokenExchangeUnauthorized and passport verification
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
