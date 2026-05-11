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

package exchange

import (
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
)

// Result classifies an exchange outcome for metric labelling. Values are kept
// short to bound cardinality and stable so dashboards survive code refactors.
type Result string

const (
	ResultSuccess           Result = "success"
	ResultUnauthorized      Result = "unauthorized"
	ResultUnsupportedSource Result = "unsupported_source"
	ResultMalformed         Result = "malformed"
	ResultJWKSUnavailable   Result = "jwks_unavailable"
	ResultExpired           Result = "expired"
	ResultInsufficientScope Result = "insufficient_scope"
	ResultInvalidRequest    Result = "invalid_request"
	ResultError             Result = "error"
)

// ValidationMode labels which Auth0 validation path resolved the token.
type ValidationMode string

const (
	ValidationModeJWT      ValidationMode = "jwt"
	ValidationModeUserinfo ValidationMode = "userinfo"
)

//nolint:gochecknoglobals
var (
	exchangeRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_exchange_requests_total",
			Help: "Total number of exchange requests, labeled by token source and result.",
		},
		[]string{"source", "result"},
	)

	exchangeDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "identity_exchange_duration_seconds",
			Help: "End-to-end latency of exchange requests, labeled by token source.",
		},
		[]string{"source"},
	)

	auth0ValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "identity_exchange_auth0_validation_total",
			Help: "Auth0 exchange validation attempts by mode and result.",
		},
		[]string{"mode", "result"},
	)

	auth0UserinfoDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "identity_exchange_auth0_userinfo_duration_seconds",
			Help: "Latency of Auth0 /userinfo fallback validation calls.",
		},
		[]string{"result"},
	)
)

// ObserveExchange records the outcome of one exchange request. Callers should
// invoke this in a defer immediately after measuring start time, e.g.:
//
//	start := time.Now()
//	defer func() { ObserveExchange(source, result, time.Since(start)) }()
//
// source may be SourceUnknown when classification failed before validator
// dispatch — it is normalized to a stable label.
func ObserveExchange(source Source, result Result, duration time.Duration) {
	label := sourceLabel(source)

	exchangeRequestsTotal.WithLabelValues(label, string(result)).Inc()
	exchangeDurationSeconds.WithLabelValues(label).Observe(duration.Seconds())
}

// ObserveAuth0Validation records Auth0 validation attempt mode and result.
func ObserveAuth0Validation(mode ValidationMode, result Result) {
	auth0ValidationTotal.WithLabelValues(string(mode), string(result)).Inc()
}

// ObserveAuth0UserinfoCall records Auth0 /userinfo fallback latency by result.
func ObserveAuth0UserinfoCall(result Result, duration time.Duration) {
	auth0UserinfoDurationSeconds.WithLabelValues(string(result)).Observe(duration.Seconds())
}

func sourceLabel(s Source) string {
	if s == SourceUnknown {
		return "unknown"
	}

	return string(s)
}

// ClassifyResult maps a validator/router error to a Result label. Pass nil for
// success. Mapping is intentionally narrow — anything unrecognised falls
// through to ResultError so we don't accidentally leak token-derived strings
// into metric cardinality.
func ClassifyResult(err error) Result {
	if err == nil {
		return ResultSuccess
	}

	if result, ok := classifyKnownResult(err); ok {
		return result
	}

	if result, ok := classifyOAuth2Result(err); ok {
		return result
	}

	return ResultError
}

func classifyKnownResult(err error) (Result, bool) {
	switch {
	case errors.Is(err, ErrMalformedToken):
		return ResultMalformed, true
	case errors.Is(err, ErrUnsupportedSource):
		return ResultUnsupportedSource, true
	case errors.Is(err, auth0.ErrJWKSUnavailable):
		return ResultJWKSUnavailable, true
	case errors.Is(err, auth0.ErrTokenExpired):
		return ResultExpired, true
	case errors.Is(err, auth0.ErrInsufficientScope):
		return ResultInsufficientScope, true
	case errors.Is(err, auth0.ErrInvalidToken), errors.Is(err, ErrUNIUserinfoNotAvailable):
		return ResultUnauthorized, true
	case errors.Is(err, auth0.ErrUserinfoUnavailable), errors.Is(err, auth0.ErrUserinfoCircuitOpen):
		return ResultError, true
	default:
		return "", false
	}
}

func classifyOAuth2Result(err error) (Result, bool) {
	var oauthErr *oauth2errors.Error
	if !errors.As(err, &oauthErr) {
		return "", false
	}

	switch oauthErr.StatusCode() {
	case http.StatusUnauthorized:
		return ResultUnauthorized, true
	case http.StatusBadRequest:
		return ResultInvalidRequest, true
	default:
		return "", false
	}
}
