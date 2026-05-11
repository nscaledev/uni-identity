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

package auth0

import (
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const (
	// DefaultJWKSPath is the path appended to the issuer to derive the JWKS URL
	// when no explicit override is provided. Matches Auth0's well-known location.
	DefaultJWKSPath = ".well-known/jwks.json"

	// DefaultJWKSCacheTTL is the default in-memory TTL for cached Auth0 keys.
	// Long enough that signature validation does not fan out to the network on
	// the hot path; short enough that key rotations propagate within minutes.
	DefaultJWKSCacheTTL = 10 * time.Minute

	// DefaultJWKSHTTPTimeout bounds JWKS fetches so a stalled IdP cannot stall
	// the exchange request indefinitely.
	DefaultJWKSHTTPTimeout = 5 * time.Second

	// DefaultRequiredScope is the scope/permission an Auth0 access token must
	// carry to be accepted at the exchange endpoint.
	DefaultRequiredScope = "identity:token:exchange"

	// DefaultUserinfoPath is the path appended to issuer for Auth0 /userinfo.
	DefaultUserinfoPath = "userinfo"

	// DefaultUserinfoHTTPTimeout bounds one /userinfo fallback call.
	DefaultUserinfoHTTPTimeout = 700 * time.Millisecond

	// DefaultUserinfoMaxRetries limits migration fallback retries.
	DefaultUserinfoMaxRetries = 1

	// DefaultUserinfoRetryBackoff is the pause between fallback retries.
	DefaultUserinfoRetryBackoff = 100 * time.Millisecond

	// DefaultUserinfoCircuitFailures opens circuit after consecutive failures.
	DefaultUserinfoCircuitFailures = 5

	// DefaultUserinfoCircuitOpenDuration is breaker open interval.
	DefaultUserinfoCircuitOpenDuration = 30 * time.Second
)

// Options is the operator-facing configuration for the Auth0 verifier.
// Issuer/audience/jwks-url are exposed as CLI flags. Cache TTL and HTTP
// timeout are intentionally kept as code-level options with safe defaults
// — operators should not need to tune these per-deployment.
type Options struct {
	// Issuer is the Auth0 tenant issuer URL (e.g. https://tenant.auth0.com/).
	// Empty disables the Auth0 validator.
	Issuer string

	// Audience is the API identifier the access token must be addressed to.
	Audience string

	// JWKSURL overrides the JWKS endpoint. If empty, it is derived from Issuer
	// as <issuer>/.well-known/jwks.json.
	JWKSURL string

	// JWKSCacheTTL controls how long a fetched key set is reused before refresh.
	JWKSCacheTTL time.Duration

	// JWKSHTTPTimeout bounds individual JWKS fetches.
	JWKSHTTPTimeout time.Duration

	// RequiredScope is the value that must appear in either the `permissions`
	// or `scope` claim for the token to be accepted at exchange.
	RequiredScope string

	// OpaqueFallbackEnabled allows temporary Auth0 /userinfo fallback for opaque
	// tokens during migration.
	OpaqueFallbackEnabled bool

	// UserinfoURL overrides the /userinfo endpoint. If empty, derived from issuer.
	UserinfoURL string

	// UserinfoHTTPTimeout bounds one /userinfo call.
	UserinfoHTTPTimeout time.Duration

	// UserinfoMaxRetries bounds /userinfo retries after transient failures.
	UserinfoMaxRetries int

	// UserinfoRetryBackoff is the delay between retries.
	UserinfoRetryBackoff time.Duration

	// UserinfoCircuitFailures opens the breaker after N consecutive failures.
	UserinfoCircuitFailures int

	// UserinfoCircuitOpenDuration keeps breaker open before half-open probe.
	UserinfoCircuitOpenDuration time.Duration
}

// AddFlags wires the operator-facing CLI options. Tuning options (TTL,
// timeout, required scope) deliberately remain non-flag.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.Issuer, "auth0-issuer", "", "Auth0 tenant issuer URL. Empty disables Auth0 token validation at exchange.")
	f.StringVar(&o.Audience, "auth0-audience", "", "Auth0 API audience that access tokens must be addressed to.")
	f.StringVar(&o.JWKSURL, "auth0-jwks-url", "", "Override the JWKS URL. Derived from --auth0-issuer when empty.")
	f.BoolVar(&o.OpaqueFallbackEnabled, "auth0-opaque-fallback-enabled", false, "Enable temporary Auth0 /userinfo fallback for opaque tokens during migration.")
}

// Enabled returns true when the operator has configured an Auth0 issuer.
// Audience is a runtime requirement enforced by the verifier; we only treat
// the validator as wired when the issuer is set.
func (o *Options) Enabled() bool {
	return strings.TrimSpace(o.Issuer) != ""
}

// EffectiveJWKSURL returns the configured override, or the default derived
// from Issuer. Returns empty string when no issuer is configured.
func (o *Options) EffectiveJWKSURL() string {
	if override := strings.TrimSpace(o.JWKSURL); override != "" {
		return override
	}

	issuer := strings.TrimSpace(o.Issuer)
	if issuer == "" {
		return ""
	}

	return strings.TrimRight(issuer, "/") + "/" + DefaultJWKSPath
}

// EffectiveUserinfoURL returns configured override, or issuer-derived /userinfo URL.
func (o *Options) EffectiveUserinfoURL() string {
	if override := strings.TrimSpace(o.UserinfoURL); override != "" {
		return override
	}

	issuer := strings.TrimSpace(o.Issuer)
	if issuer == "" {
		return ""
	}

	return strings.TrimRight(issuer, "/") + "/" + DefaultUserinfoPath
}

// EffectiveJWKSCacheTTL returns the configured TTL, falling back to the default.
func (o *Options) EffectiveJWKSCacheTTL() time.Duration {
	if o.JWKSCacheTTL > 0 {
		return o.JWKSCacheTTL
	}

	return DefaultJWKSCacheTTL
}

// EffectiveJWKSHTTPTimeout returns the configured timeout, falling back to the default.
func (o *Options) EffectiveJWKSHTTPTimeout() time.Duration {
	if o.JWKSHTTPTimeout > 0 {
		return o.JWKSHTTPTimeout
	}

	return DefaultJWKSHTTPTimeout
}

// EffectiveRequiredScope returns the configured required scope, falling back to the default.
func (o *Options) EffectiveRequiredScope() string {
	if scope := strings.TrimSpace(o.RequiredScope); scope != "" {
		return scope
	}

	return DefaultRequiredScope
}

// EffectiveUserinfoHTTPTimeout returns configured timeout or default.
func (o *Options) EffectiveUserinfoHTTPTimeout() time.Duration {
	if o.UserinfoHTTPTimeout > 0 {
		return o.UserinfoHTTPTimeout
	}

	return DefaultUserinfoHTTPTimeout
}

// EffectiveUserinfoMaxRetries returns configured retries or default.
func (o *Options) EffectiveUserinfoMaxRetries() int {
	if o.UserinfoMaxRetries >= 0 {
		return o.UserinfoMaxRetries
	}

	return DefaultUserinfoMaxRetries
}

// EffectiveUserinfoRetryBackoff returns configured backoff or default.
func (o *Options) EffectiveUserinfoRetryBackoff() time.Duration {
	if o.UserinfoRetryBackoff > 0 {
		return o.UserinfoRetryBackoff
	}

	return DefaultUserinfoRetryBackoff
}

// EffectiveUserinfoCircuitFailures returns configured threshold or default.
func (o *Options) EffectiveUserinfoCircuitFailures() int {
	if o.UserinfoCircuitFailures > 0 {
		return o.UserinfoCircuitFailures
	}

	return DefaultUserinfoCircuitFailures
}

// EffectiveUserinfoCircuitOpenDuration returns configured open duration or default.
func (o *Options) EffectiveUserinfoCircuitOpenDuration() time.Duration {
	if o.UserinfoCircuitOpenDuration > 0 {
		return o.UserinfoCircuitOpenDuration
	}

	return DefaultUserinfoCircuitOpenDuration
}
