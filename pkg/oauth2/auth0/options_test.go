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

package auth0_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
)

func TestOptions_AddFlagsParsesAll(t *testing.T) {
	t.Parallel()

	o := &auth0.Options{}

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o.AddFlags(flags)

	require.NoError(t, flags.Parse([]string{
		"--auth0-issuer=https://tenant.auth0.com/",
		"--auth0-audience=https://identity.example.com",
		"--auth0-jwks-url=https://tenant.auth0.com/keys",
		"--auth0-opaque-fallback-enabled=true",
	}))

	assert.Equal(t, "https://tenant.auth0.com/", o.Issuer)
	assert.Equal(t, "https://identity.example.com", o.Audience)
	assert.Equal(t, "https://tenant.auth0.com/keys", o.JWKSURL)
	assert.True(t, o.OpaqueFallbackEnabled)
}

func TestOptions_Enabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		options  auth0.Options
		expected bool
	}{
		{
			name:     "empty issuer is disabled",
			options:  auth0.Options{},
			expected: false,
		},
		{
			name:     "whitespace issuer is disabled",
			options:  auth0.Options{Issuer: "  "},
			expected: false,
		},
		{
			name:     "configured issuer is enabled",
			options:  auth0.Options{Issuer: "https://tenant.auth0.com/"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, (&tt.options).Enabled())
		})
	}
}

func TestOptions_EffectiveJWKSURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		options  auth0.Options
		expected string
	}{
		{
			name:     "trailing slash on issuer is normalized",
			options:  auth0.Options{Issuer: "https://tenant.auth0.com/"},
			expected: "https://tenant.auth0.com/.well-known/jwks.json",
		},
		{
			name:     "no trailing slash on issuer",
			options:  auth0.Options{Issuer: "https://tenant.auth0.com"},
			expected: "https://tenant.auth0.com/.well-known/jwks.json",
		},
		{
			name:     "explicit override wins over issuer-derived URL",
			options:  auth0.Options{Issuer: "https://tenant.auth0.com/", JWKSURL: "https://other/.well-known/jwks.json"},
			expected: "https://other/.well-known/jwks.json",
		},
		{
			name:     "no issuer, no override — returns empty",
			options:  auth0.Options{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.expected, tt.options.EffectiveJWKSURL())
		})
	}
}

func TestOptions_EffectiveUserinfoURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		options  auth0.Options
		expected string
	}{
		{
			name:     "trailing slash on issuer is normalized",
			options:  auth0.Options{Issuer: "https://tenant.auth0.com/"},
			expected: "https://tenant.auth0.com/userinfo",
		},
		{
			name:     "explicit override wins over issuer-derived URL",
			options:  auth0.Options{Issuer: "https://tenant.auth0.com/", UserinfoURL: "https://tenant.auth0.com/custom-userinfo"},
			expected: "https://tenant.auth0.com/custom-userinfo",
		},
		{
			name:     "no issuer, no override returns empty",
			options:  auth0.Options{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.options.EffectiveUserinfoURL())
		})
	}
}

func TestOptions_Defaults(t *testing.T) {
	t.Parallel()

	t.Run("effective jwks cache ttl", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{}
		assert.Equal(t, auth0.DefaultJWKSCacheTTL, o.EffectiveJWKSCacheTTL())
	})

	t.Run("effective jwks http timeout", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{}
		assert.Equal(t, auth0.DefaultJWKSHTTPTimeout, o.EffectiveJWKSHTTPTimeout())
	})

	t.Run("effective required scope", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{}
		assert.Equal(t, auth0.DefaultRequiredScope, o.EffectiveRequiredScope())
	})

	t.Run("effective userinfo http timeout", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{}
		assert.Equal(t, auth0.DefaultUserinfoHTTPTimeout, o.EffectiveUserinfoHTTPTimeout())
	})

	t.Run("effective userinfo max retries", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{UserinfoMaxRetries: -1}
		assert.Equal(t, auth0.DefaultUserinfoMaxRetries, o.EffectiveUserinfoMaxRetries())
	})

	t.Run("effective userinfo retry backoff", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{}
		assert.Equal(t, auth0.DefaultUserinfoRetryBackoff, o.EffectiveUserinfoRetryBackoff())
	})

	t.Run("effective userinfo circuit failures", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{}
		assert.Equal(t, auth0.DefaultUserinfoCircuitFailures, o.EffectiveUserinfoCircuitFailures())
	})

	t.Run("effective userinfo circuit open duration", func(t *testing.T) {
		t.Parallel()

		o := &auth0.Options{}
		assert.Equal(t, auth0.DefaultUserinfoCircuitOpenDuration, o.EffectiveUserinfoCircuitOpenDuration())
	})
}
