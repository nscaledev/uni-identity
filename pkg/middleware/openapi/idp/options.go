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

package idp

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spf13/pflag"
)

// Options configures the optional external OIDC issuer (federated user tokens).
// The platform's own issuer is configured separately (its JWKS and claims are
// known), so these flags describe only the third-party issuer.
type Options struct {
	Issuer                  string
	Audience                string
	TokenVerificationLeeway time.Duration
	JWKSMinRefreshInterval  time.Duration
}

// AddFlags registers the external OIDC issuer flags. The names are shared by the
// identity service and by the remote middleware so both validate the same
// issuer/audience.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.Issuer, "oidc-issuer", "", "External OIDC issuer accepted for local validation of federated user access tokens.")
	f.StringVar(&o.Audience, "oidc-audience", "", "External OIDC API audience asserted when validating federated user access tokens.")
}

// Enabled reports whether an external OIDC issuer is configured.
func (o *Options) Enabled() bool {
	return o.Issuer != "" || o.Audience != ""
}

// IssuerConfig builds the resolver config for the external OIDC issuer. The
// federated user's email (surfaced under our namespaced claim on the access
// token) is the subject; machine grants and unverified emails are rejected.
func (o *Options) IssuerConfig() IssuerConfig {
	return IssuerConfig{
		Issuer:    o.Issuer,
		Audience:  o.Audience,
		Algorithm: jose.RS256,
		Mapper: EmailUserMapper(
			"https://unikorn-cloud.org/email",
			"https://unikorn-cloud.org/email_verified",
		),
		TokenVerificationLeeway: o.TokenVerificationLeeway,
		JWKSMinRefreshInterval:  o.JWKSMinRefreshInterval,
	}
}
