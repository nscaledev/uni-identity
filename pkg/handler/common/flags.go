/*
Copyright 2025 the Unikorn Authors.
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

package common

import (
	"net/url"

	"github.com/spf13/pflag"
)

// IssuerValue is a value that can be used with pflag.Var, so as to set an issuer URL and hostname
// with the same argument.
type IssuerValue struct {
	// URL is the OAuth2/OIDC issuer URL (e.g., "https://identity.example.com")
	// This is used when minting tokens and populating subject records.
	URL string
	// Hostname is just the hostname part (e.g., "identity.example.com")
	// This is used for audience claims and other non-issuer uses.
	Hostname string
}

var _ pflag.Value = &IssuerValue{}

func (v *IssuerValue) Set(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return err
	}

	v.URL = value
	v.Hostname = u.Hostname()

	return nil
}

func (v *IssuerValue) String() string {
	return v.URL
}

func (*IssuerValue) Type() string {
	return "issuerURL"
}
