/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

package handler

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/serviceaccounts"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
)

// Options defines configurable handler options.
type Options struct {
	// cacheMaxAge defines the max age for cachable items e.g. images and
	// flavors don't change all that often.
	CacheMaxAge time.Duration

	// Options contains options shared across multiple handler components.
	Issuer common.IssuerValue

	// ServiceAccounts define any service account tunables.
	ServiceAccounts serviceaccounts.Options

	// Users define any user tunables.
	Users users.Options
}

// AddFlags adds the options flags to the given flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	// This is given the arg name --host for backward-compatibility; the expected value includes the scheme, e.g., https://identity.unikorn-cloud.org
	f.Var(&o.Issuer, "host", "The service hostname.")
	f.DurationVar(&o.CacheMaxAge, "cache-max-age", 24*time.Hour, "How long to cache long-lived queries in the browser.")

	o.ServiceAccounts.AddFlags(f)
	o.Users.AddFlags(f)
}
