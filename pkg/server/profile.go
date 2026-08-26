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

package server

import (
	goerrors "errors"
	"fmt"

	"github.com/spf13/pflag"
)

// ErrInvalidAPIProfile is returned for an unrecognized profile.  Parsing
// fails loudly at startup: a typo must never silently select a surface
// nobody intended.
var ErrInvalidAPIProfile = goerrors.New("invalid API profile")

// APIProfile selects which HTTP surface the server mounts.
type APIProfile string

const (
	// APIProfileFull mounts every operation in the spec.  The default, and
	// the only value that predates the enclave authorization profile, so an
	// unset flag must resolve here.
	APIProfileFull APIProfile = "full"

	// APIProfileAuthorization mounts ONLY the read-only authorization
	// surface: the decision endpoint and both ACL routes.  Every write
	// route is absent from the mux, which is the profile's primary guard.
	// It is not the write guard: the handler is still constructed over a
	// write-capable client, so the deployment's read-only ClusterRole is
	// what makes a write impossible.
	APIProfileAuthorization APIProfile = "authorization"
)

var _ pflag.Value = (*APIProfile)(nil)

// Set implements pflag.Value with whitelist validation.
func (p *APIProfile) Set(value string) error {
	profile := APIProfile(value)

	if profile != APIProfileFull && profile != APIProfileAuthorization {
		return fmt.Errorf("%w: %q (valid values: %s, %s)", ErrInvalidAPIProfile, value, APIProfileFull, APIProfileAuthorization)
	}

	*p = profile

	return nil
}

// String implements pflag.Value.
func (p *APIProfile) String() string {
	return string(*p)
}

// Type implements pflag.Value.
func (*APIProfile) Type() string {
	return "apiProfile"
}
