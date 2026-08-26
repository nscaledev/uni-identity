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

package server_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/server"
)

// TestAPIProfileDefaultIsFull pins the compatibility contract: an unset flag
// serves the whole API, because every deployment that predates the profile
// depends on that.  The safety of the narrow profile comes from the chart
// always setting the flag and from the read-only ClusterRole, not from a
// defensive default here.
func TestAPIProfileDefaultIsFull(t *testing.T) {
	t.Parallel()

	options := &server.Options{}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	options.AddFlags(flags)

	require.NoError(t, flags.Parse(nil))
	require.Equal(t, server.APIProfileFull, options.APIProfile)
}

// TestAPIProfileAccepts pins the two legal values.
func TestAPIProfileAccepts(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"full", "authorization"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			options := &server.Options{}
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			options.AddFlags(flags)

			require.NoError(t, flags.Parse([]string{"--api-profile=" + value}))
			require.Equal(t, server.APIProfile(value), options.APIProfile)
		})
	}
}

// TestAPIProfileRejectsUnknown pins fail-loud parsing.  A typo must stop the
// process at startup rather than silently select a surface nobody intended.
func TestAPIProfileRejectsUnknown(t *testing.T) {
	t.Parallel()

	options := &server.Options{}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	options.AddFlags(flags)

	err := flags.Parse([]string{"--api-profile=authz"})
	require.ErrorIs(t, err, server.ErrInvalidAPIProfile)
}
