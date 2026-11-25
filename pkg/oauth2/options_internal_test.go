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

package oauth2

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// Deployments may still pass --code-cache-size; it must parse until removed.
func TestOptionsAcceptDeprecatedCodeCacheSize(t *testing.T) {
	t.Parallel()

	options := &Options{}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	options.AddFlags(flags)

	require.NoError(t, flags.Parse([]string{"--code-cache-size=8192"}))
}
