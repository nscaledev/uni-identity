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

package organizations

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestOptionsDefaults(t *testing.T) {
	t.Parallel()

	options := &Options{}
	options.AddFlags(pflag.NewFlagSet("test", pflag.ContinueOnError))

	require.Equal(t, 0, options.V1ListLimit)
	require.NoError(t, options.Validate())
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	require.NoError(t, (&Options{}).Validate())
	require.NoError(t, (&Options{V1ListLimit: 25}).Validate())
	require.ErrorIs(t, (&Options{V1ListLimit: -1}).Validate(), ErrInvalidOptions)
}
