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

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

func TestMaxListLimitMatchesSpec(t *testing.T) {
	t.Parallel()

	spec, err := openapi.GetSwagger()
	require.NoError(t, err)

	param := spec.Components.Parameters["organizationListLimitParameter"]
	require.NotNil(t, param)
	require.NotNil(t, param.Value.Schema.Value.Min)
	require.InDelta(t, 1, *param.Value.Schema.Value.Min, 0)
	require.NotNil(t, param.Value.Schema.Value.Max)
	require.InDelta(t, float64(maxListLimit), *param.Value.Schema.Value.Max, 0)
}

func TestListParameterRulesMatchSpec(t *testing.T) {
	t.Parallel()

	spec, err := openapi.GetSwagger()
	require.NoError(t, err)

	name := spec.Components.Parameters["organizationListNameParameter"]
	require.NotNil(t, name)
	require.Equal(t, nameFilterPattern, name.Value.Schema.Value.Pattern)
	require.NotNil(t, name.Value.Schema.Value.MaxLength)
	require.Equal(t, uint64(maxNameFilterLength), *name.Value.Schema.Value.MaxLength)

	cursor := spec.Components.Parameters["organizationListCursorParameter"]
	require.NotNil(t, cursor)
	require.NotNil(t, cursor.Value.Schema.Value.MaxLength)
	require.Equal(t, uint64(maxCursorLength), *cursor.Value.Schema.Value.MaxLength)

	id := spec.Components.Parameters["organizationListIDParameter"]
	require.NotNil(t, id)
	require.NotNil(t, id.Value.Schema.Value.MaxItems)
	require.Equal(t, uint64(maxIDs), *id.Value.Schema.Value.MaxItems)
}

func TestOptionsDefaults(t *testing.T) {
	t.Parallel()

	options := &Options{}
	options.AddFlags(pflag.NewFlagSet("test", pflag.ContinueOnError))

	require.Equal(t, 0, options.V1ListLimit)
	require.Equal(t, 50, options.V2DefaultLimit)
	require.NoError(t, options.Validate())
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	require.NoError(t, (&Options{}).Validate())

	for name, options := range map[string]Options{
		"negative v1 limit":   {V1ListLimit: -1, V2DefaultLimit: 50},
		"negative v2 default": {V1ListLimit: 0, V2DefaultLimit: -1},
		"v2 default too big":  {V1ListLimit: 0, V2DefaultLimit: maxListLimit + 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.ErrorIs(t, options.Validate(), ErrInvalidOptions)
		})
	}

	require.NoError(t, (&Options{V1ListLimit: 0, V2DefaultLimit: maxListLimit}).Validate())
}

func TestOptionsV2Limit(t *testing.T) {
	t.Parallel()

	require.Equal(t, 50, (&Options{}).V2Limit())
	require.Equal(t, 25, (&Options{V2DefaultLimit: 25}).V2Limit())
}
