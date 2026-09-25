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
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/utils/ptr"
)

func TestResolveWalk(t *testing.T) {
	t.Parallel()

	bound := Cursor{ID: "id", Filter: "acme", Email: "a@example.com"}.Encode()
	boundUpper := Cursor{ID: "id", Filter: "ACME", Email: "a@example.com"}.Encode()
	unbound := Cursor{ID: "id"}.Encode()
	longEmail := strings.Repeat("a", 242) + "@example.com"
	longName := strings.Repeat("a", maxNameFilterLength+1)

	options := &Options{V2DefaultLimit: 25}

	cases := map[string]struct {
		options    *Options
		params     openapi.GetApiV2OrganizationsParams
		wantFilter string
		wantEmail  *string
		wantCursor bool
		wantLimit  int
		wantErr    bool
	}{
		"no cursor passes filters through":                {params: openapi.GetApiV2OrganizationsParams{Name: ptr.To("x"), Email: ptr.To("e")}, wantFilter: "x", wantEmail: ptr.To("e")},
		"no cursor normalises the name":                   {params: openapi.GetApiV2OrganizationsParams{Name: ptr.To("ACME")}, wantFilter: "acme"},
		"cursor alone restores both filters":              {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound}, wantFilter: "acme", wantEmail: ptr.To("a@example.com"), wantCursor: true},
		"equal name accepted":                             {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Name: ptr.To("acme")}, wantFilter: "acme", wantEmail: ptr.To("a@example.com"), wantCursor: true},
		"name differing in case only accepted":            {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Name: ptr.To("ACME")}, wantFilter: "acme", wantEmail: ptr.To("a@example.com"), wantCursor: true},
		"cursor filter case differing from name accepted": {params: openapi.GetApiV2OrganizationsParams{Cursor: &boundUpper, Name: ptr.To("acme")}, wantFilter: "acme", wantEmail: ptr.To("a@example.com"), wantCursor: true},
		"name too long rejected":                          {params: openapi.GetApiV2OrganizationsParams{Name: ptr.To(longName)}, wantErr: true},
		"name with invalid character rejected":            {params: openapi.GetApiV2OrganizationsParams{Name: ptr.To("a b")}, wantErr: true},
		"name that lowercases to a valid one rejected":    {params: openapi.GetApiV2OrganizationsParams{Name: ptr.To("\u212a")}, wantErr: true},
		"equal email accepted":                            {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Email: ptr.To("a@example.com")}, wantFilter: "acme", wantEmail: ptr.To("a@example.com"), wantCursor: true},
		"different name rejected":                         {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Name: ptr.To("other")}, wantErr: true},
		"different email rejected":                        {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Email: ptr.To("b@example.com")}, wantErr: true},
		"email differing in case only rejected":           {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Email: ptr.To("A@example.com")}, wantErr: true},
		"name present, cursor binds none":                 {params: openapi.GetApiV2OrganizationsParams{Cursor: &unbound, Name: ptr.To("acme")}, wantErr: true},
		"email present, cursor binds none":                {params: openapi.GetApiV2OrganizationsParams{Cursor: &unbound, Email: ptr.To("a@example.com")}, wantErr: true},
		"unbound cursor alone":                            {params: openapi.GetApiV2OrganizationsParams{Cursor: &unbound}, wantCursor: true},
		"malformed cursor rejected":                       {params: openapi.GetApiV2OrganizationsParams{Cursor: ptr.To("%%%")}, wantErr: true},
		"empty name, no cursor, no filter":                {params: openapi.GetApiV2OrganizationsParams{Name: ptr.To("")}},
		"empty email, no cursor, nil email":               {params: openapi.GetApiV2OrganizationsParams{Email: ptr.To("")}},
		"empty name restores bound filters":               {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Name: ptr.To("")}, wantFilter: "acme", wantEmail: ptr.To("a@example.com"), wantCursor: true},
		"empty email restores bound filters":              {params: openapi.GetApiV2OrganizationsParams{Cursor: &bound, Email: ptr.To("")}, wantFilter: "acme", wantEmail: ptr.To("a@example.com"), wantCursor: true},
		"email of 254 bytes accepted":                     {params: openapi.GetApiV2OrganizationsParams{Email: ptr.To(longEmail)}, wantEmail: ptr.To(longEmail)},
		"email of 255 bytes rejected":                     {params: openapi.GetApiV2OrganizationsParams{Email: ptr.To("a" + longEmail)}, wantErr: true},
		"absent limit uses configured value":              {wantLimit: 25},
		"absent limit uses zero-value default":            {options: &Options{}, wantLimit: defaultV2Limit},
		"explicit limit used":                             {params: openapi.GetApiV2OrganizationsParams{Limit: ptr.To(7)}, wantLimit: 7},
		"maximum limit accepted":                          {params: openapi.GetApiV2OrganizationsParams{Limit: ptr.To(maxListLimit)}, wantLimit: maxListLimit},
		"limit 0 rejected":                                {params: openapi.GetApiV2OrganizationsParams{Limit: ptr.To(0)}, wantErr: true},
		"limit 501 rejected":                              {params: openapi.GetApiV2OrganizationsParams{Limit: ptr.To(501)}, wantErr: true},
		"limit 764 rejected":                              {params: openapi.GetApiV2OrganizationsParams{Limit: ptr.To(764)}, wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			o := options
			if tc.options != nil {
				o = tc.options
			}

			wantLimit := tc.wantLimit
			if wantLimit == 0 {
				wantLimit = options.V2DefaultLimit
			}

			walk, err := o.ResolveWalk(tc.params)

			if tc.wantErr {
				require.Error(t, err)
				require.True(t, errors.IsBadRequest(err))

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantFilter, walk.Filter)
			require.Equal(t, tc.wantEmail, walk.Email)
			require.Equal(t, tc.wantCursor, walk.After != nil)
			require.Equal(t, wantLimit, walk.Limit)
		})
	}
}

// organizationIDs parses UUID strings into organization IDs.
func organizationIDs(t *testing.T, in ...string) *[]ids.OrganizationID {
	t.Helper()

	out := make([]ids.OrganizationID, len(in))

	for i := range in {
		id, err := uuid.Parse(in[i])
		require.NoError(t, err)

		out[i] = ids.OrganizationID(id)
	}

	return &out
}

func TestResolveWalkIDs(t *testing.T) {
	t.Parallel()

	const (
		idA = "0b8e1c6a-7f5e-4f2a-9d3c-1a2b3c4d5e6f"
		idB = "9f8e7d6c-5b4a-4321-8fed-cba987654321"
	)

	cursor := Cursor{ID: "id"}.Encode()
	options := &Options{}

	walk, err := options.ResolveWalk(openapi.GetApiV2OrganizationsParams{Id: organizationIDs(t, idB, idA, idB)})
	require.NoError(t, err)
	require.Equal(t, []string{idA, idB}, walk.IDs)
	require.Equal(t, 2, walk.Limit)
	require.Nil(t, walk.After)

	// The binder parses case-insensitively, so different spellings of one
	// ID collapse to one.
	walk, err = options.ResolveWalk(openapi.GetApiV2OrganizationsParams{Id: organizationIDs(t, idA, strings.ToUpper(idA))})
	require.NoError(t, err)
	require.Equal(t, []string{idA}, walk.IDs)
	require.Equal(t, 1, walk.Limit)

	walk, err = options.ResolveWalk(openapi.GetApiV2OrganizationsParams{Id: &[]ids.OrganizationID{}})
	require.NoError(t, err)
	require.Nil(t, walk.IDs)
	require.Equal(t, defaultV2Limit, walk.Limit)

	// An empty name or email counts as absent, so it does not conflict with id.
	walk, err = options.ResolveWalk(openapi.GetApiV2OrganizationsParams{Id: organizationIDs(t, idA), Name: ptr.To(""), Email: ptr.To("")})
	require.NoError(t, err)
	require.Equal(t, []string{idA}, walk.IDs)

	// Exactly maxIDs distinct IDs is the accepted upper bound: a
	// strictly-greater check (">=" for "too many") would reject this.
	atMax := make([]string, maxIDs)
	for i := range atMax {
		atMax[i] = uuid.NewString()
	}

	walk, err = options.ResolveWalk(openapi.GetApiV2OrganizationsParams{Id: organizationIDs(t, atMax...)})
	require.NoError(t, err)
	require.Len(t, walk.IDs, maxIDs)
	require.Equal(t, maxIDs, walk.Limit)

	tooMany := make([]string, maxIDs+1)
	for i := range tooMany {
		tooMany[i] = uuid.NewString()
	}

	rejected := map[string]openapi.GetApiV2OrganizationsParams{
		"with cursor":  {Id: organizationIDs(t, idA), Cursor: &cursor},
		"with limit":   {Id: organizationIDs(t, idA), Limit: ptr.To(1)},
		"with name":    {Id: organizationIDs(t, idA), Name: ptr.To("acme")},
		"with email":   {Id: organizationIDs(t, idA), Email: ptr.To("a@example.com")},
		"too many IDs": {Id: organizationIDs(t, tooMany...)},
	}

	for name, params := range rejected {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := options.ResolveWalk(params)
			require.Error(t, err)
			require.True(t, errors.IsBadRequest(err))
		})
	}
}
