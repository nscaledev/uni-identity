/*
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
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/utils/ptr"
)

// maxEmailLength is the longest email address RFC 5321 allows.  It also
// bounds the size of a cursor.
const maxEmailLength = 254

// maxIDs is the largest number of id parameters one request accepts.  It must
// equal the maxItems of components/parameters/organizationListIDParameter in
// pkg/openapi/server.spec.yaml.  TestListParameterRulesMatchSpec enforces that.
const maxIDs = 100

// Walk is one resolved page request of a v2 list walk.
type Walk struct {
	// Filter is the normalised display name filter, empty for none.
	Filter string

	// Email selects the organizations of this user, nil for the caller.
	Email *string

	// After is the position of the walk, nil for the first page.
	After *Cursor

	// Limit is the page size, from 1 to maxListLimit.
	Limit int

	// IDs selects organizations by ID, sorted and unique, nil for none.
	// A walk with IDs has no filters and no position.
	IDs []string
}

// ResolveWalk checks a v2 list request and resolves its page size, filters
// and position.  The first request of a walk binds its filters into the
// cursor.  A repeated equal value is accepted: the name without regard to
// case, the email exactly.  ResolveWalk rejects any other value, because it
// would change the walk mid-way.  Every error is a bad request.
func (o *Options) ResolveWalk(params openapi.GetApiV2OrganizationsParams) (*Walk, error) {
	if params.Id != nil && len(*params.Id) > 0 {
		return resolveIDs(params)
	}

	limit, err := o.resolveLimit(params.Limit)
	if err != nil {
		return nil, err
	}

	filter, email, err := resolveFilters(params)
	if err != nil {
		return nil, err
	}

	walk := &Walk{Filter: filter, Email: email, Limit: limit}

	if params.Cursor == nil {
		return walk, nil
	}

	if err := walk.resume(*params.Cursor); err != nil {
		return nil, err
	}

	return walk, nil
}

// resume continues the walk from an encoded cursor.  The filters of the walk
// must be empty or equal to the filters the cursor binds.
func (w *Walk) resume(encoded string) error {
	cursor, err := DecodeCursor(encoded)
	if err != nil {
		return errors.OAuth2InvalidRequest("invalid cursor").WithError(err)
	}

	if w.Filter != "" && w.Filter != normalizeFilter(cursor.Filter) {
		return errors.OAuth2InvalidRequest("name does not match cursor")
	}

	if w.Email != nil && *w.Email != cursor.Email {
		return errors.OAuth2InvalidRequest("email does not match cursor")
	}

	w.Filter = normalizeFilter(cursor.Filter)
	w.Email = emptyAsNil(&cursor.Email)
	w.After = cursor

	return nil
}

// resolveIDs resolves a lookup by ID.  It returns the IDs in canonical form,
// sorted and unique, with one page that holds all of them.  The request
// validator must not be the only check of the ID count.
func resolveIDs(params openapi.GetApiV2OrganizationsParams) (*Walk, error) {
	// An empty name or email counts as absent, as it does on a walk.
	if params.Cursor != nil || params.Limit != nil || emptyAsNil(params.Name) != nil || emptyAsNil(params.Email) != nil {
		return nil, errors.OAuth2InvalidRequest("id cannot be combined with other parameters")
	}

	if len(*params.Id) > maxIDs {
		return nil, errors.OAuth2InvalidRequest("too many id parameters")
	}

	ids := make([]string, len(*params.Id))

	for i, id := range *params.Id {
		ids[i] = id.String()
	}

	slices.Sort(ids)
	ids = slices.Compact(ids)

	return &Walk{IDs: ids, Limit: len(ids)}, nil
}

// resolveFilters checks the name and email parameters against their rules and
// returns the normalised name filter.  It checks the raw name, not the
// normalised one.  strings.ToLower maps some non-ASCII characters to ASCII,
// for example the Kelvin sign U+212A to "k".  The cursor omits empty values,
// so an empty parameter must count as absent.  Otherwise, an empty parameter
// bypasses the cursor binding checks in ResolveWalk.  The request validator
// must not be the only check.  It may not run, or may be misconfigured.  Also,
// these rules bound the size of the cursor this walk issues.
func resolveFilters(params openapi.GetApiV2OrganizationsParams) (string, *string, error) {
	name := ptr.Deref(params.Name, "")
	email := emptyAsNil(params.Email)

	if !validFilter(name) {
		return "", nil, errors.OAuth2InvalidRequest("name invalid")
	}

	if email != nil && len(*email) > maxEmailLength {
		return "", nil, errors.OAuth2InvalidRequest("email too long")
	}

	return normalizeFilter(name), email, nil
}

// resolveLimit returns the requested page size, or the configured one when
// the request omits it.  The request validator must not be the only check:
// it parses integers differently from the parameter binder.
func (o *Options) resolveLimit(limit *int) (int, error) {
	if limit == nil {
		return o.V2Limit(), nil
	}

	if *limit < 1 || *limit > maxListLimit {
		return 0, errors.OAuth2InvalidRequest("limit out of range")
	}

	return *limit, nil
}

// emptyAsNil returns nil for a nil or empty string.
func emptyAsNil(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}

	return s
}
