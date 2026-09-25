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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// cursorVersion is the wire format version carried in every cursor.
// Increment it when the JSON shape or the sort key changes.  DecodeCursor
// then rejects old cursors.
const cursorVersion = 1

// maxCursorLength is the longest cursor accepted.  The largest cursor the
// server issues fits.  It must equal the maxLength of
// components/parameters/organizationListCursorParameter in
// pkg/openapi/server.spec.yaml.
const maxCursorLength = 4096

// nameFilterPattern and maxNameFilterLength are the rule for a display name
// filter: label-value characters only.  They must equal the pattern and the
// maxLength of components/parameters/organizationListNameParameter in
// pkg/openapi/server.spec.yaml.  TestListParameterRulesMatchSpec enforces
// both constants.
const (
	nameFilterPattern   = `^[A-Za-z0-9._-]*$`
	maxNameFilterLength = 63
)

var nameFilterRegexp = regexp.MustCompile(nameFilterPattern)

// validFilter reports whether a display name filter obeys the name
// parameter's rule.  DecodeCursor and ResolveWalk share it, so a cursor's
// carried filter and the request's name are checked identically.
func validFilter(s string) bool {
	return len(s) <= maxNameFilterLength && nameFilterRegexp.MatchString(s)
}

// ErrInvalidCursor is returned when a cursor cannot be decoded.
var ErrInvalidCursor = errors.New("invalid cursor")

// Cursor is the opaque pagination token.  It binds the position (the sort
// key of the last item on the page) and the filters of the walk.  It carries
// no authority: RBAC runs on every page.
type Cursor struct {
	Version int    `json:"v"`
	Name    string `json:"name"`
	ID      string `json:"id"`
	Filter  string `json:"filter,omitempty"`
	Email   string `json:"email,omitempty"`
}

// Encode returns the base64url form of the cursor with the current format
// version.  It does not change the receiver.  It uses JSON rather than
// separators because "|" is legal inside an email local part.
func (c Cursor) Encode() string {
	c.Version = cursorVersion

	raw, err := json.Marshal(c)
	if err != nil {
		// Cursor holds only ints and strings, so marshalling cannot fail.
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeCursor parses a cursor.  An empty Name is valid because the display
// name label is optional.  An empty ID is not valid.  The carried filter must obey
// the same rule as the name parameter, and the carried email must not exceed
// maxEmailLength, because both skip request validation.
func DecodeCursor(s string) (*Cursor, error) {
	if len(s) > maxCursorLength {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrInvalidCursor, maxCursorLength)
	}

	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCursor, err)
	}

	cursor := &Cursor{}

	if err := json.Unmarshal(raw, cursor); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCursor, err)
	}

	if cursor.Version != cursorVersion || cursor.ID == "" {
		return nil, ErrInvalidCursor
	}

	if !validFilter(cursor.Filter) {
		return nil, fmt.Errorf("%w: invalid filter", ErrInvalidCursor)
	}

	if len(cursor.Email) > maxEmailLength {
		return nil, fmt.Errorf("%w: invalid email", ErrInvalidCursor)
	}

	return cursor, nil
}
