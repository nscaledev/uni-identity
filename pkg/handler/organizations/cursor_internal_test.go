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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCursorRoundTrip(t *testing.T) {
	t.Parallel()

	in := Cursor{Name: "acme", ID: "a142f641-7fd6-4ab9-a875-344c7ebadc53", Filter: "ac", Email: "a|b@example.com"}

	out, err := DecodeCursor(in.Encode())
	require.NoError(t, err)

	want := in
	want.Version = cursorVersion

	require.Equal(t, &want, out)
}

func TestCursorEncodeOmitsEmptyFilters(t *testing.T) {
	t.Parallel()

	raw, err := base64.RawURLEncoding.DecodeString(Cursor{ID: "id"}.Encode())
	require.NoError(t, err)
	require.JSONEq(t, `{"v":1,"name":"","id":"id"}`, string(raw))
}

func TestDecodeCursorRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	encode := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

	for name, input := range map[string]string{
		"bad base64":    "%%%",
		"invalid json":  encode(`{"v":`),
		"wrong version": encode(`{"v":2,"name":"a","id":"b"}`),
		"empty id":      encode(`{"v":1,"name":"a","id":""}`),
		"too long":      strings.Repeat("A", maxCursorLength+1),
		"long filter":   Cursor{ID: "b", Filter: strings.Repeat("a", maxNameFilterLength+1)}.Encode(),
		"kelvin filter": Cursor{ID: "b", Filter: "\u212a"}.Encode(),
		"long email":    Cursor{ID: "b", Email: strings.Repeat("a", maxEmailLength+1)}.Encode(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeCursor(input)
			require.ErrorIs(t, err, ErrInvalidCursor)
		})
	}
}

func TestDecodeCursorAcceptsEmptyName(t *testing.T) {
	t.Parallel()

	cursor, err := DecodeCursor(base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"name":"","id":"b"}`)))
	require.NoError(t, err)
	require.Equal(t, "b", cursor.ID)
}

func TestLargestCursorFitsMaxLength(t *testing.T) {
	t.Parallel()

	// Each control character JSON-escapes to six bytes.
	cursor := Cursor{
		Name:   strings.Repeat("a", 63),
		ID:     strings.Repeat("a", 253),
		Filter: strings.Repeat("a", maxNameFilterLength),
		Email:  strings.Repeat("\x01", maxEmailLength),
	}

	encoded := cursor.Encode()
	require.LessOrEqual(t, len(encoded), maxCursorLength)

	_, err := DecodeCursor(encoded)
	require.NoError(t, err)
}
