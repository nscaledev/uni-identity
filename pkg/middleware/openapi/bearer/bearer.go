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

// Package bearer inspects the shape of a bearer token so a resource server can
// route it to the correct verification strategy: a UNI access token is a JWE,
// a third-party (Auth0) access token is a JWS. It is a leaf package with no
// dependency on the identity server internals, so the remote middleware can
// route tokens without importing the full oauth2 package.
package bearer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrUnrecognized is returned when a bearer token is neither a JWS nor a JWE —
// its JOSE header is absent, unparseable, or inconsistent with the
// compact-serialization segment count.
var ErrUnrecognized = errors.New("bearer token is neither a JWS nor a JWE")

// IsJWE reports whether token is a JWE (a UNI access token) rather than a JWS
// (a third-party access token) by inspecting the protected JOSE header: a JWE
// carries an "enc" content-encryption header, a JWS does not, and both carry
// "alg". JOSE header names are case-sensitive (RFC 7515 §4), and the header
// type is cross-checked against the segment count (JWS has 3 segments, JWE has
// 5) so a stray header member cannot misroute a token. It returns
// ErrUnrecognized when the token is neither, which callers treat as
// unroutable.
//
// Routing on the header rather than counting dots means an upstream switch to a
// non-JWS access token can no longer silently misroute every third-party token
// to the UNI path: a bearer that is neither a JWE nor a JWS is rejected
// outright, so a token-format change surfaces as an alertable signal instead of
// a scatter of generic 401s.
func IsJWE(token string) (bool, error) {
	header, _, ok := strings.Cut(token, ".")
	if !ok {
		return false, fmt.Errorf("%w: not a compact JOSE serialization", ErrUnrecognized)
	}

	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return false, fmt.Errorf("%w: undecodable header: %w", ErrUnrecognized, err)
	}

	// encoding/json matches keys case-insensitively, but JOSE header names are
	// case-sensitive, so decode to raw members and test exact keys.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return false, fmt.Errorf("%w: unparseable header: %w", ErrUnrecognized, err)
	}

	if _, ok := parsed["alg"]; !ok {
		return false, fmt.Errorf("%w: header has no alg", ErrUnrecognized)
	}

	_, isJWE := parsed["enc"]

	segments := strings.Count(token, ".") + 1

	switch {
	case isJWE && segments != 5:
		return false, fmt.Errorf("%w: JWE header with %d segments", ErrUnrecognized, segments)
	case !isJWE && segments != 3:
		return false, fmt.Errorf("%w: JWS header with %d segments", ErrUnrecognized, segments)
	}

	return isJWE, nil
}
