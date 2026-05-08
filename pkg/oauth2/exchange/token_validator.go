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

package exchange

import (
	"context"
	"errors"
)

// ErrUnsupportedSource is returned by the Router when an inbound token's
// issuer does not match any configured validator. The exchange endpoint must
// surface this as a 401-equivalent.
var ErrUnsupportedSource = errors.New("token source not supported")

// TokenValidator is the contract for per-source validation. Implementations
// are responsible for full verification (signature, claims, audience,
// expiry, scope, source-specific claims) and must normalize their result
// into a ValidatedIdentity before returning.
//
// Source returns the Source value the validator emits on success; it is used
// by the Router to wire validators by source without an explicit map entry.
type TokenValidator interface {
	Source() Source
	Validate(ctx context.Context, rawToken string) (*ValidatedIdentity, error)
}
