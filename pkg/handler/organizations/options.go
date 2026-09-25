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
	"errors"
	"fmt"

	"github.com/spf13/pflag"
)

// maxListLimit is the largest page GET /api/v2/organizations serves.  It must
// equal the maximum of components/parameters/organizationListLimitParameter in
// pkg/openapi/server.spec.yaml.  TestMaxListLimitMatchesSpec enforces that.
const maxListLimit = 500

// defaultV1ListLimit is the built-in default for V1ListLimit. Zero means
// unlimited.
const defaultV1ListLimit = 0

// defaultV2Limit is the built-in default for V2DefaultLimit, and the page
// size V2Limit returns when V2DefaultLimit is zero.
const defaultV2Limit = 50

// ErrInvalidOptions is returned when a list option is out of range.
var ErrInvalidOptions = errors.New("invalid organization list options")

// Options configures organization listing.
type Options struct {
	// V1ListLimit caps the deprecated v1 list response.  Zero means the
	// built-in default (unlimited).
	V1ListLimit int

	// V2DefaultLimit is the page size applied when a v2 caller omits limit.
	// Zero means the built-in default.  Read it through V2Limit.
	V2DefaultLimit int
}

// AddFlags registers the list flags.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.IntVar(&o.V1ListLimit, "v1-organization-list-limit", defaultV1ListLimit, "Maximum organizations returned by GET /api/v1/organizations, 0 for unlimited (default 0).")
	f.IntVar(&o.V2DefaultLimit, "v2-organization-list-default-limit", defaultV2Limit, "Page size for GET /api/v2/organizations when the caller omits limit, 1-500, or 0 for the built-in default.")
}

// Validate rejects values the API contract cannot serve.
func (o *Options) Validate() error {
	if o.V1ListLimit < 0 {
		return fmt.Errorf("%w: v1-organization-list-limit must be 0 or greater", ErrInvalidOptions)
	}

	if o.V2DefaultLimit < 0 || o.V2DefaultLimit > maxListLimit {
		return fmt.Errorf("%w: v2-organization-list-default-limit must be between 0 and %d", ErrInvalidOptions, maxListLimit)
	}

	return nil
}

// V2Limit returns the page size for GET /api/v2/organizations: V2DefaultLimit,
// or the built-in default when V2DefaultLimit is zero.
func (o *Options) V2Limit() int {
	if o.V2DefaultLimit == 0 {
		return defaultV2Limit
	}

	return o.V2DefaultLimit
}
