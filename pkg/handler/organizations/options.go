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

// defaultV1ListLimit is the built-in default for V1ListLimit. Zero means
// unlimited.
const defaultV1ListLimit = 0

// ErrInvalidOptions is returned when a list option is out of range.
var ErrInvalidOptions = errors.New("invalid organization list options")

// Options configures organization listing.
type Options struct {
	// V1ListLimit caps the v1 list response.  Zero means the built-in
	// default (unlimited).
	V1ListLimit int
}

// AddFlags registers the list flags.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.IntVar(&o.V1ListLimit, "v1-organization-list-limit", defaultV1ListLimit, "Maximum organizations returned by GET /api/v1/organizations, 0 for unlimited (default 0).")
}

// Validate rejects values the API contract cannot serve.
func (o *Options) Validate() error {
	if o.V1ListLimit < 0 {
		return fmt.Errorf("%w: v1-organization-list-limit must be 0 or greater", ErrInvalidOptions)
	}

	return nil
}
