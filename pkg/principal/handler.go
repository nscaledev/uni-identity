/*
Copyright 2025 the Unikorn Authors.

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

package principal

import (
	"context"

	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
)

// GetPrincipal returns the principal in a HTTP handler.  This is primarily
// used to correctly scope things like images/flavors when a service is
// provisioning on behalf of a user in it's own namespace, and also used to
// correctly attribute resource allocations to the correct organization.
func GetPrincipal(ctx context.Context) (*Principal, error) {
	p, err := FromContext(ctx)
	if err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to extract principal from context: %w", err).
			Prefixed()

		return nil, err
	}

	return p, nil
}
