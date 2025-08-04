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

package authorization

import (
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// Info contains all the information we can derive from an
// access token.
type Info struct {
	// Token is a copy of the access token made available to handlers.
	Token string
	// Actor is the identity of the user (email) or the service (X.509 CN)
	// used by RBAC to check permissions.
	Actor string
	// Principal is the user, or user we are acting on behalf of.
	Principal *principal.Principal
}

type keyType int

//nolint:gochecknoglobals
var key keyType

func NewContext(ctx context.Context, info *Info) context.Context {
	return context.WithValue(ctx, key, info)
}

func FromContext(ctx context.Context) (*Info, error) {
	if value := ctx.Value(key); value != nil {
		if info, ok := value.(*Info); ok {
			return info, nil
		}
	}

	return nil, fmt.Errorf("%w: authorization info is not defined", errors.ErrInvalidContext)
}
