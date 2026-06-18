/*
Copyright 2025 the Unikorn Authors.
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

package authorization

import (
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// Info is the authenticated identity derived from a request's credentials. It is
// the principal (the actor's subject and account type) plus the raw access
// token. The principal is the single internal identity shape — the same type
// that is propagated to downstream services — and it carries identity only:
// organisation membership and RBAC are resolved later from the actor, never read
// from the token. A service account is identified by `Type == openapi.Service`
// (there is no separate flag); the X.509 system path sets `Type == openapi.System`.
type Info struct {
	*principal.Principal
	// Token is the raw access token, retained so the remote authorizer can
	// relay it as the bearer when calling the identity GetACL endpoint.
	Token string
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
