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

package passport

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type keyLookupService interface {
	GetKeyByID(ctx context.Context, keyID string) (*jose.JSONWebKey, *jose.JSONWebKey, error)
}

type localKeySource struct {
	service keyLookupService
}

var _ KeySource = (*localKeySource)(nil)

func NewLocalKeySource(service keyLookupService) KeySource {
	return &localKeySource{service: service}
}

func (s *localKeySource) Get(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	if s.service == nil {
		return nil, fmt.Errorf("%w: local key source not configured", ErrJWKSUnavailable)
	}

	pub, _, err := s.service.GetKeyByID(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: key lookup failed: %w", ErrJWKSUnavailable, err)
	}

	return pub, nil
}
