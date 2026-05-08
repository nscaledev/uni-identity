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
	"fmt"
)

var (
	// ErrRouterDetectorRequired indicates NewRouter was called without a SourceDetector.
	ErrRouterDetectorRequired = errors.New("router: detector is required")

	// ErrRouterValidatorSourceUnknown indicates a TokenValidator declares SourceUnknown,
	// which is reserved for routing failures.
	ErrRouterValidatorSourceUnknown = errors.New("router: validator declares SourceUnknown")

	// ErrRouterDuplicateValidator indicates two validators declare the same Source.
	ErrRouterDuplicateValidator = errors.New("router: duplicate validator for source")
)

// Router selects a per-source TokenValidator using a SourceDetector and
// invokes it. The exchange endpoint should call Validate exactly once per
// request — there is no fallback between validators.
type Router struct {
	detector   *SourceDetector
	validators map[Source]TokenValidator
}

// NewRouter wires a Router from a detector and a set of validators. Validators
// are indexed by their declared Source(). A nil validator entry is silently
// dropped — useful when an operator has not configured Auth0 yet.
func NewRouter(detector *SourceDetector, validators ...TokenValidator) (*Router, error) {
	if detector == nil {
		return nil, ErrRouterDetectorRequired
	}

	indexed := make(map[Source]TokenValidator, len(validators))

	for _, v := range validators {
		if v == nil {
			continue
		}

		source := v.Source()
		if source == SourceUnknown {
			return nil, fmt.Errorf("%w: %T", ErrRouterValidatorSourceUnknown, v)
		}

		if _, dup := indexed[source]; dup {
			return nil, fmt.Errorf("%w: %q", ErrRouterDuplicateValidator, source)
		}

		indexed[source] = v
	}

	return &Router{detector: detector, validators: indexed}, nil
}

// Validate detects the token's source and delegates to the matching validator.
// Returns ErrUnsupportedSource when the issuer matches no configured source,
// or ErrMalformedToken when the token cannot be parsed at all.
func (r *Router) Validate(ctx context.Context, rawToken string) (*ValidatedIdentity, error) {
	source, err := r.detector.Detect(rawToken)
	if err != nil {
		return nil, err
	}

	if source == SourceUnknown {
		return nil, ErrUnsupportedSource
	}

	validator, ok := r.validators[source]
	if !ok {
		return nil, fmt.Errorf("%w: source %q has no validator", ErrUnsupportedSource, source)
	}

	return validator.Validate(ctx, rawToken)
}
