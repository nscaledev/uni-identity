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

	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// auth0Verifier is the slice of auth0.Verifier the Auth0 validator depends on.
// Mocked directly in tests.
type auth0Verifier interface {
	Verify(ctx context.Context, rawToken string) (*auth0.Claims, error)
}

// Auth0TokenValidator adapts an auth0.Verifier into the exchange TokenValidator
// contract by lifting its claim shape into ValidatedIdentity.
type Auth0TokenValidator struct {
	verifier auth0Verifier
}

// NewAuth0TokenValidator wraps an auth0.Verifier as a TokenValidator.
func NewAuth0TokenValidator(verifier *auth0.Verifier) *Auth0TokenValidator {
	return &Auth0TokenValidator{verifier: verifier}
}

var _ TokenValidator = (*Auth0TokenValidator)(nil)

// Source returns SourceAuth0.
func (a *Auth0TokenValidator) Source() Source {
	return SourceAuth0
}

// Validate runs the Auth0 verifier and normalizes its claim set into the
// source-agnostic ValidatedIdentity.
func (a *Auth0TokenValidator) Validate(ctx context.Context, rawToken string) (*ValidatedIdentity, error) {
	claims, err := a.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	identity := &ValidatedIdentity{
		Source:      a.Source(),
		Subject:     claims.Subject,
		Email:       claims.Email,
		AccountType: identityapi.User,
	}

	return identity, nil
}
