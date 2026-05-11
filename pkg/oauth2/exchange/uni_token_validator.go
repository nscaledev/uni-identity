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

	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// ErrUNIUserinfoNotAvailable is returned when the UNI validator can't reach
// the userinfo backend that resolves an access token to an identity.
var ErrUNIUserinfoNotAvailable = errors.New("uni userinfo not available")

// UNITokenIntrospector resolves a UNI access token into a Userinfo struct.
//
// This is intentionally a narrow contract that today's oauth2.Authenticator
// (via GetUserinfo) and tomorrow's phase-2 exchange handler can both satisfy
// without dragging the full Authenticator surface area into this package.
type UNITokenIntrospector interface {
	IntrospectUNIToken(ctx context.Context, rawToken string) (*UNIIdentity, error)
}

// UNIIdentity is the minimal projection of UNI userinfo the exchange path needs.
// The introspector implementation is responsible for performing the full token
// validation (signature, audience, expiry, session) before returning.
type UNIIdentity struct {
	Subject         string
	Email           string
	AccountType     identityapi.AuthClaimsAcctype
	OrganizationIDs []string
}

// UNITokenValidator adapts a UNITokenIntrospector into the exchange TokenValidator contract.
type UNITokenValidator struct {
	introspector UNITokenIntrospector
}

// NewUNITokenValidator wraps a UNITokenIntrospector as a TokenValidator.
func NewUNITokenValidator(introspector UNITokenIntrospector) *UNITokenValidator {
	return &UNITokenValidator{introspector: introspector}
}

var _ TokenValidator = (*UNITokenValidator)(nil)

// Source returns SourceUNI.
func (u *UNITokenValidator) Source() Source {
	return SourceUNI
}

// Validate introspects the token and lifts the result into ValidatedIdentity.
func (u *UNITokenValidator) Validate(ctx context.Context, rawToken string) (*ValidatedIdentity, error) {
	identity, err := u.introspector.IntrospectUNIToken(ctx, rawToken)
	if err != nil {
		return nil, err
	}

	return &ValidatedIdentity{
		Source:          SourceUNI,
		Subject:         identity.Subject,
		Email:           identity.Email,
		AccountType:     identity.AccountType,
		OrganizationIDs: identity.OrganizationIDs,
		Fallback:        false,
	}, nil
}
