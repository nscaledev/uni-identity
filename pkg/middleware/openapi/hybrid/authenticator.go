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

package hybrid

import (
	"net/http"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/common"
)

// Authenticator routes between local and remote authentication based on token type.
type Authenticator struct {
	detector   *common.TokenDetector
	localAuth  openapi.Authenticator
	remoteAuth openapi.Authenticator
}

// NewAuthenticator creates a new hybrid authenticator.
func NewAuthenticator(localAuth, remoteAuth openapi.Authenticator) *Authenticator {
	return &Authenticator{
		detector:   &common.TokenDetector{},
		localAuth:  localAuth,
		remoteAuth: remoteAuth,
	}
}

// Authenticate validates a token using the appropriate authenticator based on token type.
func (h *Authenticator) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	tokenType := h.detector.DetectTokenIssuer(token)

	switch tokenType {
	case common.Local:
		// Local encrypted tokens (service accounts, X.509 certificates)
		return h.localAuth.Authenticate(r, token)

	case common.Remote:
		// External signed tokens (federated users)
		return h.remoteAuth.Authenticate(r, token)

	case common.Invalid:
		fallthrough
	default:
		return nil, errors.OAuth2InvalidRequest("unrecognized token")
	}
}
