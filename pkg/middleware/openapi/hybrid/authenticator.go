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

// HybridAuthenticator routes between local and remote authentication based on token type
type HybridAuthenticator struct {
	detector   *common.TokenDetector
	localAuth  openapi.Authenticator
	remoteAuth openapi.Authenticator
}

// NewHybridAuthenticator creates a new hybrid authenticator
func NewHybridAuthenticator(localAuth, remoteAuth openapi.Authenticator) *HybridAuthenticator {
	return &HybridAuthenticator{
		detector:   &common.TokenDetector{},
		localAuth:  localAuth,
		remoteAuth: remoteAuth,
	}
}

// Authenticate validates a token using the appropriate authenticator based on token type
func (h *HybridAuthenticator) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	tokenType := h.detector.DetectTokenType(token)

	switch tokenType {
	case common.TokenTypeLocalJWE:
		// Local encrypted tokens (service accounts, X.509 certificates)
		return h.localAuth.Authenticate(r, token)

	case common.TokenTypeJWT, common.TokenTypeExternalJWE, common.TokenTypeExternalOpaque:
		info, err := h.remoteAuth.Authenticate(r, token)
		if err != nil {
			return nil, err
		}
		if email := info.Userinfo.Email; email != nil {
			info.Userinfo.Sub = *email
		}
		return info, nil

	default:
		return nil, errors.OAuth2InvalidRequest("unrecognized token format")
	}
}
