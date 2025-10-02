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

package local

import (
	"net/http"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/util"
)

// Authenticator handles authentication for local JWE tokens.
type Authenticator struct {
	authenticator *oauth2.Authenticator
}

// NewAuthenticator creates a new local authenticator.
func NewAuthenticator(authenticator *oauth2.Authenticator) *Authenticator {
	return &Authenticator{
		authenticator: authenticator,
	}
}

// Authenticate validates a local JWE token and returns user information.
func (a *Authenticator) Authenticate(r *http.Request, token string) (*authorization.Info, error) {
	userinfo, claims, err := a.authenticator.GetUserinfo(r.Context(), r, token)
	if err != nil {
		return nil, err
	}

	info := &authorization.Info{
		Token:    token,
		Userinfo: userinfo,
	}

	// Set flags based on token type
	switch claims.Type {
	case oauth2.TokenTypeFederated:
		info.ClientID = claims.Federated.ClientID
	case oauth2.TokenTypeServiceAccount:
		info.ServiceAccount = true
	case oauth2.TokenTypeService:
		// All API requests will ultimately end up here as service call back
		// into the identity service to validate the token presented to the API.
		// If the token is bound to a certificate, we also expect the client
		// certificate to be presented by the first client in the chain and
		// propagated here.
		certPEM, err := authorization.ClientCertFromContext(r.Context())
		if err != nil {
			return nil, errors.OAuth2AccessDenied("client certificate not present for bound token").WithError(err)
		}

		certificate, err := util.GetClientCertificate(certPEM)
		if err != nil {
			return nil, errors.OAuth2AccessDenied("client certificate parse error").WithError(err)
		}

		thumbprint := util.GetClientCertifcateThumbprint(certificate)

		if thumbprint != claims.Service.X509Thumbprint {
			return nil, errors.OAuth2AccessDenied("client certificate mismatch for bound token")
		}

		info.SystemAccount = true
	}

	return info, nil
}
