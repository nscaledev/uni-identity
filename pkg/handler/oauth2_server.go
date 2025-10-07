/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.

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

package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

type Oauth2Handler struct {
	// options allows behaviour to be defined on the CLI.
	options *Oauth2Options

	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer

	// oauth2 is the oauth2 deletgating authenticator.
	oauth2 *oauth2.Authenticator
}

func NewOauth2Handler(oauth2 *oauth2.Authenticator, issuer *jose.JWTIssuer, options *Oauth2Options) *Oauth2Handler {
	return &Oauth2Handler{
		options: options,
		issuer:  issuer,
		oauth2:  oauth2,
	}
}

func (h *Oauth2Handler) GetWellKnownOpenidConfiguration(w http.ResponseWriter, r *http.Request) {
	result := &openapi.OpenidConfiguration{
		Issuer:                h.options.Host,
		AuthorizationEndpoint: fmt.Sprintf("%s/oauth2/v2/authorization", h.options.Host),
		TokenEndpoint:         fmt.Sprintf("%s/oauth2/v2/token", h.options.Host),
		UserinfoEndpoint:      fmt.Sprintf("%s/oauth2/v2/userinfo", h.options.Host),
		JwksUri:               fmt.Sprintf("%s/oauth2/v2/jwks", h.options.Host),
		ScopesSupported: []openapi.Scope{
			openapi.ScopeEmail,
			openapi.ScopeOpenid,
			openapi.ScopeProfile,
		},
		ClaimsSupported: []openapi.Claim{
			openapi.ClaimAud,
			openapi.ClaimEmail,
			openapi.ClaimEmailVerified,
			openapi.ClaimExp,
			openapi.ClaimFamilyName,
			openapi.ClaimGivenName,
			openapi.ClaimIat,
			openapi.ClaimIss,
			openapi.ClaimLocale,
			openapi.ClaimName,
			openapi.ClaimPicture,
			openapi.ClaimSub,
		},
		ResponseTypesSupported: []openapi.ResponseType{
			openapi.ResponseTypeCode,
			openapi.ResponseTypeIdToken,
		},
		ResponseModesSupported: []openapi.ResponseMode{
			openapi.Query,
		},
		TokenEndpointAuthMethodsSupported: []openapi.AuthMethod{
			openapi.ClientSecretBasic,
			openapi.ClientSecretPost,
			openapi.TlsClientAuth,
		},
		GrantTypesSupported: []openapi.GrantType{
			openapi.AuthorizationCode,
			openapi.ClientCredentials,
			openapi.RefreshToken,
		},
		IdTokenSigningAlgValuesSupported: []openapi.SigningAlgorithm{
			openapi.ES512,
		},
		CodeChallengeMethodsSupported: []openapi.CodeChallengeMethod{
			openapi.Plain,
			openapi.S256,
		},
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Oauth2Handler) GetOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Authorization(w, r)
}

func (h *Oauth2Handler) PostOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Authorization(w, r)
}

func (h *Oauth2Handler) PostOauth2V2Login(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Login(w, r)
}

func (h *Oauth2Handler) PostOauth2V2Onboard(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Onboard(w, r)
}

func (h *Oauth2Handler) PostOauth2V2Token(w http.ResponseWriter, r *http.Request) {
	result, err := h.oauth2.Token(w, r)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// See OIDC 1.0 Section 3.1.3.3.
	setUncacheableNoStore(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Oauth2Handler) GetOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if header == "" {
		errors.HandleError(w, r, errors.OAuth2ServerError("authorization header not set"))
		return
	}

	parts := strings.Split(header, " ")

	if len(parts) != 2 {
		errors.HandleError(w, r, errors.OAuth2InvalidRequest("authorization header malformed"))
		return
	}

	if !strings.EqualFold(parts[0], "bearer") {
		errors.HandleError(w, r, errors.OAuth2InvalidRequest("authorization scheme not allowed"))
		return
	}

	userinfo, _, err := h.oauth2.GetUserinfo(r.Context(), r, parts[1])
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2AccessDenied("access token is invalid").WithError(err))
		return
	}

	setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo)
}

func (h *Oauth2Handler) PostOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	if header := r.Header.Get("Authorization"); header != "" {
		parts := strings.Split(header, " ")

		if len(parts) != 2 {
			errors.HandleError(w, r, errors.OAuth2InvalidRequest("authorization header malformed"))
			return
		}

		if !strings.EqualFold(parts[0], "bearer") {
			errors.HandleError(w, r, errors.OAuth2InvalidRequest("authorization scheme not allowed"))
			return
		}

		userinfo, _, err := h.oauth2.GetUserinfo(r.Context(), r, parts[1])
		if err != nil {
			errors.HandleError(w, r, errors.OAuth2AccessDenied("access token is invalid").WithError(err))
			return
		}

		setUncacheable(w)
		util.WriteJSONResponse(w, r, http.StatusOK, userinfo)

		return
	}

	if err := r.ParseForm(); err != nil {
		errors.HandleError(w, r, errors.OAuth2InvalidRequest("unable to parse form data").WithError(err))
		return
	}

	userinfo, _, err := h.oauth2.GetUserinfo(r.Context(), r, r.Form.Get("access_token"))
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2AccessDenied("access token is invalid").WithError(err))
		return
	}

	setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo)
}

func (h *Oauth2Handler) GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request) {
	result, _, err := h.issuer.GetJSONWebKeySet(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to generate json web key set").WithError(err))
		return
	}

	setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Oauth2Handler) GetOidcCallback(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Callback(w, r)
}
