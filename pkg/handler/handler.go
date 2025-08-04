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

//nolint:revive
package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/allocations"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/handler/oauth2providers"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"
	"github.com/unikorn-cloud/identity/pkg/handler/quotas"
	"github.com/unikorn-cloud/identity/pkg/handler/roles"
	"github.com/unikorn-cloud/identity/pkg/handler/serviceaccounts"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// namespace is the namespace we are running in.
	namespace string

	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer

	// oauth2 is the oauth2 deletgating authenticator.
	oauth2 *oauth2.Authenticator

	// rbac gives access to low level rbac functionality.
	rbac *rbac.RBAC

	pdp rbac.PolicyDecisionPoint

	// options allows behaviour to be defined on the CLI.
	options *Options
}

func New(client client.Client, namespace string, issuer *jose.JWTIssuer, oauth2 *oauth2.Authenticator, rbac *rbac.RBAC, pdp rbac.PolicyDecisionPoint, options *Options) (*Handler, error) {
	h := &Handler{
		client:    client,
		namespace: namespace,
		issuer:    issuer,
		oauth2:    oauth2,
		rbac:      rbac,
		pdp:       pdp,
		options:   options,
	}

	return h, nil
}

/*
func (h *Handler) setCacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d", h.options.CacheMaxAge/time.Second))
	w.Header().Add("Cache-Control", "private")
}
*/

func (h *Handler) setUncacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-cache")
}

func (h *Handler) setUncacheableNoStore(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-store")
}

func (h *Handler) GetWellKnownOpenidConfiguration(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) GetOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Authorization(w, r)
}

func (h *Handler) PostOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Authorization(w, r)
}

func (h *Handler) PostOauth2V2Login(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Login(w, r)
}

func (h *Handler) PostOauth2V2Token(w http.ResponseWriter, r *http.Request) {
	result, err := h.oauth2.Token(w, r)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// See OIDC 1.0 Section 3.1.3.3.
	h.setUncacheableNoStore(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
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

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo)
}

func (h *Handler) PostOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
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

		h.setUncacheable(w)
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

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo)
}

func (h *Handler) GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request) {
	result, _, err := h.issuer.GetJSONWebKeySet(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to generate json web key set").WithError(err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOidcCallback(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Callback(w, r)
}

func (h *Handler) oauth2ProvidersClient() *oauth2providers.Client {
	return oauth2providers.New(h.client, h.namespace, h.pdp)
}

func (h *Handler) GetApiV1Oauth2providers(w http.ResponseWriter, r *http.Request) {
	result, err := h.oauth2ProvidersClient().ListGlobal(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1Acl(w http.ResponseWriter, r *http.Request) {
	result, err := h.rbac.GetACL(r.Context(), "")
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

// TODO: Delete me.
func (h *Handler) GetApiV1OrganizationsOrganizationIDAcl(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.rbac.GetACL(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRoles(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := roles.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDOauth2providers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.oauth2ProvidersClient().List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDOauth2providers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	request := &openapi.Oauth2ProviderWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.oauth2ProvidersClient().Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDOauth2providersProviderID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, providerID openapi.Oauth2ProvderIDParameter) {
	request := &openapi.Oauth2ProviderWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.oauth2ProvidersClient().Update(r.Context(), organizationID, providerID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDOauth2providersProviderID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, providerID openapi.Oauth2ProvderIDParameter) {
	if err := h.oauth2ProvidersClient().Delete(r.Context(), organizationID, providerID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) organizationClient() *organizations.Client {
	return organizations.New(h.client, h.namespace, h.pdp)
}

func (h *Handler) GetApiV1Organizations(w http.ResponseWriter, r *http.Request, params openapi.GetApiV1OrganizationsParams) {
	result, err := h.organizationClient().List(r.Context(), params.Email)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1Organizations(w http.ResponseWriter, r *http.Request) {
	request := &openapi.OrganizationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.organizationClient().Create(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.organizationClient().Get(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	request := &openapi.OrganizationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.organizationClient().Update(r.Context(), organizationID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := h.organizationClient().Delete(r.Context(), organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) groupClient() *groups.Client {
	return groups.New(h.client, h.namespace, h.pdp)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.groupClient().List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	request := &openapi.GroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.groupClient().Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	result, err := h.groupClient().Get(r.Context(), organizationID, groupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := h.groupClient().Delete(r.Context(), organizationID, groupID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	request := &openapi.GroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.groupClient().Update(r.Context(), organizationID, groupID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) projectClient() *projects.Client {
	return projects.New(h.client, h.namespace, h.pdp)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjects(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.projectClient().List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjects(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	request := &openapi.ProjectWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.projectClient().Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	result, err := h.projectClient().Get(r.Context(), organizationID, projectID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	request := &openapi.ProjectWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.projectClient().Update(r.Context(), organizationID, projectID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := h.projectClient().Delete(r.Context(), organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) serviceAccountsClient(r *http.Request) *serviceaccounts.Client {
	return serviceaccounts.New(h.client, h.namespace, r.Host, h.oauth2, h.pdp, &h.options.ServiceAccounts)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDServiceaccounts(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	// TODO: a service account should be able to see itself.
	result, err := h.serviceAccountsClient(r).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDServiceaccounts(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	request := &openapi.ServiceAccountWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient(r).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	request := &openapi.ServiceAccountWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient(r).Update(r.Context(), organizationID, serviceAccountID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	if err := h.serviceAccountsClient(r).Delete(r.Context(), organizationID, serviceAccountID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountIDRotate(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	// TODO: a service account should be able to rotate itself.
	result, err := h.serviceAccountsClient(r).Rotate(r.Context(), organizationID, serviceAccountID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) usersClient(r *http.Request) *users.Client {
	return users.New(r.Host, h.client, h.namespace, h.issuer, h.pdp, &h.options.Users)
}

func (h *Handler) GetApiV1Signup(w http.ResponseWriter, r *http.Request) {
	h.usersClient(r).Signup(w, r)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDUsers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.usersClient(r).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDUsers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	request := &openapi.UserWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient(r).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDUsersUserID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, userID openapi.UserIDParameter) {
	if err := h.usersClient(r).Delete(r.Context(), organizationID, userID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDUsersUserID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, userID openapi.UserIDParameter) {
	request := &openapi.UserWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient(r).Update(r.Context(), organizationID, userID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) quotasClient() *quotas.Client {
	return quotas.New(h.client, h.namespace, h.pdp)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.quotasClient().Get(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	request := &openapi.QuotasWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.quotasClient().Update(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) allocationsClient() *allocations.Client {
	return allocations.New(h.client, h.namespace, h.pdp)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAllocations(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	result, err := h.allocationsClient().List(ctx, organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocations(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	request := &openapi.AllocationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsClient().Create(r.Context(), organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	if err := h.allocationsClient().Delete(r.Context(), organizationID, projectID, allocationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	result, err := h.allocationsClient().Get(r.Context(), organizationID, projectID, allocationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	request := &openapi.AllocationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsClient().Update(r.Context(), organizationID, projectID, allocationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
