/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

//nolint:revive
package handler

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/handler/oauth2providers"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"
	"github.com/unikorn-cloud/identity/pkg/handler/quotas"
	"github.com/unikorn-cloud/identity/pkg/handler/roles"
	"github.com/unikorn-cloud/identity/pkg/handler/serviceaccounts"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// directclient gives uncached access to Kubernetes; this is needed
	// for e.g., allocations, where we need to have reads consistent with
	// writes.
	directclient client.Client

	// namespace is the namespace we are running in.
	namespace string

	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer

	// oauth2 is the oauth2 deletgating authenticator.
	oauth2 *oauth2.Authenticator

	// rbac gives access to low level rbac functionality.
	rbac *rbac.RBAC

	// options allows behaviour to be defined on the CLI.
	options *Options

	// allocationMutex serialises allocation decisions
	allocationMutex sync.Mutex
}

func New(client client.Client, directclient client.Client, namespace string, issuer *jose.JWTIssuer, oauth2 *oauth2.Authenticator, rbac *rbac.RBAC, options *Options) (*Handler, error) {
	h := &Handler{
		client:       client,
		directclient: directclient,
		namespace:    namespace,
		issuer:       issuer,
		oauth2:       oauth2,
		rbac:         rbac,
		options:      options,
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
		Issuer:                h.options.Issuer.URL,
		AuthorizationEndpoint: fmt.Sprintf("%s/oauth2/v2/authorization", h.options.Issuer.URL),
		TokenEndpoint:         fmt.Sprintf("%s/oauth2/v2/token", h.options.Issuer.URL),
		UserinfoEndpoint:      fmt.Sprintf("%s/oauth2/v2/userinfo", h.options.Issuer.URL),
		JwksUri:               fmt.Sprintf("%s/oauth2/v2/jwks", h.options.Issuer.URL),
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

func (h *Handler) GetWellKnownOpenidProtectedResource(w http.ResponseWriter, r *http.Request) {
	result := &coreapi.OpenidProtectedResource{
		Resource: "https://" + r.Host,
		AuthorizationServers: coreapi.AuthorizationServerList{
			"https://" + r.Host,
		},
		ScopesSupported: coreapi.ScopeList{
			"openapi",
			"email",
			"profile",
		},
		BearerMethodsSupported: coreapi.BearerMethodList{
			coreapi.Header,
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

func (h *Handler) PostOauth2V2Onboard(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Onboard(w, r)
}

func (h *Handler) PostOauth2V2Token(w http.ResponseWriter, r *http.Request) {
	result, err := h.oauth2.Token(w, r)
	if err != nil {
		oauth2errors.HandleError(w, r, err)
		return
	}

	// See OIDC 1.0 Section 3.1.3.3.
	h.setUncacheableNoStore(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if header == "" {
		errors.HandleError(w, r, errors.AccessDenied(r, "authorization header not set"))
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
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo)
}

func (h *Handler) PostOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	if header := r.Header.Get("Authorization"); header != "" {
		parts := strings.Split(header, " ")

		if len(parts) != 2 {
			errors.HandleError(w, r, errors.AccessDenied(r, "authorization header malformed"))
			return
		}

		if !strings.EqualFold(parts[0], "bearer") {
			errors.HandleError(w, r, errors.AccessDenied(r, "authorization scheme not allowed"))
			return
		}

		userinfo, _, err := h.oauth2.GetUserinfo(r.Context(), r, parts[1])
		if err != nil {
			errors.HandleError(w, r, err)
			return
		}

		h.setUncacheable(w)
		util.WriteJSONResponse(w, r, http.StatusOK, userinfo)

		return
	}

	if err := r.ParseForm(); err != nil {
		errors.HandleError(w, r, errors.AccessDenied(r, "unable to parse form data").WithError(err))
		return
	}

	userinfo, _, err := h.oauth2.GetUserinfo(r.Context(), r, r.Form.Get("access_token"))
	if err != nil {
		errors.HandleError(w, r, errors.AccessDenied(r, "access token is invalid").WithError(err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo)
}

func (h *Handler) GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request) {
	result, _, err := h.issuer.GetJSONWebKeySet(r.Context())
	if err != nil {
		errors.HandleError(w, r, fmt.Errorf("%w: unable to generate json web key set", err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOidcCallback(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Callback(w, r)
}

func (h *Handler) GetApiV1Oauth2providers(w http.ResponseWriter, r *http.Request) {
	result, err := oauth2providers.New(h.client, h.namespace).ListGlobal(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1Acl(w http.ResponseWriter, r *http.Request) {
	// The middleware will populate this from the URL, and thus not have access to any
	// scoping information, so just return anything at the global scope.
	// TODO: we may want to consider just returning everything across all organizations.
	result := rbac.FromContext(r.Context())

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAcl(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result := rbac.FromContext(r.Context())

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRoles(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:roles", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := roles.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDOauth2providers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := oauth2providers.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDOauth2providers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.Oauth2ProviderWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := oauth2providers.New(h.client, h.namespace).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDOauth2providersProviderID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, providerID openapi.Oauth2ProvderIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.Oauth2ProviderWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := oauth2providers.New(h.client, h.namespace).Update(r.Context(), organizationID, providerID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDOauth2providersProviderID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, providerID openapi.Oauth2ProvderIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := oauth2providers.New(h.client, h.namespace).Delete(r.Context(), organizationID, providerID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) GetApiV1Organizations(w http.ResponseWriter, r *http.Request, params openapi.GetApiV1OrganizationsParams) {
	result, err := organizations.New(h.client, h.namespace).List(r.Context(), h.rbac, params.Email)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1Organizations(w http.ResponseWriter, r *http.Request) {
	if err := rbac.AllowGlobalScope(r.Context(), "identity:organizations", openapi.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.OrganizationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := organizations.New(h.client, h.namespace).Create(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:organizations", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := organizations.New(h.client, h.namespace).Get(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:organizations", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.OrganizationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := organizations.New(h.client, h.namespace).Update(r.Context(), organizationID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowGlobalScope(r.Context(), "identity:organizations", openapi.Delete); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := organizations.New(h.client, h.namespace).Delete(r.Context(), organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := groups.New(h.client, h.namespace, h.options.Issuer).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.GroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := groups.New(h.client, h.namespace, h.options.Issuer).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := groups.New(h.client, h.namespace, h.options.Issuer).Get(r.Context(), organizationID, groupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := groups.New(h.client, h.namespace, h.options.Issuer).Delete(r.Context(), organizationID, groupID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.GroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := groups.New(h.client, h.namespace, h.options.Issuer).Update(r.Context(), organizationID, groupID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjects(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := projects.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	ctx := r.Context()

	// Apply RBAC after listing as a filter.
	result = slices.DeleteFunc(result, func(resource openapi.ProjectRead) bool {
		return rbac.AllowProjectScope(ctx, "identity:projects", openapi.Read, organizationID, resource.Metadata.Id) != nil
	})

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjects(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:projects", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ProjectWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := projects.New(h.client, h.namespace).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects", openapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := projects.New(h.client, h.namespace).Get(r.Context(), organizationID, projectID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects", openapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ProjectWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := projects.New(h.client, h.namespace).Update(r.Context(), organizationID, projectID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects", openapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := projects.New(h.client, h.namespace).Delete(r.Context(), organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReference(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, reference openapi.ReferenceParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects/references", openapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := projects.New(h.client, h.namespace).ReferenceCreate(r.Context(), organizationID, projectID, reference); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDReferencesReference(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, reference openapi.ReferenceParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects/references", openapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := projects.New(h.client, h.namespace).ReferenceDelete(r.Context(), organizationID, projectID, reference); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serviceAccountsClient() *serviceaccounts.Client {
	return serviceaccounts.New(h.client, h.namespace, h.options.Issuer, h.oauth2, &h.options.ServiceAccounts)
}

// allowServiceAccountOrSelfAccess allows either access to a service account via the usual RBAC
// interfaces, or allows the service account to access itself.  This allows for fully transparent
// rotation without any end user interaction, think Let's Encrypt's automatic certificate issuing.
func allowServiceAccountOrSelfAccess(ctx context.Context, operation openapi.AclOperation, organizationID, serviceAccountID string) error {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("%w: unable to get authorization info", err)
	}

	if info.ServiceAccount && (serviceAccountID == "" || info.Userinfo.Sub == serviceAccountID) {
		return nil
	}

	return rbac.AllowOrganizationScope(ctx, "identity:serviceaccounts", operation, organizationID)
}

// filterServiceAccounts is used when reading service accounts to only return the service account
// for a service accounts access token.
func filterServiceAccounts(ctx context.Context, organizationID string, serviceAccounts *openapi.ServiceAccounts) error {
	// If the actor has full access don't modify.
	if rbac.AllowOrganizationScope(ctx, "identity:serviceaccounts", openapi.Read, organizationID) == nil {
		return nil
	}

	// Otherwise it's a service account without full read privileges, so we allow it
	// to read itself in order to acquire its ID via introspection for rotation.
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("%w: unable to get authorization info", err)
	}

	if !info.ServiceAccount {
		return nil
	}

	*serviceAccounts = slices.DeleteFunc(*serviceAccounts, func(serviceAccount openapi.ServiceAccountRead) bool {
		return serviceAccount.Metadata.Id != info.Userinfo.Sub
	})

	return nil
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDServiceaccounts(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	// NOTE: this allows regular RBAC based access or a service account to self discover its ID.
	if err := allowServiceAccountOrSelfAccess(r.Context(), openapi.Read, organizationID, ""); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient().List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := filterServiceAccounts(r.Context(), organizationID, &result); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDServiceaccounts(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:serviceaccounts", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServiceAccountWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient().Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:serviceaccounts", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServiceAccountWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient().Update(r.Context(), organizationID, serviceAccountID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:serviceaccounts", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serviceAccountsClient().Delete(r.Context(), organizationID, serviceAccountID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountIDRotate(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	// NOTE: this allows regular RBAC based access or a service account to self rotate.
	if err := allowServiceAccountOrSelfAccess(r.Context(), openapi.Update, organizationID, serviceAccountID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient().Rotate(r.Context(), organizationID, serviceAccountID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) usersClient() *users.Client {
	return users.New(h.client, h.namespace, h.issuer, h.options.Issuer, &h.options.Users)
}

func (h *Handler) GetApiV1Signup(w http.ResponseWriter, r *http.Request) {
	h.usersClient().Signup(w, r)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDUsers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient().List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDUsers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.UserWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient().Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDUsersUserID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, userID openapi.UserIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.usersClient().Delete(r.Context(), organizationID, userID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDUsersUserID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, userID openapi.UserIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.UserWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient().Update(r.Context(), organizationID, userID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) quotasClient() *quotas.Client {
	return quotas.New(h.client, h.namespace)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:quotas", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.quotasClient().Get(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:quotas", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

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
