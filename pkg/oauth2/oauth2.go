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

package oauth2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	"github.com/unikorn-cloud/core/pkg/util/retry"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/html"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers"
	"github.com/unikorn-cloud/identity/pkg/oauth2/types"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/util"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const SessionCookie = "unikorn-identity-session"

var (
	ErrUnsupportedProviderType = goerrors.New("unhandled provider type")
	ErrReference               = goerrors.New("resource reference error")
	ErrUserNotDomainMapped     = goerrors.New("user is not domain mapped to an organization")
	ErrUserNotFound            = goerrors.New("user not found")
)

type Options struct {
	// AccessTokenDuration should be short to prevent long term use.
	AccessTokenDuration time.Duration

	// RefreshTokenDuration should be driven by the signing key rotation
	// period.
	RefreshTokenDuration time.Duration

	// TokenVerificationLeeway tells us how permissive we should or shouldn't
	// be of timing.
	TokenVerificationLeeway time.Duration

	// TokenLeewayDuration allows us to remove a period from the IdP access token
	// lifetime so we can "guarantee" ours will expire before theirs and force
	// a refresh before any errors can come from the IdP.
	TokenLeewayDuration time.Duration

	// TokenCacheSize is used to control the size of the LRU cache for token validation
	// checks.  This bounds the memory use to prevent DoS attacks.
	TokenCacheSize int

	// CodeCacheSize is used to set the number of authorization code in flight.
	CodeCacheSize int

	// AccountCreationCacheSize is used to set the number of account creation tokens
	// in flight.
	AccountCreationCacheSize int

	// AccountCreationEnabled is used to permit new account creation.
	AccountCreationEnabled bool

	// AccountCreationDefaultRoles is used to provide default roles for a new user.
	AccountCreationDefaultRoles []string

	// AccountCreationWebhookURI is used to notify an external service of an organization/user
	// creation event.
	AccountCreationWebhookURI string

	// AccountCreationWebhookToken is used in conjunction with the URI for authentication.
	// Must be used over TLS or it's useless.
	AccountCreationWebhookToken string
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.AccessTokenDuration, "access-token-duration", time.Hour, "Maximum time an access token can be active for.")
	f.DurationVar(&o.RefreshTokenDuration, "refresh-token-duration", 0, "Maximum time a refresh token can be active for.")
	f.DurationVar(&o.TokenVerificationLeeway, "token-verification-leeway", 0, "How mush leeway to permit for verification of token validity.")
	f.DurationVar(&o.TokenLeewayDuration, "token-leeway", time.Minute, "How long to remove from the provider token expiry to account for network and processing latency.")
	f.IntVar(&o.TokenCacheSize, "token-cache-size", 8192, "How many token cache entries to allow.")
	f.IntVar(&o.CodeCacheSize, "code-cache-size", 8192, "How many code cache entries to allow.")
	f.IntVar(&o.AccountCreationCacheSize, "account-creation-cache-size", 8192, "How many account creation cache entries to allow.")
	f.BoolVar(&o.AccountCreationEnabled, "account-creation-enabled", false, "Whether to allow accounts to be created.")
	f.StringSliceVar(&o.AccountCreationDefaultRoles, "account-creation-default-roles", []string{"administrator"}, "Default role names to grant a account creators user.")
	f.StringVar(&o.AccountCreationWebhookURI, "account-creation-webhook-uri", "", "URI to post user signup data.")
	f.StringVar(&o.AccountCreationWebhookToken, "account-creation-webhook-token", "", "Bearer token for authenticating singup data.")
}

// Authenticator provides Keystone authentication functionality.
type Authenticator struct {
	options *Options

	namespace string

	client client.Client

	// commonOptions contains shared handler configuration (issuer, hostname, etc.).
	issuer common.IssuerValue

	// jwtIssuer allows creation and validation of JWT bearer tokens.
	jwtIssuer *jose.JWTIssuer

	rbac *rbac.RBAC

	// tokenCache is used to enhance interaction as the validation is a
	// very expensive operation.
	tokenCache *cache.LRUExpireCache

	// codeCache is used to protect against authorization code reuse.
	codeCache *cache.LRUExpireCache

	// accountCreationCache is used to ensure an account creation token
	// can only be used once.
	accountCreationCache *cache.LRUExpireCache
}

// New returns a new authenticator with required fields populated.
// You must call AddFlags after this.
func New(options *Options, namespace string, issuer common.IssuerValue, client client.Client, jwtIssuer *jose.JWTIssuer, rbac *rbac.RBAC) *Authenticator {
	return &Authenticator{
		options:              options,
		namespace:            namespace,
		client:               client,
		issuer:               issuer,
		jwtIssuer:            jwtIssuer,
		rbac:                 rbac,
		tokenCache:           cache.NewLRUExpireCache(options.TokenCacheSize),
		codeCache:            cache.NewLRUExpireCache(options.CodeCacheSize),
		accountCreationCache: cache.NewLRUExpireCache(options.AccountCreationCacheSize),
	}
}

type Error string

const (
	ErrorInvalidRequest           Error = "invalid_request"
	ErrorUnauthorizedClient       Error = "unauthorized_client"
	ErrorAccessDenied             Error = "access_denied"
	ErrorUnsupportedResponseType  Error = "unsupported_response_type"
	ErrorInvalidScope             Error = "invalid_scope"
	ErrorServerError              Error = "server_error"
	ErrorLoginRequired            Error = "login_required"
	ErrorRequestNotSupported      Error = "request_not_supported"
	ErrorRequestURINotSupported   Error = "request_uri_not_supported"
	ErrorInteractionRequired      Error = "interaction_required"
	ErrorRegistrationNotSupported Error = "registration_not_supported"
)

// State records state across the call to the authorization server.
// This must be encrypted with JWE.
type State struct {
	// Nonce is the one time nonce used to create the token.
	Nonce string `json:"n"`
	// Code verifier is required to prove our identity when
	// exchanging the code with the token endpoint.
	CodeVerifier string `json:"cv"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
	// ClientQuery stores the full client query string.
	ClientQuery string `json:"cq"`
}

// OnboardingState propagates information across an onboarding dialog.
type OnboardingState struct {
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
	// ClientQuery stores the full client query string.
	ClientQuery string `json:"cq"`
	// IDToken is the full set of claims returned by the provider.
	IDToken *oidc.IDToken `json:"idt"`
}

// Code is an authorization code to return to the client that can be
// exchanged for an access token.  Much like how we client things in the oauth2
// state during the OIDC exchange, to mitigate problems with horizonal scaling
// and sharing stuff, we do the same here.
type Code struct {
	// ID is a unique identifier for the code.
	ID string `json:"id"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
	// UserID is the user that issued the code.
	UserID string `json:"uid"`
	// ClientQuery stores the full client query string.
	ClientQuery string `json:"cq"`
	// IDToken is the full set of claims returned by the provider.
	IDToken *oidc.IDToken `json:"idt"`
	// Interactive declares whether this is an interactive login
	// or not (e.g. cookie based).
	Interactive bool `json:"int"`
}

// htmlError is used in dire situations when we cannot return an error via
// the usual oauth2 flow.
//
//nolint:unparam
func htmlError(w http.ResponseWriter, r *http.Request, status int, description string) {
	log := log.FromContext(r.Context())

	body, err := html.Error("oauth2 error", description)
	if err != nil {
		log.Info("oauth2: failed to generate error page", "error", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)

	if _, err := w.Write(body); err != nil {
		log.Info("oauth2: failed to write HTML response")
	}
}

// redirector wraps up error redirects.
type redirector struct {
	w           http.ResponseWriter
	r           *http.Request
	redirectURI string
	state       string
}

func newRedirector(w http.ResponseWriter, r *http.Request, redirectURI, state string) *redirector {
	return &redirector{
		w:           w,
		r:           r,
		redirectURI: redirectURI,
		state:       state,
	}
}

func (e *redirector) redirect(values url.Values) {
	http.Redirect(e.w, e.r, e.redirectURI+"?"+values.Encode(), http.StatusFound)
}

// raise redirects to the client's callback URI with an error
// code in the query.
func (e *redirector) raise(kind Error, description string) {
	values := url.Values{}
	values.Set("error", string(kind))
	values.Set("error_description", description)

	if e.state != "" {
		values.Set("state", e.state)
	}

	e.redirect(values)
}

// lookupClient returns the oauth2 client given its ID.
func (a *Authenticator) lookupClient(ctx context.Context, id string) (*unikornv1.OAuth2Client, error) {
	key := client.ObjectKey{
		Namespace: a.namespace,
		Name:      id,
	}

	var oauth2Client unikornv1.OAuth2Client
	if err := a.client.Get(ctx, key, &oauth2Client); err != nil {
		return nil, err
	}

	return &oauth2Client, nil
}

// lookupOrganization maps from an email address to an organization, this handles
// corporate mandates that say your entire domain have to use a single sign on
// provider across the entire enterprise.
func (a *Authenticator) lookupOrganization(ctx context.Context, email string) (*unikornv1.Organization, error) {
	// TODO: error checking.
	parts := strings.Split(email, "@")

	// TODO: error checking.
	domain := parts[1]

	opts := []client.ListOption{
		&client.ListOptions{Namespace: a.namespace},
	}

	var list unikornv1.OrganizationList
	if err := a.client.List(ctx, &list, opts...); err != nil {
		return nil, err
	}

	for _, organization := range list.Items {
		if organization.Spec.Domain != nil && *organization.Spec.Domain == domain {
			return &organization, nil
		}
	}

	return nil, ErrUserNotDomainMapped
}

// getProviders lists all identity providers.
func (a *Authenticator) getProviders(ctx context.Context) (*unikornv1.OAuth2ProviderList, error) {
	opts := []client.ListOption{
		&client.ListOptions{Namespace: a.namespace},
	}

	var list unikornv1.OAuth2ProviderList
	if err := a.client.List(ctx, &list, opts...); err != nil {
		return nil, err
	}

	return &list, nil
}

func (a *Authenticator) getProviderTypes(ctx context.Context) ([]string, error) {
	resources, err := a.getProviders(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(resources.Items))

	for _, resource := range resources.Items {
		if resource.Spec.Type != nil && *resource.Spec.Type != "" {
			result = append(result, string(*resource.Spec.Type))
		}
	}

	return result, nil
}

// lookupProviderByType finds the provider configuration by the type chosen by the user.
func (a *Authenticator) lookupProviderByType(ctx context.Context, t unikornv1.IdentityProviderType) (*unikornv1.OAuth2Provider, error) {
	resources, err := a.getProviders(ctx)
	if err != nil {
		return nil, err
	}

	for i := range resources.Items {
		if resources.Items[i].Spec.Type != nil && *resources.Items[i].Spec.Type == t {
			return &resources.Items[i], nil
		}
	}

	return nil, ErrUnsupportedProviderType
}

// lookupProviderByID finds the provider based on ID.
func (a *Authenticator) lookupProviderByID(ctx context.Context, id string, organization *unikornv1.Organization) (*unikornv1.OAuth2Provider, error) {
	var list unikornv1.OAuth2ProviderList
	if err := a.client.List(ctx, &list); err != nil {
		return nil, err
	}

	isTargetOAuth2Provider := func(provider unikornv1.OAuth2Provider) bool {
		return provider.Name == id
	}

	index := slices.IndexFunc(list.Items, isTargetOAuth2Provider)
	if index < 0 {
		return nil, fmt.Errorf("%w: requested provider does not exist", ErrReference)
	}

	provider := &list.Items[index]

	// If the provider is neither global, nor scoped to the provided organization, reject.
	// NOTE: when called by the authorization endpoint and an email is provided, that email
	// maps to an organization, and the provider must be in that organization to avoid
	// jailbreaking.  In later provider authorization and token exchanges we can trust the
	// ID as it's already been checked, and it has been cryptographically protected against
	// tampering.
	if provider.Namespace != a.namespace && (organization == nil || provider.Namespace != organization.Status.Namespace) {
		return nil, fmt.Errorf("%w: requested provider not allowed", ErrReference)
	}

	return provider, nil
}

// authorizationValidateNonRedirecting checks authorization request parameters
// are valid that directly control the ability to redirect, and returns some helpful
// debug in HTML.
func (a *Authenticator) authorizationValidateNonRedirecting(w http.ResponseWriter, r *http.Request, query url.Values) (*unikornv1.OAuth2Client, bool) {
	if !query.Has("client_id") {
		htmlError(w, r, http.StatusBadRequest, "client_id is not specified")
		return nil, false
	}

	if !query.Has("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is not specified")
		return nil, false
	}

	client, err := a.lookupClient(r.Context(), query.Get("client_id"))
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "client_id does not exist")
		return nil, false
	}

	if client.Spec.RedirectURI != query.Get("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is invalid")
		return nil, false
	}

	return client, true
}

// getCodeChallengeMethod handles defaulting when a code challenge is provided.
func getCodeChallengeMethod(query url.Values) openapi.CodeChallengeMethod {
	if query.Has("code_challenge_method") {
		return openapi.CodeChallengeMethod(query.Get("code_challenge_method"))
	}

	return openapi.Plain
}

var (
	//nolint:gochecknoglobals
	allowedResponseTypes = []string{
		string(openapi.ResponseTypeCode),
	}

	//nolint:gochecknoglobals
	allowedResponseModes = []string{
		string(openapi.Query),
	}

	//nolint:gochecknoglobals
	allowedCodeChallengeMethods = []string{
		string(openapi.Plain),
		string(openapi.S256),
	}
)

// authorizationValidateRedirecting checks autohorization request parameters after
// the redirect URI has been validated.  If any of these fail, we redirect but with an
// error query rather than a code for the client to pick up and run with.
func authorizationValidateRedirecting(redirector *redirector, query url.Values) bool {
	if query.Has("request") {
		redirector.raise(ErrorRequestNotSupported, "request object by value not supported")
		return false
	}

	if query.Has("request_uri") {
		redirector.raise(ErrorRequestURINotSupported, "request object by URI not supported")
		return false
	}

	if query.Has("registration") {
		redirector.raise(ErrorRegistrationNotSupported, "registration not supported")
		return false
	}

	if !slices.Contains(allowedResponseTypes, query.Get("response_type")) {
		redirector.raise(ErrorUnsupportedResponseType, "response_type must be one of "+strings.Join(allowedResponseTypes, ", "))
		return false
	}

	if query.Has("response_mode") && !slices.Contains(allowedResponseModes, query.Get("response_mode")) {
		redirector.raise(ErrorRequestNotSupported, "response_mode must be one of "+strings.Join(allowedResponseModes, ", "))
		return false
	}

	if !slices.Contains(allowedCodeChallengeMethods, string(getCodeChallengeMethod(query))) {
		redirector.raise(ErrorInvalidRequest, "code_challenge_method must be one of "+strings.Join(allowedCodeChallengeMethods, ", "))
		return false
	}

	return true
}

// randomString creates size bytes of high entropy randomness and base64 URL
// encodes it into a string.  Bear in mind base64 expands the size by 33%, so for example
// an oauth2 code verifier needs to be at least 43 bytes, so you'd need a size of 32,
// 32 * 1.33 = 42.66.
func randomString(size int) (string, error) {
	buf := make([]byte, size)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// LoginStateClaims are used to encrypt information across the login dialog.
type LoginStateClaims struct {
	Query string `json:"query"`
}

func (a *Authenticator) getUser(ctx context.Context, id string) (*unikornv1.User, error) {
	key := client.ObjectKey{
		Namespace: a.namespace,
		Name:      id,
	}

	var user unikornv1.User
	if err := a.client.Get(ctx, key, &user); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, ErrUserNotFound
		}

		return nil, err
	}

	return &user, nil
}

//nolint:cyclop
func (a *Authenticator) authorizationSilent(r *http.Request, redirector *redirector, query url.Values) bool {
	if !query.Has("max_age") && query.Get("prompt") != "none" {
		return false
	}

	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		return false
	}

	var code Code
	if err := a.jwtIssuer.DecodeJWEToken(r.Context(), cookie.Value, &code, jose.TokenTypeAuthorizationCode); err != nil {
		return false
	}

	clientQuery, err := url.ParseQuery(code.ClientQuery)
	if err != nil {
		return false
	}

	if clientQuery.Get("client_id") != query.Get("client_id") {
		return false
	}

	if clientQuery.Get("redirect_uri") != query.Get("redirect_uri") {
		return false
	}

	user, err := a.getUser(r.Context(), code.UserID)
	if err != nil {
		return false
	}

	session, err := user.Session(query.Get("client_id"))
	if err != nil {
		return false
	}

	if query.Has("max_age") {
		maxAge, err := strconv.Atoi(query.Get("max_age"))
		if err != nil {
			return false
		}

		if maxAge == 0 {
			return false
		}

		if session.LastAuthentication == nil {
			return false
		}

		if session.LastAuthentication.Add(time.Duration(maxAge) * time.Second).Before(time.Now()) {
			return false
		}
	}

	// Skip the nonsense!
	oauth2Code := &Code{
		ID:             uuid.New().String(),
		UserID:         user.Name,
		ClientQuery:    query.Encode(),
		OAuth2Provider: code.OAuth2Provider,
		IDToken:        code.IDToken,
	}

	newCode, err := a.jwtIssuer.EncodeJWEToken(r.Context(), oauth2Code, jose.TokenTypeAuthorizationCode)
	if err != nil {
		return false
	}

	q := make(url.Values)
	q.Set("code", newCode)

	if query.Has("state") {
		q.Set("state", query.Get("state"))
	}

	a.codeCache.Add(newCode, nil, time.Minute)

	redirector.redirect(q)

	return true
}

func getAuthorizationQuery(r *http.Request) (url.Values, error) {
	if r.Method == http.MethodGet {
		return r.URL.Query(), nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return r.Form, nil
}

// Authorization redirects the client to the OIDC autorization endpoint
// to get an authorization code.  Note that this function is responsible for
// either returning an authorization grant or error via a HTTP 302 redirect,
// or returning a HTML fragment for errors that cannot follow the provided
// redirect URI.
//
//nolint:cyclop
func (a *Authenticator) Authorization(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	// Extract the client supplied parameters.
	query, err := getAuthorizationQuery(r)
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "failed to get authorization query")
		return
	}

	// Get the client corresponding to the request, if this errors then we cannot
	// trust the redirect URI and must render an error page.
	client, ok := a.authorizationValidateNonRedirecting(w, r, query)
	if !ok {
		return
	}

	redirector := newRedirector(w, r, client.Spec.RedirectURI, query.Get("state"))

	// Validate the other request parameters based on what we support, on error this
	// returns control back to the client via the redirect.
	if !authorizationValidateRedirecting(redirector, query) {
		return
	}

	// If 'max_age' is set and not zero, or 'prompt=none', then we may be able to silently
	// authenticate the user with a browser cookie, instantly returning an authorization
	// code to the client.
	if a.authorizationSilent(r, redirector, query) {
		return
	}

	// If that wasn't able to be handled and prompt=none, then we need to return an
	// interaction_required error.
	if query.Get("prompt") == "none" {
		redirector.raise(ErrorInteractionRequired, "login required but no prompt requested")
		return
	}

	// Encrypt the query across the login dialog to prevent tampering.
	stateClaims := &LoginStateClaims{
		Query: query.Encode(),
	}

	state, err := a.jwtIssuer.EncodeJWEToken(r.Context(), stateClaims, jose.TokenTypeLoginDialogState)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to encode request state")
		return
	}

	supportedTypes, err := a.getProviderTypes(r.Context())
	if err != nil {
		redirector.raise(ErrorServerError, "failed to get oauth2 providers")
		return
	}

	loginQuery := make(url.Values)
	loginQuery.Set("state", state)
	loginQuery.Set("callback", "https://"+r.Host+"/oauth2/v2/login")
	loginQuery.Set("providers", strings.Join(supportedTypes, " "))

	// Redirect to an external login handler, if you have chosen to.
	if client.Spec.LoginURI != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?%s", *client.Spec.LoginURI, loginQuery.Encode()), http.StatusFound)
		return
	}

	// Otherwise use the internal version.
	body, err := html.Login(loginQuery.Encode())
	if err != nil {
		redirector.raise(ErrorServerError, "failed to render login template")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body); err != nil {
		log.Info("oauth2: failed to write HTML response")
		return
	}
}

// Login handles the response from the user login prompt.
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		htmlError(w, r, http.StatusBadRequest, "form parse failure")
		return
	}

	if !r.Form.Has("state") {
		htmlError(w, r, http.StatusBadRequest, "state field missing")
		return
	}

	var state LoginStateClaims
	if err := a.jwtIssuer.DecodeJWEToken(r.Context(), r.Form.Get("state"), &state, jose.TokenTypeLoginDialogState); err != nil {
		htmlError(w, r, http.StatusBadRequest, "login state failed to decode")
		return
	}

	query, err := url.ParseQuery(state.Query)
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "failed to parse query")
		return
	}

	redirector := newRedirector(w, r, query.Get("redirect_uri"), query.Get("state"))

	// Handle the case where the provider is explicitly specified.
	if providerType := r.Form.Get("provider"); providerType != "" {
		provider, err := a.lookupProviderByType(r.Context(), unikornv1.IdentityProviderType(providerType))
		if err != nil {
			redirector.raise(ErrorServerError, err.Error())
			return
		}

		a.providerAuthenticationRequest(w, r, redirector, provider, query, "")

		return
	}

	// Otherwise we need to infer the provider.
	email := r.Form.Get("email")
	if email == "" {
		redirector.raise(ErrorServerError, "email query parameter not specified")
		return
	}

	organization, err := a.lookupOrganization(r.Context(), email)
	if err != nil {
		redirector.raise(ErrorServerError, err.Error())
		return
	}

	provider, err := a.lookupProviderByID(r.Context(), *organization.Spec.ProviderID, organization)
	if err != nil {
		redirector.raise(ErrorServerError, err.Error())
		return
	}

	a.providerAuthenticationRequest(w, r, redirector, provider, query, email)
}

// providerAuthenticationRequest kicks off the authorization flow with the backend
// provider.
func (a *Authenticator) providerAuthenticationRequest(w http.ResponseWriter, r *http.Request, redirector *redirector, provider *unikornv1.OAuth2Provider, query url.Values, email string) {
	// Try to infer the email address if one was not specified.
	if email == "" && query.Has("login_hint") {
		email = query.Get("login_hint")
	}

	// OIDC requires a nonce, just some random data base64 URL encoded will suffice.
	nonce, err := randomString(16)
	if err != nil {
		redirector.raise(ErrorServerError, "unable to create oidc nonce: "+err.Error())
		return
	}

	// We pass a hashed code challenge to the OIDC authorization endpoint when
	// requesting an authentication code.  When we exchange that for a token we
	// send the initial code challenge verifier so the token endpoint can validate
	// it's talking to the same client.
	codeVerifier := oauth2.GenerateVerifier()

	// Rather than cache any state we require after the oauth redirection dance, which
	// requires persistent state at the minimum, and a database in the case of multi-head
	// deployments, just encrypt it and send with the authorization request.
	oidcState := &State{
		OAuth2Provider: provider.Name,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		ClientQuery:    query.Encode(),
	}

	state, err := a.jwtIssuer.EncodeJWEToken(r.Context(), oidcState, jose.TokenTypeLoginState)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to encode oidc state: "+err.Error())
		return
	}

	driver := providers.New(provider.Spec.Type)

	configParameters := &types.ConfigParameters{
		Host:     r.Host,
		Provider: provider,
	}

	config, err := driver.Config(r.Context(), a.client, configParameters)
	if err != nil {
		redirector.raise(ErrorServerError, "unable to create oauth2 config: "+err.Error())
		return
	}

	parameters := &types.AuthorizationParamters{
		Nonce:        nonce,
		State:        state,
		CodeVerifier: codeVerifier,
		Email:        email,
		Query:        query,
	}

	url, err := driver.AuthorizationURL(config, parameters)
	if err != nil {
		redirector.raise(ErrorServerError, "unable to create oauth2 redirect: "+err.Error())
		return
	}

	http.Redirect(w, r, url, http.StatusFound)
}

// Callback is called by the authorization endpoint in order to return an
// authorization back to us.  We then exchange the code for an ID token, and
// refresh token.  Remember, as far as the client is concerned we're still doing
// the code grant, so return errors in the redirect query.
//
//nolint:cyclop,nestif
func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// This should always be present, if not then we are boned and cannot
	// send an error back to the redirectURI, cos that's in the state!
	if !query.Has("state") {
		htmlError(w, r, http.StatusBadRequest, "oidc state is required")
		return
	}

	var state State
	if err := a.jwtIssuer.DecodeJWEToken(r.Context(), query.Get("state"), &state, jose.TokenTypeLoginState); err != nil {
		htmlError(w, r, http.StatusBadRequest, "oidc state failed to decode")
		return
	}

	clientQuery, err := url.ParseQuery(state.ClientQuery)
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "client query failed to decode")
		return
	}

	redirector := newRedirector(w, r, clientQuery.Get("redirect_uri"), clientQuery.Get("state"))

	if query.Has("error") {
		redirector.raise(Error(query.Get("error")), query.Get("error_description"))
		return
	}

	if !query.Has("code") {
		redirector.raise(ErrorServerError, "oidc callback does not contain an authorization code")
		return
	}

	provider, err := a.lookupProviderByID(r.Context(), state.OAuth2Provider, nil)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to get oauth2 provider")
		return
	}

	parameters := &types.CodeExchangeParameters{
		ConfigParameters: types.ConfigParameters{
			Host:     r.Host,
			Provider: provider,
		},
		Code:         query.Get("code"),
		CodeVerifier: state.CodeVerifier,
	}

	_, idToken, err := providers.New(provider.Spec.Type).CodeExchange(r.Context(), a.client, parameters)
	if err != nil {
		redirector.raise(ErrorServerError, "code exchange failed: "+err.Error())
		return
	}

	// Now we have done code exchange, we have access to the id_token and that
	// allows us to see if the user actually exists.  If it doesn't then we
	// either deny entry or let them signup.
	user, err := a.rbac.GetUser(r.Context(), idToken.Email.Email)
	if err != nil {
		if !goerrors.Is(err, rbac.ErrUserNotFound) {
			redirector.raise(ErrorServerError, "user lookup failure")
		}

		if !a.options.AccountCreationEnabled {
			redirector.raise(ErrorServerError, "user signup is not permitted")
			return
		}

		client, err := a.lookupClient(r.Context(), clientQuery.Get("client_id"))
		if err != nil {
			redirector.raise(ErrorServerError, "client_id lookup failed")
			return
		}

		if client.Spec.OnboardingURI == nil {
			redirector.raise(ErrorServerError, "onboarding API not implemented")
			return
		}

		onboardingState := &OnboardingState{
			OAuth2Provider: state.OAuth2Provider,
			ClientQuery:    state.ClientQuery,
			IDToken:        idToken,
		}

		state, err := a.jwtIssuer.EncodeJWEToken(r.Context(), onboardingState, jose.TokenTypeOnboardState)
		if err != nil {
			redirector.raise(ErrorServerError, "failed to encode onboarding state: "+err.Error())
			return
		}

		a.accountCreationCache.Add(state, nil, 10*time.Minute)

		q := make(url.Values)
		q.Set("state", state)
		q.Set("callback", "https://"+r.Host+"/oauth2/v2/onboard")
		q.Set("email", idToken.Email.Email)

		if idToken.Name != "" {
			q.Set("username", idToken.Name)
		}

		if idToken.GivenName != "" {
			q.Set("forename", idToken.GivenName)
		}

		if idToken.FamilyName != "" {
			q.Set("surname", idToken.FamilyName)
		}

		http.Redirect(w, r, *client.Spec.OnboardingURI+"?"+q.Encode(), http.StatusFound)

		return
	}

	if user.Spec.State != unikornv1.UserStateActive {
		redirector.raise(ErrorServerError, "user is not active")
		return
	}

	code := &Code{
		ID:             uuid.New().String(),
		UserID:         user.Name,
		ClientQuery:    state.ClientQuery,
		OAuth2Provider: state.OAuth2Provider,
		Interactive:    true,
		IDToken:        idToken,
	}

	a.authorizationCodeRedirect(w, r, redirector, clientQuery, code)
}

// authorizationCodeRedirect packages up an authorization code and redirects to the client.
func (a *Authenticator) authorizationCodeRedirect(w http.ResponseWriter, r *http.Request, redirector *redirector, clientQuery url.Values, code *Code) {
	codeCipher, err := a.jwtIssuer.EncodeJWEToken(r.Context(), code, jose.TokenTypeAuthorizationCode)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to encode authorization code: "+err.Error())
		return
	}

	q := make(url.Values)
	q.Set("code", codeCipher)

	if clientQuery.Has("state") {
		q.Set("state", clientQuery.Get("state"))
	}

	a.codeCache.Add(codeCipher, nil, time.Minute)

	// OIDC support silent re-authentication, the expectation is that the user will
	// be able to reauthenticate for a period without a login prompt, up to the max_age
	// specified in the authentication request.  To trust the user we store away a cookie
	// we can use to establish trust, bind the to the client ID etc etc.
	cookie := &http.Cookie{
		Name:     SessionCookie,
		Path:     "/",
		Domain:   r.Host,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Value:    codeCipher,
	}

	w.Header().Add("Set-Cookie", cookie.String())

	redirector.redirect(q)
}

// OnboardWebhookData defines the webhook interface on accoutn creation.
// NOTE: this is governed by a specification and is an external contract, do not
// make any unreviewed backwards incompatible changes.
//
//nolint:tagliatelle
type OnboardWebhookData struct {
	// Email address of the user.
	Email string `json:"email"`
	// Username of the user.
	Username string `json:"username"`
	// Forename, if available, of the user.
	Forename string `json:"forename,omitempty"`
	// Surname, if available, of the user.
	Surname string `json:"surname,omitempty"`
	// UserID of the new user.
	// TODO: we can't get at this via the API...
	// UserID string `json:"userID"`
	// OrganizationID of the new user.
	OrganizationID string `json:"organizationID"`
	// OrganizationName of the new user.
	// NOTE: names are immutable, so really don't rely on this for anything.
	OrganizationName string `json:"organizationName"`
	// OrganizationUserID of the new user.
	OrganizationUserID string `json:"organizationUserID"`
}

func (a *Authenticator) validateOnboardState(ctx context.Context, w http.ResponseWriter, r *http.Request) (*OnboardingState, url.Values, bool) {
	if !a.options.AccountCreationEnabled {
		htmlError(w, r, http.StatusBadRequest, "attempt to use disabled endpoint")
		return nil, nil, false
	}

	if err := r.ParseForm(); err != nil {
		htmlError(w, r, http.StatusBadRequest, "form parse failure")
		return nil, nil, false
	}

	requiredFields := []string{
		"state",
		"organization_name",
		"group_name",
	}

	for _, req := range requiredFields {
		if !r.Form.Has(req) {
			htmlError(w, r, http.StatusBadRequest, req+" field missing")
			return nil, nil, false
		}
	}

	stateRaw := r.Form.Get("state")
	if _, ok := a.accountCreationCache.Get(stateRaw); !ok {
		htmlError(w, r, http.StatusBadRequest, "stale account creation state")
		return nil, nil, false
	}

	a.accountCreationCache.Remove(stateRaw)

	var state OnboardingState
	if err := a.jwtIssuer.DecodeJWEToken(ctx, stateRaw, &state, jose.TokenTypeOnboardState); err != nil {
		htmlError(w, r, http.StatusBadRequest, "account creation state failed to decode")
		return nil, nil, false
	}

	query, err := url.ParseQuery(state.ClientQuery)
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "client query failed to decode")
		return nil, nil, false
	}

	return &state, query, true
}

// getInternalIssuer returns the conventional token issuer for tokens issued here.
func (a *Authenticator) getInternalIssuer() string {
	return a.issuer.URL
}

// getAudience returns the conventional audience for tokens issued here.
func (a *Authenticator) getAudience() string {
	return a.issuer.Hostname
}

// Onboard creates a user's initial account and organization under guidance
// from the client.
//
//nolint:cyclop
func (a *Authenticator) Onboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state, clientQuery, ok := a.validateOnboardState(ctx, w, r)
	if !ok {
		return
	}

	redirector := newRedirector(w, r, clientQuery.Get("redirect_uri"), clientQuery.Get("state"))

	// List all global roles available and filter based on whether they are usable
	// and part of the requested set.
	opts := []client.ListOption{
		&client.ListOptions{Namespace: a.namespace},
	}

	var list unikornv1.RoleList
	if err := a.client.List(ctx, &list, opts...); err != nil {
		redirector.raise(ErrorServerError, "failed to list roles")
		return
	}

	requestedRoles := a.options.AccountCreationDefaultRoles

	if r.Form.Has("roles") {
		requestedRoles = strings.Split(r.Form.Get("roles"), " ")
	}

	list.Items = slices.DeleteFunc(list.Items, func(role unikornv1.Role) bool {
		return role.Spec.Protected || !slices.Contains(requestedRoles, role.Labels[constants.NameLabel])
	})

	roleIDs := make([]string, len(list.Items))

	for i := range list.Items {
		roleIDs[i] = list.Items[i].Name
	}

	// Set up the context for auditing and RBAC.
	// NOTE: we could bypass the handler functions to avoid RBAC entirely, we
	// are well within rights!
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub:   state.IDToken.Email.Email,
			Email: &state.IDToken.Email.Email,
		},
	}

	ctx = authorization.NewContext(ctx, info)

	var err error

	ctx, err = a.rbac.NewSuperContext(ctx)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to create ACL")
		return
	}

	// Create the requested organization, waiting for the controller to build it.
	organizationRequest := &openapi.OrganizationWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: r.Form.Get("organization_name"),
		},
		Spec: openapi.OrganizationSpec{
			OrganizationType: openapi.Adhoc,
		},
	}

	if r.Form.Has("organization_description") {
		organizationRequest.Metadata.Description = ptr.To(r.Form.Get("organization_description"))
	}

	if r.Form.Has("organization_tags") {
		fields := strings.Split(r.Form.Get("organization_tags"), " ")

		tags := make(coreapi.TagList, len(fields))

		for i := range fields {
			kv := strings.Split(fields[i], ":")
			if len(kv) != 2 {
				continue
			}

			tags[i].Name = kv[0]
			tags[i].Value = kv[1]
		}

		organizationRequest.Metadata.Tags = &tags
	}

	organization, err := organizations.New(a.client, a.namespace).Create(ctx, organizationRequest)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to create organization")
		return
	}

	organizationReady := func() error {
		meta, err := organizations.New(a.client, a.namespace).GetMetadata(ctx, organization.Metadata.Id)
		if err != nil {
			return err
		}

		if meta.Namespace == "" {
			return fmt.Errorf("%w: organization not provisioned", ErrReference)
		}

		return nil
	}

	if err := retry.Forever().DoWithContext(ctx, organizationReady); err != nil {
		redirector.raise(ErrorServerError, "failed to provision organization in time")
		return
	}

	// Create the group in the organization containing the requested roles.
	groupRequest := &openapi.GroupWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: r.Form.Get("group_name"),
		},
		Spec: openapi.GroupSpec{
			RoleIDs: roleIDs,
		},
	}

	if r.Form.Has("group_description") {
		groupRequest.Metadata.Description = ptr.To(r.Form.Get("group_description"))
	}

	group, err := groups.New(a.client, a.namespace, a.issuer).Create(ctx, organization.Metadata.Id, groupRequest)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to create group")
		return
	}

	// Finally create the user.
	userRequest := &openapi.UserWrite{
		Spec: openapi.UserSpec{
			Subject: state.IDToken.Email.Email,
			State:   openapi.Pending,
			GroupIDs: openapi.GroupIDs{
				group.Metadata.Id,
			},
		},
	}

	user, err := users.New(a.client, a.namespace, a.jwtIssuer, a.issuer, &users.Options{}).Create(ctx, organization.Metadata.Id, userRequest)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to create user")
		return
	}

	if !a.notifyAccountCreation(ctx, redirector, state.IDToken, organization, user) {
		return
	}

	// Finally when the optional webhook is
	userRequest.Spec.State = openapi.Active

	if _, err := users.New(a.client, a.namespace, a.jwtIssuer, a.issuer, &users.Options{}).Update(ctx, organization.Metadata.Id, user.Metadata.Id, userRequest); err != nil {
		redirector.raise(ErrorServerError, "failed to create user")
		return
	}

	shadowUser, err := a.rbac.GetUser(r.Context(), state.IDToken.Email.Email)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to read shadow user")
		return
	}

	code := &Code{
		ID:             uuid.New().String(),
		UserID:         shadowUser.Name,
		ClientQuery:    state.ClientQuery,
		OAuth2Provider: state.OAuth2Provider,
		Interactive:    true,
		IDToken:        state.IDToken,
	}

	a.authorizationCodeRedirect(w, r, redirector, clientQuery, code)
}

// notifyAccountCreation does any external service notification of account creation
// e.g. for billing perhaps.  Returns false if something failed.
func (a *Authenticator) notifyAccountCreation(ctx context.Context, redirector *redirector, idToken *oidc.IDToken, organization *openapi.OrganizationRead, user *openapi.UserRead) bool {
	if a.options.AccountCreationWebhookURI == "" {
		return true
	}

	webhookData := &OnboardWebhookData{
		Email:              idToken.Email.Email,
		Username:           idToken.Name,
		Forename:           idToken.GivenName,
		Surname:            idToken.FamilyName,
		OrganizationID:     organization.Metadata.Id,
		OrganizationName:   organization.Metadata.Name,
		OrganizationUserID: user.Metadata.Id,
	}

	webhookBody, err := json.Marshal(webhookData)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to marshal webhook data")
		return false
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.options.AccountCreationWebhookURI, bytes.NewBuffer(webhookBody))
	if err != nil {
		redirector.raise(ErrorServerError, "failed to create webhook request")
		return false
	}

	request.Header.Set("Content-Type", "application/json")

	if a.options.AccountCreationWebhookToken != "" {
		request.Header.Set("Authorization", "Bearer "+a.options.AccountCreationWebhookToken)
	}

	hc := &http.Client{}

	response, err := hc.Do(request)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to do webhook request")
		return false
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		redirector.raise(ErrorServerError, "webhook response returned unexpected status code")
		return false
	}

	return true
}

// tokenValidate does any request validation when issuing a token.
func tokenValidate(r *http.Request) error {
	if grantType := r.Form.Get("grant_type"); grantType != "authorization_code" {
		return errorsv2.NewInvalidGrantError().
			WithSimpleCausef("unsupported grant type: %s", grantType).
			WithErrorDescription("The provided grant type is invalid.").
			Prefixed()
	}

	required := []string{
		"redirect_uri",
		"code",
	}

	for _, parameter := range required {
		if !r.Form.Has(parameter) {
			return errorsv2.NewInvalidRequestError().
				WithSimpleCausef("missing required parameter: %s", parameter).
				WithErrorDescriptionf("The required parameter '%s' is missing.", parameter).
				Prefixed()
		}
	}

	return nil
}

// tokenValidateCode validates the request against the parsed code.
func tokenValidateCode(r *http.Request, query url.Values) error {
	if query.Get("redirect_uri") != r.Form.Get("redirect_uri") {
		return errorsv2.NewInvalidRequestError().
			WithSimpleCause("redirect_uri mismatch with authorization code").
			WithErrorDescription("The provided 'redirect_uri' does not match the registered URI for this client.").
			Prefixed()
	}

	// PKCE is optional, but highly recommended!
	if query.Has("code_challenge") {
		challenge := query.Get("code_challenge")
		verifier := r.Form.Get("code_verifier")

		switch getCodeChallengeMethod(query) {
		case openapi.Plain:
		case openapi.S256:
			verifier = oauth2.S256ChallengeFromVerifier(verifier)
		}

		if challenge != verifier {
			return errorsv2.NewInvalidGrantError().
				WithSimpleCause("code challenge and verifier mismatch").
				WithErrorDescription("The code verifier does not match the code challenge associated with this authorization code.").
				Prefixed()
		}
	}

	return nil
}

// oidcHash is used to create at_hash and c_hash values.
// TODO: this is very much tied to the algorithm defined (hard coded) in
// the JOSE package.
func oidcHash(value string) string {
	sum := sha512.Sum512([]byte(value))

	return base64.RawURLEncoding.EncodeToString(sum[:sha512.Size>>1])
}

// oidcIDToken builds an OIDC ID token.
func (a *Authenticator) oidcIDToken(r *http.Request, idToken *oidc.IDToken, query url.Values, expiry time.Duration, atHash string, lastAuthenticationTime time.Time) (*string, error) {
	scope := strings.Split(query.Get("scope"), " ")

	//nolint:nilnil
	if !slices.Contains(scope, "openid") {
		return nil, nil
	}

	claims := &oidc.IDToken{
		Claims: jwt.Claims{
			Issuer: a.getInternalIssuer(),
			// TODO: we should use the user ID.
			Subject: idToken.Email.Email,
			Audience: []string{
				query.Get("client_id"),
			},
			Expiry:   jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Default: oidc.Default{
			Nonce:           query.Get("nonce"),
			AuthTime:        ptr.To(lastAuthenticationTime.Unix()),
			AuthorizedParty: query.Get("client_id"),
		},
	}

	if atHash != "" {
		claims.ATHash = atHash
	}

	// NOTE: the scope here is intended to defined what happens when you call the
	// userinfo endpoint (and probably the "code id_token" grant type), but Google
	// etc. all do this, so why not...
	if slices.Contains(scope, "email") {
		claims.Email = idToken.Email
	}

	if slices.Contains(scope, "profile") {
		claims.Profile = idToken.Profile
	}

	token, err := a.jwtIssuer.EncodeJWT(r.Context(), claims)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (a *Authenticator) validateClientSecret(r *http.Request, query url.Values) error {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		if !r.Form.Has("client_id") {
			return errorsv2.NewInvalidRequestError().
				WithSimpleCause("missing required parameter: client_id").
				WithErrorDescription("The required parameter 'client_id' is missing.").
				Prefixed()
		}

		if !r.Form.Has("client_secret") {
			return errorsv2.NewInvalidClientError().
				WithSimpleCause("missing required parameter: client_secret").
				WithErrorDescription("Client authentication failed because the client_secret is missing.").
				Prefixed()
		}

		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if query.Get("client_id") != clientID {
		return errorsv2.NewInvalidClientError().
			WithSimpleCause("client_id mismatch with authorization code").
			WithErrorDescription("The client_id in the request does not match the client identifier associated with this authorization code.").
			Prefixed()
	}

	client, err := a.lookupClient(r.Context(), query.Get("client_id"))
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errorsv2.NewInvalidClientError().
				WithSimpleCause("client_id valid but no oauth2 client found").
				WithErrorDescription("The client could not be authenticated.").
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to retrieve oauth2 client: %w", err).
			Prefixed()
	}

	if client.Status.Secret == "" {
		return errorsv2.NewInternalError().
			WithSimpleCause("client secret missing for oauth2 client").
			Prefixed()
	}

	if client.Status.Secret != clientSecret {
		return errorsv2.NewInvalidClientError().
			WithSimpleCause("client secret mismatch for oauth2 client").
			WithErrorDescription("Client authentication failed due to invalid client credentials.").
			Prefixed()
	}

	return nil
}

// revokeSession revokes all tokens for a clientID.
func (a *Authenticator) revokeSession(ctx context.Context, clientID, codeID, subject string) error {
	user, err := a.rbac.GetActiveUser(ctx, subject)
	if err != nil {
		if goerrors.Is(err, rbac.ErrUserNotFound) {
			// REVIEW_ME: Sessions are scoped to a user. If the user doesn't exist,
			// there are no sessions to revoke, so this should return nil.
			// return nil
			_ = err // Temporary workaround to avoid lint error.
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to retrieve user: %w", err).
			Prefixed()
	}

	isTargetUserSession := func(session unikornv1.UserSession) bool {
		return session.ClientID == clientID && session.AuthorizationCodeID == codeID
	}

	index := slices.IndexFunc(user.Spec.Sessions, isTargetUserSession)
	if index < 0 {
		return nil
	}

	// Things can still go wrong between here and issuing the new token, so invalidate
	// the session now rather than relying on the reissue doing it for us.
	a.InvalidateToken(ctx, user.Spec.Sessions[index].AccessToken)

	user.Spec.Sessions = append(user.Spec.Sessions[:index], user.Spec.Sessions[index+1:]...)

	if err := a.client.Update(ctx, user); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to update user during session revocation: %w", err).
			Prefixed()
	}

	return nil
}

// TokenAuthorizationCode issues a token based on whether the provided code is correct and
// the client code verifier (PKCS) matches.
func (a *Authenticator) TokenAuthorizationCode(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	if err := tokenValidate(r); err != nil {
		return nil, err
	}

	codeRaw := r.Form.Get("code")

	var code Code
	if err := a.jwtIssuer.DecodeJWEToken(r.Context(), codeRaw, &code, jose.TokenTypeAuthorizationCode); err != nil {
		err = errorsv2.NewInvalidGrantError().
			WithCausef("failed to decode authorization code: %w", err).
			WithErrorDescription("The provided authorization code is invalid.").
			Prefixed()

		return nil, err
	}

	clientQuery, err := url.ParseQuery(code.ClientQuery)
	if err != nil {
		err = errorsv2.NewInvalidGrantError().
			WithCausef("failed to parse client query from authorization code: %w", err).
			WithErrorDescription("The provided authorization code is invalid.").
			Prefixed()

		return nil, err
	}

	clientID := clientQuery.Get("client_id")

	if err := tokenValidateCode(r, clientQuery); err != nil {
		return nil, err
	}

	if err := a.validateClientSecret(r, clientQuery); err != nil {
		return nil, err
	}

	// RFC 6749 4.1.2 - code reuse should revoke any tokens associated with the
	// authentication code, we just clear out anything associated with the client
	// session.
	if _, ok := a.codeCache.Get(codeRaw); !ok {
		_ = a.revokeSession(r.Context(), clientID, code.ID, code.IDToken.Email.Email)

		err = errorsv2.NewInvalidGrantError().
			WithSimpleCause("authorization code reuse detected").
			WithErrorDescription("The provided authorization code has already been used.").
			Prefixed()

		return nil, err
	}

	a.codeCache.Remove(codeRaw)

	info := &IssueInfo{
		Issuer:   a.getInternalIssuer(),
		Audience: a.getAudience(),
		// TODO: we should probably use the user ID here.
		Subject: code.IDToken.Email.Email,
		Type:    TokenTypeFederated,
		Federated: &FederatedClaims{
			ClientID: clientID,
			UserID:   code.UserID,
			Provider: code.OAuth2Provider,
			Scope:    NewScope(clientQuery.Get("scope")),
		},
		AuthorizationCodeID: &code.ID,
		Interactive:         code.Interactive,
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to issue token: %w", err).
			Prefixed()

		return nil, err
	}

	// Handle OIDC.
	idToken, err := a.oidcIDToken(r, code.IDToken, clientQuery, a.options.AccessTokenDuration, oidcHash(tokens.AccessToken), tokens.LastAuthenticationTime)
	if err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to create oidc id token: %w", err).
			Prefixed()

		return nil, err
	}

	result := &openapi.Token{
		TokenType:    "Bearer",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IdToken:      idToken,
		ExpiresIn:    int(time.Until(tokens.Expiry).Seconds()),
	}

	return result, nil
}

func (a *Authenticator) validateClientSecretRefresh(r *http.Request, claims *RefreshTokenClaims) error {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		if !r.Form.Has("client_id") {
			return errorsv2.NewInvalidRequestError().
				WithSimpleCause("missing required parameter: client_id").
				WithErrorDescription("The required parameter 'client_id' is missing.").
				Prefixed()
		}

		if !r.Form.Has("client_secret") {
			return errorsv2.NewInvalidClientError().
				WithSimpleCause("missing required parameter: client_secret").
				WithErrorDescription("Client authentication failed because the client_secret is missing.").
				Prefixed()
		}

		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if claims.Federated.ClientID != clientID {
		return errorsv2.NewInvalidClientError().
			WithSimpleCause("client_id mismatch with authorization code").
			WithErrorDescription("The client_id in the request does not match the client identifier associated with this authorization code.").
			Prefixed()
	}

	client, err := a.lookupClient(r.Context(), claims.Federated.ClientID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errorsv2.NewInvalidClientError().
				WithSimpleCause("client_id valid but no oauth2 client found").
				WithErrorDescription("The client could not be authenticated.").
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to retrieve oauth2 client: %w", err).
			Prefixed()
	}

	if client.Status.Secret == "" {
		return errorsv2.NewInternalError().
			WithSimpleCause("client secret missing for oauth2 client").
			Prefixed()
	}

	if client.Status.Secret != clientSecret {
		return errorsv2.NewInvalidClientError().
			WithSimpleCause("client secret mismatch for oauth2 client").
			WithErrorDescription("Client authentication failed due to invalid client credentials.").
			Prefixed()
	}

	return nil
}

// validateRefreshToken checks the refresh token ID is still valid (unused) and clears it
// from the user record.
func (a *Authenticator) validateRefreshToken(ctx context.Context, r *http.Request, refreshToken string, claims *RefreshTokenClaims) error {
	if err := a.validateClientSecretRefresh(r, claims); err != nil {
		return err
	}

	user, err := a.rbac.GetActiveUser(ctx, claims.Subject)
	if err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to retrieve user during refresh token validation: %w", err).
			Prefixed()
	}

	isTargetUserSession := func(session unikornv1.UserSession) bool {
		return session.ClientID == claims.Federated.ClientID
	}

	index := slices.IndexFunc(user.Spec.Sessions, isTargetUserSession)
	if index < 0 {
		return errorsv2.NewInvalidGrantError().
			WithSimpleCause("no active session found during refresh token validation").
			WithErrorDescription("The provided refresh token is invalid.").
			Prefixed()
	}

	if user.Spec.Sessions[index].RefreshToken == "" {
		return errorsv2.NewInvalidGrantError().
			WithSimpleCause("refresh token already used").
			WithErrorDescription("The refresh token has already been used and cannot be used for issuing new access tokens.").
			Prefixed()
	}

	if user.Spec.Sessions[index].RefreshToken != refreshToken {
		return errorsv2.NewInvalidGrantError().
			WithSimpleCause("refresh token mismatch during refresh token validation").
			WithErrorDescription("The provided refresh token is invalid.").
			Prefixed()
	}

	// Things can still go wrong between here and issuing the new token, so invalidate
	// the session now rather than relying on the reissue doing it for us.
	a.InvalidateToken(ctx, user.Spec.Sessions[index].AccessToken)

	user.Spec.Sessions[index].RefreshToken = ""

	if err := a.client.Update(ctx, user); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to update user during session revocation: %w", err).
			Prefixed()
	}

	return nil
}

// TokenRefreshToken issues a token if the provided refresh token is valid.
func (a *Authenticator) TokenRefreshToken(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	refreshTokenRaw := r.Form.Get("refresh_token")

	// Validate the refresh token and extract the claims.
	var claims RefreshTokenClaims
	if err := a.jwtIssuer.DecodeJWEToken(r.Context(), refreshTokenRaw, &claims, jose.TokenTypeRefreshToken); err != nil {
		err = errorsv2.NewInvalidGrantError().
			WithCausef("failed to decode refresh token: %w", err).
			WithErrorDescription("The provided refresh token is invalid.").
			Prefixed()

		return nil, err
	}

	if err := a.validateRefreshToken(r.Context(), r, refreshTokenRaw, &claims); err != nil {
		return nil, err
	}

	info := &IssueInfo{
		Issuer:    a.getInternalIssuer(),
		Audience:  a.getAudience(),
		Subject:   claims.Subject,
		Type:      TokenTypeFederated,
		Federated: claims.Federated,
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to issue token: %w", err).
			Prefixed()

		return nil, err
	}

	result := &openapi.Token{
		TokenType:    "Bearer",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int(time.Until(tokens.Expiry).Seconds()),
	}

	return result, nil
}

// TokenClientCredentials issues a token if the client credentials are valid.  We only support
// mTLS based authentication.
func (a *Authenticator) TokenClientCredentials(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	certPEM, err := util.GetClientCertificateHeader(r.Header)
	if err != nil {
		err = errorsv2.NewInvalidRequestError().
			WithCausef("failed to retrieve mTLS client certificate header from request: %w", err).
			WithErrorDescription("Client authentication failed because the client certificate is missing from the request.").
			Prefixed()

		return nil, err
	}

	certificate, err := util.GetClientCertificate(certPEM)
	if err != nil {
		err = errorsv2.NewInvalidRequestError().
			WithCausef("failed to parse or validate mTLS client certificate: %w", err).
			WithErrorDescription("Client authentication failed because the provided client certificate could not be validated.").
			Prefixed()

		return nil, err
	}

	thumbprint := util.GetClientCertifcateThumbprint(certificate)

	info := &IssueInfo{
		Issuer:   a.getInternalIssuer(),
		Audience: a.getAudience(),
		Subject:  certificate.Subject.CommonName,
		Type:     TokenTypeService,
		Service: &ServiceClaims{
			X509Thumbprint: thumbprint,
		},
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to issue token: %w", err).
			Prefixed()

		return nil, err
	}

	result := &openapi.Token{
		TokenType:   "Bearer",
		AccessToken: tokens.AccessToken,
		ExpiresIn:   int(time.Until(tokens.Expiry).Seconds()),
	}

	return result, nil
}

// Token issues an OAuth2 access token from the provided authorization code.
func (a *Authenticator) Token(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	if err := r.ParseForm(); err != nil {
		err = errorsv2.NewInvalidRequestError().
			WithCausef("failed to parse form data: %w", err).
			WithErrorDescription("Failed to process the request. Ensure all required parameters are correctly formatted.").
			Prefixed()

		return nil, err
	}

	grantType := r.Form.Get("grant_type")

	// We support 3 garnt types:
	// * "authorization_code" is used by all humans in the system
	// * "refresh_token" is used by anyone to get a new access token
	// * "client_credentials" is used by other services for IPC
	switch openapi.GrantType(grantType) {
	case openapi.AuthorizationCode:
		return a.TokenAuthorizationCode(w, r)
	case openapi.RefreshToken:
		return a.TokenRefreshToken(w, r)
	case openapi.ClientCredentials:
		return a.TokenClientCredentials(w, r)
	}

	err := errorsv2.NewUnsupportedGrantTypeError().
		WithSimpleCausef("unsupported grant type received in token request: %s", grantType).
		WithErrorDescription("The provided grant type is not supported.").
		Prefixed()

	return nil, err
}

// GetUserinfo does access token introspection.
func (a *Authenticator) GetUserinfo(ctx context.Context, token string) (*openapi.Userinfo, *Claims, error) {
	verifyInfo := &VerifyInfo{
		Issuer:   a.getInternalIssuer(),
		Audience: a.getAudience(),
		Token:    token,
	}

	// Check the token is from us, for us, and in date.
	claims, err := a.Verify(ctx, verifyInfo)
	if err != nil {
		return nil, nil, err
	}

	userinfo := &openapi.Userinfo{
		Sub: claims.Subject,
	}

	if claims.Type == TokenTypeFederated {
		if slices.Contains(claims.Federated.Scope, "email") {
			userinfo.Email = ptr.To(claims.Subject)
			userinfo.EmailVerified = ptr.To(true)
		}
	}

	return userinfo, claims, nil
}
