/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	goerrors "errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers"
	providererrors "github.com/unikorn-cloud/identity/pkg/oauth2/providers/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
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
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.AccessTokenDuration, "access-token-duration", time.Hour, "Maximum time an access token can be active for.")
	f.DurationVar(&o.RefreshTokenDuration, "refresh-token-duration", 0, "Maximum time a refresh token can be active for.")
	f.DurationVar(&o.TokenVerificationLeeway, "token-verification-leeway", 0, "How mush leeway to permit for verification of token validity.")
	f.DurationVar(&o.TokenLeewayDuration, "token-leeway", time.Minute, "How long to remove from the provider token expiry to account for network and processing latency.")
}

// Authenticator provides Keystone authentication functionality.
type Authenticator struct {
	options *Options

	namespace string

	client client.Client

	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer

	rbac *rbac.RBAC
}

// New returns a new authenticator with required fields populated.
// You must call AddFlags after this.
func New(options *Options, namespace string, client client.Client, issuer *jose.JWTIssuer, rbac *rbac.RBAC) *Authenticator {
	return &Authenticator{
		options:   options,
		namespace: namespace,
		client:    client,
		issuer:    issuer,
		rbac:      rbac,
	}
}

func (a *Authenticator) GetRBAC() *rbac.RBAC {
	return a.rbac
}

type Error string

const (
	ErrorInvalidRequest          Error = "invalid_request"
	ErrorUnauthorizedClient      Error = "unauthorized_client"
	ErrorAccessDenied            Error = "access_denied"
	ErrorUnsupportedResponseType Error = "unsupported_response_type"
	ErrorInvalidScope            Error = "invalid_scope"
	ErrorServerError             Error = "server_error"
)

const (
	ProviderCookie = "provider"
)

// State records state across the call to the authorization server.
// This must be encrypted with JWE.
type State struct {
	// Nonce is the one time nonce used to create the token.
	Nonce string `json:"n"`
	// Code verfier is required to prove our identity when
	// exchanging the code with the token endpoint.
	CodeVerfier string `json:"cv"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
	// ClientID is the client identifier.
	ClientID string `json:"cid"`
	// ClientRedirectURI is the redirect URL requested by the client.
	ClientRedirectURI string `json:"cri"`
	// Client state records the client's OAuth state while we interact
	// with the OIDC authorization server.
	ClientState string `json:"cst,omitempty"`
	// ClientCodeChallenge records the client code challenge so we can
	// authenticate we are handing the authorization token back to the
	// correct client.
	ClientCodeChallenge string `json:"ccc"`
	// ClientScope records the requested client scope.
	ClientScope Scope `json:"csc,omitempty"`
	// ClientNonce is injected into a OIDC id_token.
	ClientNonce string `json:"cno,omitempty"`
}

// Code is an authorization code to return to the client that can be
// exchanged for an access token.  Much like how we client things in the oauth2
// state during the OIDC exchange, to mitigate problems with horizonal scaling
// and sharing stuff, we do the same here.
// WARNING: Don't make this too big, the ingress controller will barf if the
// headers are too hefty.
type Code struct {
	// ClientID is the client identifier.
	ClientID string `json:"cid"`
	// ClientRedirectURI is the redirect URL requested by the client.
	ClientRedirectURI string `json:"cri"`
	// ClientCodeChallenge records the client code challenge so we can
	// authenticate we are handing the authorization token back to the
	// correct client.
	ClientCodeChallenge string `json:"ccc"`
	// ClientScope records the requested client scope.
	ClientScope Scope `json:"csc,omitempty"`
	// ClientNonce is injected into a OIDC id_token.
	ClientNonce string `json:"cno,omitempty"`
	// IDToken is the full set of claims returned by the provider.
	IDToken IDToken `json:"idt"`
	// AccessToken is the user's access token.
	AccessToken string `json:"at"`
	// RefreshToken is the users's refresh token.
	RefreshToken string `json:"rt"`
	// AccessTokenExpiry tells us how long the token will last for.
	AccessTokenExpiry time.Time `json:"ate"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
}

var (
	// errorTemplate defines the HTML used to raise an error to the client.
	//go:embed error.tmpl
	errorTemplate string

	// loginTemplate defines the HTML used to acquire an email address from
	// the end user.
	//go:embed login.tmpl
	loginTemplate string
)

// htmlError is used in dire situations when we cannot return an error via
// the usual oauth2 flow.
func htmlError(w http.ResponseWriter, r *http.Request, status int, description string) {
	log := log.FromContext(r.Context())

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)

	tmpl, err := template.New("error").Parse(errorTemplate)
	if err != nil {
		log.Info("oauth2: failed to parse template", "error", err)
		return
	}

	templateContext := map[string]interface{}{
		"description": description,
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, templateContext); err != nil {
		log.Info("oauth2: failed to render template", "error", err)
		return
	}

	if _, err := w.Write(buffer.Bytes()); err != nil {
		log.Info("oauth2: failed to write HTML response")
	}
}

// authorizationError redirects to the client's callback URI with an error
// code in the query.
func authorizationError(w http.ResponseWriter, r *http.Request, redirectURI string, kind Error, description string) {
	values := &url.Values{}
	values.Set("error", string(kind))
	values.Set("error_description", description)

	http.Redirect(w, r, redirectURI+"?"+values.Encode(), http.StatusFound)
}

func (a *Authenticator) lookupClient(w http.ResponseWriter, r *http.Request, clientID string) (*unikornv1.OAuth2Client, bool) {
	var clients unikornv1.OAuth2ClientList

	if err := a.client.List(r.Context(), &clients, &client.ListOptions{Namespace: a.namespace}); err != nil {
		htmlError(w, r, http.StatusInternalServerError, err.Error())

		return nil, false
	}

	for i := range clients.Items {
		if clients.Items[i].Name == clientID {
			return &clients.Items[i], true
		}
	}

	htmlError(w, r, http.StatusBadRequest, "client_id is invalid")

	return nil, false
}

// OAuth2AuthorizationValidateNonRedirecting checks authorization request parameters
// are valid that directly control the ability to redirect, and returns some helpful
// debug in HTML.
func (a *Authenticator) authorizationValidateNonRedirecting(w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query()

	if !query.Has("client_id") {
		htmlError(w, r, http.StatusBadRequest, "client_id is not specified")

		return false
	}

	if !query.Has("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is not specified")

		return false
	}

	client, ok := a.lookupClient(w, r, query.Get("client_id"))
	if !ok {
		return false
	}

	if client.Spec.RedirectURI != query.Get("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is invalid")

		return false
	}

	return true
}

// OAuth2AuthorizationValidateRedirecting checks autohorization request parameters after
// the redirect URI has been validated.  If any of these fail, we redirect but with an
// error query rather than a code for the client to pick up and run with.
func (a *Authenticator) authorizationValidateRedirecting(w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query()

	var kind Error

	var description string

	switch {
	case query.Get("response_type") != "code":
		kind = ErrorUnsupportedResponseType
		description = "response_type must be 'code'"
	case query.Get("code_challenge_method") != "S256":
		kind = ErrorInvalidRequest
		description = "code_challenge_method must be 'S256'"
	case query.Get("code_challenge") == "":
		kind = ErrorInvalidRequest
		description = "code_challenge must be specified"
	default:
		return true
	}

	authorizationError(w, r, query.Get("redirect_uri"), kind, description)

	return false
}

// oidcConfig returns a oauth2 configuration for the OIDC backend.
func (a *Authenticator) oidcConfig(r *http.Request, provider *unikornv1.OAuth2Provider, endpoint oauth2.Endpoint, scopes []string) *oauth2.Config {
	s := []string{
		oidc.ScopeOpenID,
		// For the user's name.
		"profile",
		// For the user's real email address i.e. not an alias.
		"email",
	}

	s = append(s, scopes...)

	config := &oauth2.Config{
		ClientID: provider.Spec.ClientID,
		Endpoint: endpoint,
		// TODO: the ingress converts this all into a relative URL
		// and adds an X-Forwardered-Host, X-Forwarded-Proto.  You should
		// never use HTTP anyway to be fair...
		RedirectURL: "https://" + r.Host + "/oidc/callback",
		Scopes:      s,
	}

	if provider.Spec.ClientSecret != nil {
		config.ClientSecret = *provider.Spec.ClientSecret
	}

	return config
}

// encodeCodeChallengeS256 performs code verifier to code challenge translation
// for the SHA256 method.
func encodeCodeChallengeS256(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))

	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// randomString creates size bytes of high entropy randomness and base64 URL
// encodes it into a string.  Bear in mind base64 expands the size by 33%, so for example
// an oauth2 code verifier needs to be at least 43 bytes, so youd nee'd a size of 32,
// 32 * 1.33 = 42.66.
func randomString(size int) (string, error) {
	buf := make([]byte, size)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

type providerGetter func(*http.Request, string) (*unikornv1.OAuth2Provider, error)

func (a *Authenticator) cookieProviderGetter(r *http.Request, _ string) (*unikornv1.OAuth2Provider, error) {
	providerCookie, err := r.Cookie(ProviderCookie)
	if err != nil {
		return nil, err
	}

	return a.lookupProviderByType(r.Context(), unikornv1.IdentityProviderType(providerCookie.Value))
}

func (a *Authenticator) organizationProviderGetter(r *http.Request, email string) (*unikornv1.OAuth2Provider, error) {
	organization, err := a.lookupOrganization(r.Context(), email)
	if err != nil {
		return nil, err
	}

	return a.lookupProviderByName(r.Context(), *organization.Spec.ProviderID)
}

func (a *Authenticator) providerGetters() []providerGetter {
	return []providerGetter{
		a.cookieProviderGetter,
		a.organizationProviderGetter,
	}
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

	query := r.URL.Query()

	if !a.authorizationValidateNonRedirecting(w, r) {
		return
	}

	if !a.authorizationValidateRedirecting(w, r) {
		return
	}

	// If the login_hint is provided, we can short cut the user interaction and
	// directly do the request to the backend provider.  This makes token expiry
	// alomost seamless in that a client can catch a 401, and just redirect back
	// here with the cached email address in the id_token.  For users who have
	// clicked "login in X", we need to have remembered this provider with a
	// cookie also.
	if email := query.Get("login_hint"); email != "" {
		for _, getter := range a.providerGetters() {
			provider, err := getter(r, email)
			if err == nil {
				a.providerAuthenticationRequest(w, r, email, provider, query)
				return
			}
		}
	}

	loginQuery := url.Values{}

	loginQuery.Set("state", query.Encode())
	loginQuery.Set("callback", "https://"+r.Host+"/oauth2/v2/login")
	// TODO: this needs to be driven by the available oauth2providers
	loginQuery.Set("providers", "google microsoft")

	client, ok := a.lookupClient(w, r, query.Get("client_id"))
	if !ok {
		htmlError(w, r, http.StatusBadRequest, "client_id is not specified")
		return
	}

	// Redirect to an external login handler, if you have chosen to.
	if client.Spec.LoginURI != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?%s", *client.Spec.LoginURI, loginQuery.Encode()), http.StatusFound)
		return
	}

	// Otherwise use the internal version.
	tmpl, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		log.Info("oauth2: failed to parse template", "error", err)
		return
	}

	templateContext := map[string]interface{}{
		"state": query.Encode(),
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, templateContext); err != nil {
		log.Info("oauth2: failed to render template", "error", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(buffer.Bytes()); err != nil {
		log.Info("oauth2: failed to write HTML response")
	}
}

// lookupOrganization maps from an email address to an organization, this handles
// corporate mandates that say your entire domain have to use a single sign on
// provider across the entire enterprise.
func (a *Authenticator) lookupOrganization(ctx context.Context, email string) (*unikornv1.Organization, error) {
	if email == "" {
		//nolint:goerr113
		return nil, fmt.Errorf("no email address provided")
	}

	// TODO: error checking.
	parts := strings.Split(email, "@")

	// TODO: error checking.
	domain := parts[1]

	var organizations unikornv1.OrganizationList

	if err := a.client.List(ctx, &organizations, &client.ListOptions{Namespace: a.namespace}); err != nil {
		return nil, err
	}

	for i := range organizations.Items {
		if organizations.Items[i].Spec.Domain == nil {
			continue
		}

		if *organizations.Items[i].Spec.Domain == domain {
			return &organizations.Items[i], nil
		}
	}

	// TODO: error type!
	//nolint:goerr113
	return nil, fmt.Errorf("unsupported domain")
}

func (a *Authenticator) lookupProviderByType(ctx context.Context, t unikornv1.IdentityProviderType) (*unikornv1.OAuth2Provider, error) {
	var resources unikornv1.OAuth2ProviderList

	if err := a.client.List(ctx, &resources, &client.ListOptions{Namespace: a.namespace}); err != nil {
		return nil, err
	}

	for i := range resources.Items {
		if resources.Items[i].Spec.Type != nil && *resources.Items[i].Spec.Type == t {
			return &resources.Items[i], nil
		}
	}

	// TODO: error type!
	//nolint:goerr113
	return nil, fmt.Errorf("unsupported provider type")
}

func (a *Authenticator) lookupProviderByName(ctx context.Context, name string) (*unikornv1.OAuth2Provider, error) {
	var providerResource unikornv1.OAuth2Provider

	if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: name}, &providerResource); err != nil {
		return nil, err
	}

	return &providerResource, nil
}

// newOIDCProvider abstracts away any hacks for specific providers.
func newOIDCProvider(ctx context.Context, p *unikornv1.OAuth2Provider) (*oidc.Provider, error) {
	if p.Spec.Type != nil && *p.Spec.Type == unikornv1.MicrosoftEntra {
		ctx = oidc.InsecureIssuerURLContext(ctx, "https://login.microsoftonline.com/{tenantid}/v2.0")
	}

	return oidc.NewProvider(ctx, p.Spec.Issuer)
}

// providerAuthenticationRequest takes a client provided email address and routes it
// to the correct identity provider, if we can.
func (a *Authenticator) providerAuthenticationRequest(w http.ResponseWriter, r *http.Request, email string, providerResource *unikornv1.OAuth2Provider, query url.Values) {
	log := log.FromContext(r.Context())

	driver := providers.New(providerResource.Spec.Type)

	provider, err := newOIDCProvider(r.Context(), providerResource)
	if err != nil {
		log.Error(err, "failed to do OIDC discovery")
		return
	}

	endpoint := provider.Endpoint()

	clientRedirectURI := query.Get("redirect_uri")

	// OIDC requires a nonce, just some random data base64 URL encoded will suffice.
	nonce, err := randomString(16)
	if err != nil {
		authorizationError(w, r, clientRedirectURI, ErrorServerError, "unable to create oidc nonce: "+err.Error())
		return
	}

	// We pass a hashed code challenge to the OIDC authorization endpoint when
	// requesting an authentication code.  When we exchange that for a token we
	// send the initial code challenge verifier so the token endpoint can validate
	// it's talking to the same client.
	codeVerifier, err := randomString(32)
	if err != nil {
		authorizationError(w, r, clientRedirectURI, ErrorServerError, "unable to create oauth2 code verifier: "+err.Error())
		return
	}

	codeChallenge := encodeCodeChallengeS256(codeVerifier)

	// Rather than cache any state we require after the oauth rediretion dance, which
	// requires persistent state at the minimum, and a database in the case of multi-head
	// deployments, just encrypt it and send with the authoriation request.
	oidcState := &State{
		OAuth2Provider:      providerResource.Name,
		Nonce:               nonce,
		CodeVerfier:         codeVerifier,
		ClientID:            query.Get("client_id"),
		ClientRedirectURI:   query.Get("redirect_uri"),
		ClientState:         query.Get("state"),
		ClientCodeChallenge: query.Get("code_challenge"),
	}

	// To implement OIDC we need a copy of the scopes.
	if query.Has("scope") {
		oidcState.ClientScope = NewScope(query.Get("scope"))
	}

	if query.Has("nonce") {
		oidcState.ClientNonce = query.Get("nonce")
	}

	state, err := a.issuer.EncodeJWEToken(r.Context(), oidcState, jose.TokenTypeLoginState)
	if err != nil {
		authorizationError(w, r, clientRedirectURI, ErrorServerError, "failed to encode oidc state: "+err.Error())
		return
	}

	// Finally generate the redirection URL and send back to the client.
	authURLParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("login_hint", email),
		oidc.Nonce(nonce),
	}

	for k, v := range driver.AuthorizationRequestParameters() {
		authURLParams = append(authURLParams, oauth2.SetAuthURLParam(k, v))
	}

	http.Redirect(w, r, a.oidcConfig(r, providerResource, endpoint, driver.Scopes()).AuthCodeURL(state, authURLParams...), http.StatusFound)
}

// Login handles the response from the user login prompt.
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		log.Error(err, "form parse failed")
		return
	}

	if !r.Form.Has("state") {
		log.Info("state doesn't exist in form")
		return
	}

	query, err := url.ParseQuery(r.Form.Get("state"))
	if err != nil {
		log.Error(err, "failed to parse query")
		return
	}

	if providerType := r.Form.Get("provider"); providerType != "" {
		provider, err := a.lookupProviderByType(r.Context(), unikornv1.IdentityProviderType(providerType))
		if err != nil {
			authorizationError(w, r, query.Get("redirect_uri"), ErrorServerError, err.Error())
			return
		}

		// Remember the choice for steam-lining login when a login_hint is provided.
		cookie := &http.Cookie{
			Name:     ProviderCookie,
			Value:    providerType,
			Secure:   true,
			HttpOnly: true,
		}

		w.Header().Add("Set-Cookie", cookie.String())

		a.providerAuthenticationRequest(w, r, r.Form.Get("email"), provider, query)

		return
	}

	// Remove the cookie otherwise.
	cookie := &http.Cookie{
		Name:   ProviderCookie,
		Value:  "undefined",
		MaxAge: -1,
	}

	w.Header().Add("Set-Cookie", cookie.String())

	if !r.Form.Has("email") {
		log.Info("email doesn't exist in form")
		return
	}

	organization, err := a.lookupOrganization(r.Context(), r.Form.Get("email"))
	if err != nil {
		authorizationError(w, r, query.Get("redirect_uri"), ErrorServerError, err.Error())
		return
	}

	provider, err := a.lookupProviderByName(r.Context(), *organization.Spec.ProviderID)
	if err != nil {
		authorizationError(w, r, query.Get("redirect_uri"), ErrorServerError, err.Error())
		return
	}

	a.providerAuthenticationRequest(w, r, r.Form.Get("email"), provider, query)
}

// oidcExtractIDToken wraps up token verification against the JWKS service and conversion
// to a concrete type.
func (a *Authenticator) oidcExtractIDToken(ctx context.Context, provider *oidc.Provider, providerResource *unikornv1.OAuth2Provider, token string) (*oidc.IDToken, error) {
	config := &oidc.Config{
		ClientID: providerResource.Spec.ClientID,
		// TODO: this is a Entra-ism
		SkipIssuerCheck: true,
	}

	idTokenVerifier := provider.Verifier(config)

	idToken, err := idTokenVerifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	return idToken, nil
}

// OIDCCallback is called by the authorization endpoint in order to return an
// authorization back to us.  We then exchange the code for an ID token, and
// refresh token.  Remember, as far as the client is concerned we're still doing
// the code grant, so return errors in the redirect query.
//
//nolint:cyclop
func (a *Authenticator) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	query := r.URL.Query()

	// This should always be present, if not then we are boned and cannot
	// send an error back to the redirectURI, cos that's in the state!
	if !query.Has("state") {
		htmlError(w, r, http.StatusBadRequest, "oidc state is required")
		return
	}

	// Extract our state for the next part...
	state := &State{}

	if err := a.issuer.DecodeJWEToken(r.Context(), query.Get("state"), state, jose.TokenTypeLoginState); err != nil {
		htmlError(w, r, http.StatusBadRequest, "oidc state failed to decode")
		return
	}

	if query.Has("error") {
		authorizationError(w, r, state.ClientRedirectURI, Error(query.Get("error")), query.Get("description"))
		return
	}

	if !query.Has("code") {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "oidc callback does not contain an authorization code")
		return
	}

	var providerResource unikornv1.OAuth2Provider

	if err := a.client.Get(r.Context(), client.ObjectKey{Namespace: a.namespace, Name: state.OAuth2Provider}, &providerResource); err != nil {
		log.Error(err, "failed to get provider")
		return
	}

	provider, err := newOIDCProvider(r.Context(), &providerResource)
	if err != nil {
		log.Error(err, "failed to do OIDC discovery")
		return
	}

	endpoint := provider.Endpoint()

	// Exchange the code for an id_token, access_token and refresh_token with
	// the extracted code verifier.
	authURLParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", state.ClientID),
		oauth2.SetAuthURLParam("code_verifier", state.CodeVerfier),
	}

	if providerResource.Spec.ClientSecret != nil {
		authURLParams = append(authURLParams, oauth2.SetAuthURLParam("client_secret", *providerResource.Spec.ClientSecret))
	}

	tokens, err := a.oidcConfig(r, &providerResource, endpoint, nil).Exchange(r.Context(), query.Get("code"), authURLParams...)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "oidc code exchange failed: "+err.Error())
		return
	}

	idTokenRaw, ok := tokens.Extra("id_token").(string)
	if !ok {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "oidc response missing id_token")
		return
	}

	idToken, err := a.oidcExtractIDToken(r.Context(), provider, &providerResource, idTokenRaw)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "id_token verification failed: "+err.Error())
		return
	}

	var idTokenClaims IDToken

	if err := idToken.Claims(&idTokenClaims); err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "failed to extract id_token email claims: "+err.Error())
		return
	}

	userExists, err := a.rbac.UserExists(r.Context(), idTokenClaims.Email)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "failed to perform RBAC user lookup: "+err.Error())
		return
	}

	if !userExists {
		authorizationError(w, r, state.ClientRedirectURI, ErrorAccessDenied, "user not found")
		return
	}

	// NOTE: the email is the canonical one returned by the IdP, which removes
	// aliases from the equation.
	oauth2Code := &Code{
		ClientID:            state.ClientID,
		ClientRedirectURI:   state.ClientRedirectURI,
		ClientCodeChallenge: state.ClientCodeChallenge,
		ClientScope:         state.ClientScope,
		ClientNonce:         state.ClientNonce,
		OAuth2Provider:      state.OAuth2Provider,
		IDToken:             idTokenClaims,
		AccessTokenExpiry:   tokens.Expiry,
	}

	driver := providers.New(providerResource.Spec.Type)

	// These can be big, see the provider comment for why.
	if driver.RequiresAccessToken() {
		oauth2Code.AccessToken = tokens.AccessToken
		oauth2Code.RefreshToken = tokens.RefreshToken
	}

	code, err := a.issuer.EncodeJWEToken(r.Context(), oauth2Code, jose.TokenTypeAuthorizationCode)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "failed to encode authorization code: "+err.Error())
		return
	}

	q := &url.Values{}
	q.Set("code", code)

	if state.ClientState != "" {
		q.Set("state", state.ClientState)
	}

	http.Redirect(w, r, state.ClientRedirectURI+"?"+q.Encode(), http.StatusFound)
}

// tokenValidate does any request validation when issuing a token.
func tokenValidate(r *http.Request) error {
	if r.Form.Get("grant_type") != "authorization_code" {
		return errors.OAuth2UnsupportedGrantType("grant_type must be 'authorization_code'")
	}

	required := []string{
		"client_id",
		"redirect_uri",
		"code",
		"code_verifier",
	}

	for _, parameter := range required {
		if !r.Form.Has(parameter) {
			return errors.OAuth2InvalidRequest(parameter + " must be specified")
		}
	}

	return nil
}

// tokenValidateCode validates the request against the parsed code.
func tokenValidateCode(code *Code, r *http.Request) error {
	if code.ClientID != r.Form.Get("client_id") {
		return errors.OAuth2InvalidGrant("client_id mismatch")
	}

	if code.ClientRedirectURI != r.Form.Get("redirect_uri") {
		return errors.OAuth2InvalidGrant("redirect_uri mismatch")
	}

	if code.ClientCodeChallenge != encodeCodeChallengeS256(r.Form.Get("code_verifier")) {
		return errors.OAuth2InvalidClient("code_verfier invalid")
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
func (a *Authenticator) oidcIDToken(r *http.Request, code *Code, expiry time.Duration, atHash string) (*string, error) {
	//nolint:nilnil
	if !slices.Contains(code.ClientScope, "openid") {
		return nil, nil
	}

	claims := &IDToken{
		Claims: jwt.Claims{
			Issuer:  "https://" + r.Host,
			Subject: code.IDToken.OIDCClaimsEmail.Email,
			Audience: []string{
				code.ClientID,
			},
			Expiry:   jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		OIDCClaims: OIDCClaims{
			Nonce:  code.ClientNonce,
			ATHash: atHash,
		},
	}

	if slices.Contains(code.ClientScope, "email") {
		claims.OIDCClaimsEmail = code.IDToken.OIDCClaimsEmail
	}

	if slices.Contains(code.ClientScope, "profile") {
		claims.OIDCClaimsProfile = code.IDToken.OIDCClaimsProfile
	}

	idToken, err := a.issuer.EncodeJWT(r.Context(), claims)
	if err != nil {
		return nil, err
	}

	return &idToken, nil
}

// Token issues an OAuth2 access token from the provided authorization code.
//
//nolint:cyclop
func (a *Authenticator) Token(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse form data: " + err.Error())
	}

	//nolint:nestif
	if r.Form.Get("grant_type") == "refresh_token" {
		// Validate the refresh token and extract the claims.
		claims := &RefreshTokenClaims{}

		if err := a.issuer.DecodeJWEToken(r.Context(), r.Form.Get("refresh_token"), claims, jose.TokenTypeRefreshToken); err != nil {
			return nil, errors.OAuth2InvalidGrant("refresh token is invalid or has expired").WithError(err)
		}

		// Lookup the provider details, then do a token refresh against that to update
		// the access token.
		providerResource, err := a.lookupProviderByName(r.Context(), claims.Custom.Provider)
		if err != nil {
			return nil, err
		}

		provider, err := newOIDCProvider(r.Context(), providerResource)
		if err != nil {
			return nil, err
		}

		refreshToken := &oauth2.Token{
			Expiry:       time.Now(),
			RefreshToken: claims.Custom.RefreshToken,
		}

		providerTokens, err := a.oidcConfig(r, providerResource, provider.Endpoint(), nil).TokenSource(r.Context(), refreshToken).Token()
		if err != nil {
			var rerr *oauth2.RetrieveError

			if goerrors.As(err, &rerr) && rerr.ErrorCode == string(coreopenapi.InvalidGrant) {
				return nil, errors.OAuth2InvalidGrant("provider refresh token has expired").WithError(err)
			}

			return nil, err
		}

		info := &IssueInfo{
			Issuer:   "https://" + r.Host,
			Audience: r.Host,
			Subject:  claims.Claims.Subject,
			Provider: claims.Custom.Provider,
			Tokens: Tokens{
				Expiry:       providerTokens.Expiry,
				AccessToken:  providerTokens.AccessToken,
				RefreshToken: providerTokens.RefreshToken,
			},
		}

		tokens, err := a.Issue(r.Context(), info)
		if err != nil {
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

	if err := tokenValidate(r); err != nil {
		return nil, err
	}

	code := &Code{}

	if err := a.issuer.DecodeJWEToken(r.Context(), r.Form.Get("code"), code, jose.TokenTypeAuthorizationCode); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse code: " + err.Error())
	}

	if err := tokenValidateCode(code, r); err != nil {
		return nil, err
	}

	info := &IssueInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		Subject:  code.IDToken.OIDCClaimsEmail.Email,
		Provider: code.OAuth2Provider,
		Tokens: Tokens{
			Expiry:       code.AccessTokenExpiry,
			AccessToken:  code.AccessToken,
			RefreshToken: code.RefreshToken,
		},
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		return nil, err
	}

	// Handle OIDC.
	idToken, err := a.oidcIDToken(r, code, a.options.AccessTokenDuration, oidcHash(tokens.AccessToken))
	if err != nil {
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

func (a *Authenticator) Groups(w http.ResponseWriter, r *http.Request) (openapi.AvailableGroups, error) {
	userinfo := userinfo.FromContext(r.Context())

	organization, err := a.lookupOrganization(r.Context(), userinfo.Subject)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("user not a member of this domain").WithError(err)
	}

	provider, err := a.lookupProviderByName(r.Context(), *organization.Spec.ProviderID)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to lookup provider for domain").WithError(err)
	}

	header := r.Header.Get("Authorization")

	parts := strings.Split(header, " ")

	info := &VerifyInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		Token:    parts[1],
	}

	claims, err := a.Verify(r.Context(), info)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to verify token").WithError(err)
	}

	driver := providers.New(provider.Spec.Type)

	groups, err := driver.Groups(r.Context(), organization, claims.Custom.AccessToken)
	if err != nil {
		if goerrors.Is(err, providererrors.ErrUnauthorized) {
			return nil, errors.OAuth2AccessDenied("unable to get groups from provider").WithError(err)
		}

		return nil, errors.OAuth2ServerError("unable to get groups").WithError(err)
	}

	result := make([]openapi.AvailableGroup, 0, len(groups))

	for _, group := range groups {
		result = append(result, openapi.AvailableGroup{
			Name:        group.Name,
			DisplayName: group.DisplayName,
		})
	}

	return result, nil
}
