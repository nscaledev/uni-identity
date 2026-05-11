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

package server

import (
	"context"
	"net/http"

	chi "github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/logging"
	"github.com/unikorn-cloud/core/pkg/server/middleware/opentelemetry"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/passport"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
	"github.com/unikorn-cloud/identity/pkg/oauth2/exchange"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Server struct {
	// CoreOptions are all common across everything e.g. namespace.
	CoreOptions options.CoreOptions

	// ServerOptions are server specific options e.g. listener address etc.
	ServerOptions options.ServerOptions

	// HandlerOptions sets options for the HTTP handler.
	HandlerOptions handler.Options

	// JoseOptions sets options for JWE.
	JoseOptions jose.Options

	// OAuth2Options sets options for the oauth2/oidc authenticator.
	OAuth2Options oauth2.Options

	// Auth0Options configures the Auth0 access-token validator at exchange.
	// Empty Issuer disables Auth0 validation; UNI tokens are unaffected.
	Auth0Options auth0.Options

	// CORSOptions are for remote resource sharing.
	CORSOptions cors.Options

	// RBACOptions are for RBAC related things.
	RBACOptions rbac.Options

	// OpenAPIOptions are for OpenAPI processing.
	OpenAPIOptions openapimiddleware.Options
}

type authComponents struct {
	issuer        *jose.JWTIssuer
	userdb        *userdb.UserDatabase
	rbac          *rbac.RBAC
	authenticator *oauth2.Authenticator
	uniAuthorizer *local.Authorizer
}

func (s *Server) AddFlags(flags *pflag.FlagSet) {
	s.CoreOptions.AddFlags(flags)
	s.ServerOptions.AddFlags(flags)
	s.HandlerOptions.AddFlags(flags)
	s.JoseOptions.AddFlags(flags)
	s.OAuth2Options.AddFlags(flags)
	s.Auth0Options.AddFlags(flags)
	s.CORSOptions.AddFlags(flags)
	s.RBACOptions.AddFlags(flags)
	s.OpenAPIOptions.AddFlags(flags)
}

func (s *Server) SetupLogging() {
	s.CoreOptions.SetupLogging()
}

func (s *Server) SetupOpenTelemetry(ctx context.Context) error {
	return s.CoreOptions.SetupOpenTelemetry(ctx)
}

func (s *Server) GetServer(client client.Client, directclient client.Client) (*http.Server, error) {
	schema, err := helpers.NewSchema(openapi.GetSwagger)
	if err != nil {
		return nil, err
	}

	router := chi.NewRouter()

	// Middleware specified here is applied to all requests pre-routing.
	// Ordering is important:
	// * OpenTelemetry middleware optionally transmits spans over OTLP, but also
	//   establishes a trace ID that is used to correlate logs with user issues.
	// * Logging ensures at least all errors are captured by logging telemetry and we
	//   can trigger alerts based on them.
	// * Route resolver provides routing and OpenAPI information to child middlewares.
	// * CORS emulates OPTIONS endpoints based on OpenAPI (requires route resolver).
	opentelemetry := opentelemetry.New(constants.Application, constants.Version)
	logging := logging.New()
	routeresolver := routeresolver.New(schema)
	cors := cors.New(&s.CORSOptions)

	router.Use(opentelemetry.Middleware)
	router.Use(logging.Middleware)
	router.Use(routeresolver.Middleware)
	router.Use(cors.Middleware)
	router.NotFound(http.HandlerFunc(handler.NotFound))
	router.MethodNotAllowed(http.HandlerFunc(handler.MethodNotAllowed))

	components, err := s.buildAuthComponents(client)
	if err != nil {
		return nil, err
	}

	if err := s.configureExchangeRouter(components.authenticator); err != nil {
		return nil, err
	}

	passportAuthorizer, err := buildPassportAuthorizer(components.issuer, components.uniAuthorizer, components.authenticator)
	if err != nil {
		return nil, err
	}

	validator := openapimiddleware.NewValidator(&s.OpenAPIOptions, passportAuthorizer)
	audit := audit.New(constants.Application, constants.Version)

	// Middleware specified here is applied to all requests post-routing.
	// NOTE: these are applied in reverse order!!
	chiServerOptions := openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares: []openapi.MiddlewareFunc{
			audit.Middleware,
			validator.Middleware,
		},
	}

	handlerInterface, err := handler.New(client, directclient, s.CoreOptions.Namespace, components.issuer, components.authenticator, components.userdb, components.rbac, &s.HandlerOptions)
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Addr:              s.ServerOptions.ListenAddress,
		ReadTimeout:       s.ServerOptions.ReadTimeout,
		ReadHeaderTimeout: s.ServerOptions.ReadHeaderTimeout,
		WriteTimeout:      s.ServerOptions.WriteTimeout,
		Handler:           openapi.HandlerWithOptions(handlerInterface, chiServerOptions),
	}

	return server, nil
}

func (s *Server) buildAuthComponents(client client.Client) (*authComponents, error) {
	issuer := jose.NewJWTIssuer(client, s.CoreOptions.Namespace, &s.JoseOptions)
	if err := issuer.Run(context.TODO(), &jose.InClusterCoordinationClientGetter{}); err != nil {
		return nil, err
	}

	userDatabase := userdb.NewUserDatabase(client, s.CoreOptions.Namespace)
	rbacClient := rbac.New(client, s.CoreOptions.Namespace, &s.RBACOptions)
	authenticator := oauth2.New(&s.OAuth2Options, s.CoreOptions.Namespace, s.HandlerOptions.Issuer, client, issuer, userDatabase, rbacClient)

	return &authComponents{
		issuer:        issuer,
		userdb:        userDatabase,
		rbac:          rbacClient,
		authenticator: authenticator,
		uniAuthorizer: local.NewAuthorizer(authenticator, rbacClient),
	}, nil
}

func (s *Server) configureExchangeRouter(authenticator *oauth2.Authenticator) error {
	detector := exchange.NewSourceDetector(s.HandlerOptions.Issuer.URL, s.Auth0Options.Issuer)
	uniTokenValidator := exchange.NewUNITokenValidator(authenticator)

	var auth0TokenValidator exchange.TokenValidator

	if s.Auth0Options.Enabled() {
		httpClient := &http.Client{Timeout: s.Auth0Options.EffectiveJWKSHTTPTimeout()}

		keySource := auth0.NewCachedHTTPKeySource(
			httpClient,
			s.Auth0Options.EffectiveJWKSURL(),
			s.Auth0Options.EffectiveJWKSCacheTTL(),
		)

		verifier, err := auth0.NewVerifier(keySource, &s.Auth0Options)
		if err != nil {
			return err
		}

		auth0TokenValidator = exchange.NewAuth0TokenValidator(verifier, false)

		if s.Auth0Options.OpaqueFallbackEnabled {
			userinfoVerifier, err := auth0.NewUserinfoVerifier(httpClient, &s.Auth0Options)
			if err != nil {
				return err
			}

			auth0OpaqueTokenValidator := exchange.NewAuth0TokenValidator(userinfoVerifier, true)

			authenticator.ConfigureAuth0OpaqueFallback(auth0OpaqueTokenValidator)
		}
	}

	exchangeRouter, err := exchange.NewRouter(detector, uniTokenValidator, auth0TokenValidator)
	if err != nil {
		return err
	}

	authenticator.ConfigureExchangeRouter(detector, exchangeRouter)

	return nil
}

func buildPassportAuthorizer(issuer *jose.JWTIssuer, uniAuthorizer *local.Authorizer, authenticator *oauth2.Authenticator) (*passport.Authorizer, error) {
	verifier := passport.NewVerifier(passport.NewLocalKeySource(issuer))
	tokenExchange := passport.NewLocalTokenExchange(authenticator)

	return passport.NewAuthorizer(verifier, uniAuthorizer, tokenExchange)
}
