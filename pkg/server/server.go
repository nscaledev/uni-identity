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
	"fmt"
	"net/http"

	chi "github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/logging"
	"github.com/unikorn-cloud/core/pkg/server/middleware/opentelemetry"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
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

	// CORSOptions are for remote resource sharing.
	CORSOptions cors.Options

	// RBACOptions are for RBAC related things.
	RBACOptions rbac.Options

	// OpenAPIOptions are for OpenAPI processing.
	OpenAPIOptions openapimiddleware.Options
}

func (s *Server) AddFlags(flags *pflag.FlagSet) {
	s.CoreOptions.AddFlags(flags)
	s.ServerOptions.AddFlags(flags)
	s.HandlerOptions.AddFlags(flags)
	s.JoseOptions.AddFlags(flags)
	s.OAuth2Options.AddFlags(flags)
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

	// Setup authn/authz
	issuer := jose.NewJWTIssuer(client, s.CoreOptions.Namespace, &s.JoseOptions)
	if err := issuer.Run(context.TODO(), &jose.InClusterCoordinationClientGetter{}); err != nil {
		return nil, err
	}

	userdb := userdb.NewUserDatabase(client, s.CoreOptions.Namespace)
	rbac := rbac.New(client, s.CoreOptions.Namespace, &s.RBACOptions)
	oauth2, err := oauth2.New(&s.OAuth2Options, s.CoreOptions.Namespace, s.HandlerOptions.Issuer, client, issuer, userdb, rbac)

	if err != nil {
		return nil, err
	}

	// Startup migration gate: validate the RBAC admin list against the set of
	// trusted non-UNI issuers known at startup. This is advisory — runtime CRD
	// creation bypasses it; the issuer-aware match in validatorForIssuer is the
	// real control — but it catches the most common misconfiguration (bare admin
	// entry added before migrating to issuer::subject format) before the server
	// accepts traffic.
	trustedNonUNIIssuers := computeTrustedNonUNIIssuers(context.TODO(), client, s.CoreOptions.Namespace, s.OAuth2Options.Auth0ExchangeIssuer)

	if err := s.RBACOptions.Validate(trustedNonUNIIssuers); err != nil {
		return nil, fmt.Errorf("startup migration gate: %w", err)
	}

	// Setup middleware.
	authorizer := local.NewAuthorizer(oauth2, rbac)
	validator := openapimiddleware.NewValidator(&s.OpenAPIOptions, authorizer)
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

	handlerInterface, err := handler.New(client, directclient, s.CoreOptions.Namespace, issuer, oauth2, userdb, rbac, &s.HandlerOptions)
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

// computeTrustedNonUNIIssuers returns the issuers (verbatim) of all
// BearerTrust-enabled OAuth2Providers in the identity namespace, plus the
// legacy Auth0 flag issuer if set, minus the UNI sentinel. The result is
// used by the startup migration gate only; the runtime issuer-match in
// validatorForIssuer is the real control.
//
// A List failure (e.g. informer cache not yet warm) is treated as non-fatal:
// the gate is skipped and returns an empty slice so startup is not blocked.
// The runtime validatorForIssuer call is the real gate.
func computeTrustedNonUNIIssuers(ctx context.Context, cli client.Client, namespace, auth0LegacyIssuer string) []string {
	var providers unikornv1.OAuth2ProviderList

	if err := cli.List(ctx, &providers, &client.ListOptions{Namespace: namespace}); err != nil {
		return nil
	}

	seen := make(map[string]struct{})

	var result []string

	add := func(raw string) {
		if raw == "" || raw == constants.UNISentinel {
			return
		}

		if _, ok := seen[raw]; ok {
			return
		}

		seen[raw] = struct{}{}

		result = append(result, raw)
	}

	for i := range providers.Items {
		p := &providers.Items[i]

		if p.Spec.BearerTrust != nil && p.Namespace == namespace {
			add(p.Spec.Issuer)
		}
	}

	if auth0LegacyIssuer != "" {
		add(auth0LegacyIssuer)
	}

	return result
}
