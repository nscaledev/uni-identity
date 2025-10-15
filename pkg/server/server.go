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

package server

import (
	"context"
	"net/http"

	chi "github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel/sdk/trace"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/opentelemetry"
	"github.com/unikorn-cloud/core/pkg/server/middleware/timeout"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/common"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/hybrid"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
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

	// ClientOptions are for generic TLS client options e.g. certificates.
	ClientOptions coreclient.HTTPClientOptions

	// ExternalOIDCOptions specifies an external OIDC platform to use for authentication.
	ExternalOIDCOptions *identityclient.Options
}

func (s *Server) AddFlags(flags *pflag.FlagSet) {
	s.CoreOptions.AddFlags(flags)
	s.ServerOptions.AddFlags(flags)
	s.HandlerOptions.AddFlags(flags)
	s.JoseOptions.AddFlags(flags)
	s.OAuth2Options.AddFlags(flags)
	s.CORSOptions.AddFlags(flags)
	s.RBACOptions.AddFlags(flags)
	s.ClientOptions.AddFlags(flags)

	if s.ExternalOIDCOptions == nil {
		s.ExternalOIDCOptions = identityclient.NewExternalOptions()
	}
	s.ExternalOIDCOptions.AddFlags(flags)
}

func (s *Server) SetupLogging() {
	s.CoreOptions.SetupLogging()
}

func (s *Server) SetupOpenTelemetry(ctx context.Context) error {
	return s.CoreOptions.SetupOpenTelemetry(ctx, trace.WithSpanProcessor(&opentelemetry.LoggingSpanProcessor{}))
}

func (s *Server) GetServer(client client.Client) (*http.Server, error) {
	schema, err := coreapi.NewSchema(openapi.GetSwagger)
	if err != nil {
		return nil, err
	}

	// Middleware specified here is applied to all requests pre-routing.
	router := chi.NewRouter()
	router.Use(timeout.Middleware(s.ServerOptions.RequestTimeout))
	router.Use(opentelemetry.Middleware(constants.Application, constants.Version))
	router.Use(cors.Middleware(schema, &s.CORSOptions))
	router.NotFound(http.HandlerFunc(handler.NotFound))
	router.MethodNotAllowed(http.HandlerFunc(handler.MethodNotAllowed))

	// Setup authn/authz
	issuer := jose.NewJWTIssuer(client, s.CoreOptions.Namespace, &s.JoseOptions)
	if err := issuer.Run(context.TODO(), &jose.InClusterCoordinationClientGetter{}); err != nil {
		return nil, err
	}

	userdb := userdb.NewUserDatabase(client, s.CoreOptions.Namespace)
	rbac := rbac.New(client, s.CoreOptions.Namespace, &s.RBACOptions)
	oauth2 := oauth2.New(&s.OAuth2Options, s.CoreOptions.Namespace, client, issuer, userdb, rbac)

	// Setup middleware.
	var authorizer openapimiddleware.Authorizer

	if s.ExternalOIDCOptions.Host() == "" { // External OIDC has not been provided
		// Fallback to local-only for now
		authorizer = local.NewAuthorizer(oauth2, rbac)
	} else { // External OIDC has been provided
		remoteAuth := remote.NewAuthenticator(client, s.ExternalOIDCOptions, &s.ClientOptions)
		localAuth := local.NewAuthenticator(oauth2)
		detector := &common.TokenDetector{
			ExternalIssuer: s.ExternalOIDCOptions.Host(),
			LocalIssuer:    s.HandlerOptions.Host,
		}
		authorizer = hybrid.NewAuthorizer(localAuth, remoteAuth, detector, rbac)
	}

	// Middleware specified here is applied to all requests post-routing.
	// NOTE: these are applied in reverse order!!
	chiServerOptions := openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares: []openapi.MiddlewareFunc{
			audit.Middleware(schema, constants.Application, constants.Version),
			openapimiddleware.Middleware(authorizer, schema),
		},
	}

	handlerInterface, err := handler.New(client, s.CoreOptions.Namespace, issuer, oauth2, userdb, rbac, &s.HandlerOptions)
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
