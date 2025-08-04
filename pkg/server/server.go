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
	"flag"
	"net/http"

	chi "github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/unikorn-cloud/core/pkg/manager/otel"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/opentelemetry"
	"github.com/unikorn-cloud/core/pkg/server/middleware/timeout"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	klog "k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type Server struct {
	// Options are server specific options e.g. listener address etc.
	Options Options

	// ZapOptions configure logging.
	ZapOptions zap.Options

	// HandlerOptions sets options for the HTTP handler.
	HandlerOptions handler.Options

	// JoseOptions sets options for JWE.
	JoseOptions jose.Options

	// OAuth2Options sets options for the oauth2/oidc authenticator.
	OAuth2Options oauth2.Options

	// CORSOptions are for remote resource sharing.
	CORSOptions cors.Options

	// OTelOptions are for tracing.
	OTelOptions otel.Options

	// RBACOptions are for RBAC related things.
	RBACOptions rbac.Options
}

func (s *Server) AddFlags(goflags *flag.FlagSet, flags *pflag.FlagSet) {
	s.ZapOptions.BindFlags(goflags)

	s.Options.AddFlags(flags)
	s.HandlerOptions.AddFlags(flags)
	s.JoseOptions.AddFlags(flags)
	s.OAuth2Options.AddFlags(flags)
	s.CORSOptions.AddFlags(flags)
	s.OTelOptions.AddFlags(flags)
	s.RBACOptions.AddFlags(flags)
}

func (s *Server) SetupLogging() {
	logr := zap.New(zap.UseFlagOptions(&s.ZapOptions))

	klog.SetLogger(logr)
	log.SetLogger(logr)
}

func (s *Server) SetupOpenTelemetry(ctx context.Context) error {
	return s.OTelOptions.Setup(ctx, trace.WithSpanProcessor(&opentelemetry.LoggingSpanProcessor{}))
}

func (s *Server) GetServer(client client.Client) (*http.Server, error) {
	schema, err := coreapi.NewSchema(openapi.GetSwagger)
	if err != nil {
		return nil, err
	}

	// Middleware specified here is applied to all requests pre-routing.
	router := chi.NewRouter()
	router.Use(timeout.Middleware(s.Options.RequestTimeout))
	router.Use(opentelemetry.Middleware(constants.Application, constants.Version))
	router.Use(cors.Middleware(schema, &s.CORSOptions))
	router.NotFound(http.HandlerFunc(handler.NotFound))
	router.MethodNotAllowed(http.HandlerFunc(handler.MethodNotAllowed))

	// Setup authn/authz
	issuer := jose.NewJWTIssuer(client, s.Options.Namespace, &s.JoseOptions)
	if err := issuer.Run(context.TODO(), &jose.InClusterCoordinationClientGetter{}); err != nil {
		return nil, err
	}

	r := rbac.New(client, s.Options.Namespace, &s.RBACOptions)
	pdp := rbac.NewLocalPDP(r)
	oauth2 := oauth2.New(&s.OAuth2Options, s.Options.Namespace, client, issuer, r)

	// Middleware specified here is applied to all requests post-routing.
	// NOTE: these are applied in reverse order!!
	chiServerOptions := openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares: []openapi.MiddlewareFunc{
			audit.Middleware(schema, constants.Application, constants.Version),
			openapimiddleware.Middleware(schema),
		},
	}

	handlerInterface, err := handler.New(client, s.Options.Namespace, issuer, oauth2, r, pdp, &s.HandlerOptions)
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Addr:              s.Options.ListenAddress,
		ReadTimeout:       s.Options.ReadTimeout,
		ReadHeaderTimeout: s.Options.ReadHeaderTimeout,
		WriteTimeout:      s.Options.WriteTimeout,
		Handler:           openapi.HandlerWithOptions(handlerInterface, chiServerOptions),
	}

	return server, nil
}
