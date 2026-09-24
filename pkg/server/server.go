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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	chi "github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/logging"
	"github.com/unikorn-cloud/core/pkg/server/middleware/opentelemetry"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/openapi/enclave"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// storeVersionSchema is the only marker schema this build understands.  A
	// future publisher that changes the shape bumps it, and an older pod then
	// refuses rather than guessing.
	storeVersionSchema = 1

	// maxStoreVersionBytes bounds the marker read.
	maxStoreVersionBytes = 4 << 10

	// storeStateValid and storeStateWithdrawn mirror the two states the
	// policy controller publishes (pkg/authz/cerbos/controller).
	storeStateValid     = "valid"
	storeStateWithdrawn = "withdrawn"
)

// ErrStoreVersion is returned when the publication marker is present but not
// something this build is willing to act on.
var ErrStoreVersion = errors.New("invalid policy store version marker")

type Server struct {
	// CoreOptions are all common across everything e.g. namespace.
	CoreOptions options.CoreOptions

	// ServerOptions are server specific options e.g. listener address etc.
	ServerOptions options.ServerOptions

	// APIProfile selects which HTTP surface GetServer mounts: the full API,
	// or (for an enclave) only the read-only authorization surface. It is a
	// field on Server rather than on ServerOptions because ServerOptions is
	// core's shared type, and adding a field there is out of scope here.
	APIProfile APIProfile

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

	// CerbosOptions configure the client for the Cerbos PDP sidecar.
	CerbosOptions cerbos.Options

	// OpenAPIOptions are for OpenAPI processing.
	OpenAPIOptions openapimiddleware.Options

	// Cerbos is the client for the Cerbos PDP sidecar; consumers arrive
	// with the authorization decision layer.
	Cerbos *cerbos.Client

	// ReadinessPolicyDirectory is the mounted policy projection an enclave
	// must observe before it may receive authorization traffic. The enclave
	// readiness endpoint fails closed when this is empty.
	ReadinessPolicyDirectory string
}

func (s *Server) AddFlags(flags *pflag.FlagSet) {
	s.CoreOptions.AddFlags(flags)
	s.ServerOptions.AddFlags(flags)
	s.APIProfile = APIProfileFull
	flags.Var(&s.APIProfile, "api-profile", "HTTP surface to serve: full (the whole API) or authorization (the read-only authorization surface only, for an enclave).")
	s.HandlerOptions.AddFlags(flags)
	s.JoseOptions.AddFlags(flags)
	s.OAuth2Options.AddFlags(flags)
	s.CORSOptions.AddFlags(flags)
	s.RBACOptions.AddFlags(flags)
	s.CerbosOptions.AddFlags(flags)
	s.OpenAPIOptions.AddFlags(flags)
	flags.StringVar(&s.ReadinessPolicyDirectory, "readiness-policy-directory", "", "Directory of the projected policy store. The readiness endpoint of the authorization profile succeeds only when this directory contains a .store-version marker with a known schema and state.")
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

	if err := s.runIssuer(issuer); err != nil {
		return nil, err
	}

	userdb := userdb.NewUserDatabase(client, s.CoreOptions.Namespace)

	// On main, bare admin entries matched from any authentication path. Mirror
	// them onto the legacy Auth0 issuer so both pre-existing paths (UNI login,
	// Auth0 exchange) keep matching; bare entries can never match a
	// CRD-declared issuer, so this preserves behaviour without widening trust.
	// Ordering invariant: this MUST run before rbac.New and before the
	// migration warning below — were the warning evaluated first, or the
	// expansion dropped while the gate stays advisory, Auth0-path admins would
	// silently lose access with no loud signal. Remove together with the
	// deprecated auth0-exchange flags.
	s.RBACOptions.PlatformAdministratorSubjects = expandBareAdminSubjects(s.RBACOptions.PlatformAdministratorSubjects, s.OAuth2Options.Auth0ExchangeIssuer)

	// The Cerbos PDP client is lazy: no connection is attempted until the
	// first RPC, so construction is safe before the sidecar is ready (an
	// eager connectivity check here would race the pod's own sidecar;
	// readiness is the sidecar health probe's job).  It backs the decision
	// API (rbac.Check/CheckMany); enforcement call sites migrate to that
	// API through the dual-path Allow* facade.
	cerbosClient, err := cerbos.New(&s.CerbosOptions)
	if err != nil {
		return nil, err
	}

	s.Cerbos = cerbosClient

	rbac := rbac.New(client, s.CoreOptions.Namespace, &s.RBACOptions).WithCerbos(cerbosClient)

	// Key the coarse-decision cache on the policy-store hash so a controller
	// republish busts every cached verdict.  The hasher reads the
	// controller-owned policies ConfigMap through the DIRECT (uncached)
	// client: a cache-backed client would spin up a cluster-wide ConfigMap
	// informer the chart's narrow `get` grant forbids — the same reason the
	// policy controller reads uncached.  An unset ConfigMap name leaves the
	// hasher off, so the cache stays inert (safe default).
	if s.CerbosOptions.PoliciesConfigMap != "" {
		hasher := cerbos.NewPolicyStoreHasher(directclient, s.CoreOptions.Namespace, s.CerbosOptions.PoliciesConfigMap, s.RBACOptions.DecisionCacheTimeout)
		rbac = rbac.WithPolicyStoreHash(hasher)
	}

	oauth2, err := oauth2.New(&s.OAuth2Options, s.CoreOptions.Namespace, s.HandlerOptions.Issuer, client, issuer, userdb, rbac)

	if err != nil {
		return nil, err
	}

	// Advisory only: warn, don't block boot. Issuer-qualified matching is the
	// runtime control, and a hard failure here would fire at an unrelated pod
	// restart long after the first bearerTrust CRD was created.
	//
	// The groups-claim map is fetched only after the issuer list proves usable: a
	// fetch after issuersErr already failed would be wasted work, because every
	// check below needs trustedNonUNIIssuers. A later GroupsClaimByIssuer failure
	// skips only the group-binding check that consumes the map, and Validate
	// still runs with a nil map, so the subject-binding advisory keeps working.
	// Validate treats nil differently from an empty-but-successful map, so it
	// never reads a failed fetch as "no dead bindings".
	trustedNonUNIIssuers, issuersErr := computeTrustedNonUNIIssuers(context.TODO(), client, s.CoreOptions.Namespace)

	if issuersErr != nil {
		log.FromContext(context.TODO()).Info("rbac options advisory check skipped: provider list unavailable", "error", issuersErr)
	} else {
		groupsClaimByIssuer, claimsErr := oauth2.GroupsClaimByIssuer(context.TODO())
		if claimsErr != nil {
			log.FromContext(context.TODO()).Info("group role binding advisory check skipped: groups claim map unavailable", "error", claimsErr)
		}

		if err := s.RBACOptions.Validate(trustedNonUNIIssuers, groupsClaimByIssuer); err != nil {
			log.FromContext(context.TODO()).Info("rbac options advisory check failed", "error", err)
		}
	}

	// Setup middleware.
	authorizer := local.NewAuthorizer(oauth2, rbac)
	validator := openapimiddleware.NewValidator(&s.OpenAPIOptions, authorizer)
	audit := audit.New(constants.Application, constants.Version)

	// Middleware specified here is applied to all requests post-routing.
	// NOTE: these are applied in reverse order!!
	middlewares := []func(http.Handler) http.Handler{
		audit.Middleware,
		validator.Middleware,
	}

	handlerInterface, err := handler.New(client, directclient, s.CoreOptions.Namespace, issuer, oauth2, userdb, rbac, &s.HandlerOptions)
	if err != nil {
		return nil, err
	}

	log.FromContext(context.TODO()).Info("serving API surface", "profile", s.APIProfile)

	serverHandler := s.mountReadiness(mountAPI(s.APIProfile, handlerInterface, router, handler.HandleError, middlewares))

	server := &http.Server{
		Addr:              s.ServerOptions.ListenAddress,
		ReadTimeout:       s.ServerOptions.ReadTimeout,
		ReadHeaderTimeout: s.ServerOptions.ReadHeaderTimeout,
		WriteTimeout:      s.ServerOptions.WriteTimeout,
		Handler:           serverHandler,
	}

	return server, nil
}

// storeVersionFile is the publication marker the policy controller writes into
// every policy store (pkg/authz/cerbos/controller).  It is the only thing that
// distinguishes a store the controller deliberately withdrew, which is a valid
// deny-all state, from one that was never published.  Both project as a
// directory with no policy document in it.
const storeVersionFile = ".store-version"

// storeVersionMarker is the publication state the controller recorded.
type storeVersionMarker struct {
	Schema uint64 `json:"schema"`
	State  string `json:"state"`
}

// policyProjectionReadiness reports whether this pod has observed a policy
// publication.  Cerbos is healthy with an empty policy directory and would
// answer deny for everything, so a pod must not join the Service before the
// controller has published once.
//
// It gates on the marker rather than on the presence of policy files, and that
// distinction is the whole point: a withdrawal publishes no policy document,
// so a file-counting gate would hold every replacement pod out of service for
// as long as the withdrawal lasted, turning one malformed Role into lost
// capacity on the next eviction or rollout.  Both marker states answer ready:
// "valid" because the store is serving, "withdrawn" because deny-all is a
// deliberate, published state that this pod is serving correctly.
//
// The marker is opened fresh on every probe so the path resolves through the
// kubelet's current ..data snapshot; a retained descriptor would pin a
// superseded projection.
func policyProjectionReadiness(directory string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if directory == "" {
			http.Error(w, "policy projection is not configured", http.StatusServiceUnavailable)

			return
		}

		if err := publishedStoreVersion(filepath.Join(directory, storeVersionFile)); err != nil {
			http.Error(w, "policy publication not observed", http.StatusServiceUnavailable)

			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// publishedStoreVersion reads and validates the marker.  The read is bounded:
// this runs on a kubelet probe against a file a controller writes, so it must
// not be able to consume the pod's memory if that file is ever wrong.
//
// Validation stays deliberately thin.  Readiness is fleet-wide, so every
// field checked here is a field a publisher bug could use to take every
// replica out of service at once.
func publishedStoreVersion(path string) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}

	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxStoreVersionBytes))
	if err != nil {
		return err
	}

	marker := &storeVersionMarker{}
	if err := json.Unmarshal(data, marker); err != nil {
		return err
	}

	if marker.Schema != storeVersionSchema {
		return fmt.Errorf("%w: schema %d", ErrStoreVersion, marker.Schema)
	}

	if marker.State != storeStateValid && marker.State != storeStateWithdrawn {
		return fmt.Errorf("%w: state %q", ErrStoreVersion, marker.State)
	}

	return nil
}

// mountReadiness fronts the API handler with /readyz for the authorization
// profile, which is the only profile that gates on a policy projection.  Every
// other profile is returned unchanged.
//
// Separated from GetServer, like mountAPI below, so the profile branch is
// unit-testable without a cluster.
func (s *Server) mountReadiness(handler http.Handler) http.Handler {
	if s.APIProfile != APIProfileAuthorization {
		return handler
	}

	root := chi.NewRouter()
	root.Get("/readyz", policyProjectionReadiness(s.ReadinessPolicyDirectory))
	root.Mount("/", handler)

	return root
}

// runIssuer starts the JOSE signing-key issuer's certificate management loop,
// unless the profile is APIProfileAuthorization.  That profile issues no
// tokens, so it never needs the loop; Run also starts leader election on a
// coordination.k8s.io Lease, which the authorization profile's ClusterRole
// does not grant on purpose (it is read-only on replicated identity state)
// -- starting it there would fail soft and log a permanent stream of
// forbidden errors.  The issuer is still constructed by the caller either
// way: handler.New takes it, even though the authorization profile's own
// handlers never call into it.  Separated from GetServer, like mountAPI
// below, so the profile branch is unit-testable without a cluster.
func (s *Server) runIssuer(issuer *jose.JWTIssuer) error {
	if s.APIProfile == APIProfileAuthorization {
		return nil
	}

	return issuer.Run(context.TODO(), &jose.InClusterCoordinationClientGetter{})
}

// mountAPI builds the HTTP handler for the configured profile.  It is
// separated from GetServer so the served route set is unit-testable without
// a cluster: the profile decision is a security boundary and must be pinned
// by a test that inspects the mux, not by an integration probe.
//
// Anything other than APIProfileAuthorization mounts the full API. Options
// is constructed directly by tests and possibly by other consumers, without
// AddFlags, so profile can hold the zero value "". The full API is the safe
// default: it is what every profile-unaware deployment already runs, so a
// zero value must resolve there rather than to an error or an empty mux.
// This mirrors RBAC.mode() in pkg/rbac/engine.go, which treats any
// unrecognised engine value as legacy.
func mountAPI(profile APIProfile, handlerInterface openapi.ServerInterface, router chi.Router, errorHandler func(http.ResponseWriter, *http.Request, error), middlewares []func(http.Handler) http.Handler) http.Handler {
	if profile == APIProfileAuthorization {
		options := enclave.ChiServerOptions{
			BaseRouter:       router,
			ErrorHandlerFunc: errorHandler,
		}

		for _, middleware := range middlewares {
			options.Middlewares = append(options.Middlewares, enclave.MiddlewareFunc(middleware))
		}

		return enclave.HandlerWithOptions(handlerInterface, options)
	}

	options := openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: errorHandler,
	}

	for _, middleware := range middlewares {
		options.Middlewares = append(options.Middlewares, openapi.MiddlewareFunc(middleware))
	}

	return openapi.HandlerWithOptions(handlerInterface, options)
}

// expandBareAdminSubjects mirrors bare (UNI-sentinel) admin entries onto the
// legacy Auth0 issuer, reproducing the issuer-unaware matching that existed
// before entries were issuer-qualified. The mirror is a concrete
// issuer-qualified entry for an already-trusted issuer, so it grants nothing
// that the old issuer-blind match didn't; CRD-declared issuers are never
// added.
func expandBareAdminSubjects(subjects []rbac.PlatformAdministratorSubject, legacyIssuer string) []rbac.PlatformAdministratorSubject {
	if legacyIssuer == "" || legacyIssuer == constants.UNISentinel {
		return subjects
	}

	// Safe to append while ranging: range captures the slice header once.
	for _, s := range subjects {
		if s.Issuer == constants.UNISentinel {
			subjects = append(subjects, rbac.PlatformAdministratorSubject{Issuer: legacyIssuer, Subject: s.Subject})
		}
	}

	return subjects
}

// computeTrustedNonUNIIssuers returns the issuers (verbatim) of all
// BearerTrust-enabled OAuth2Providers in the identity namespace, minus the
// UNI sentinel. The legacy Auth0 flag issuer is deliberately excluded:
// expandBareAdminSubjects already mirrors bare admin entries onto it, so its
// presence alone leaves nothing to migrate.
//
// A List failure (e.g. informer cache not yet warm) is returned as an error
// so the caller can skip the advisory check rather than mistake it for a
// genuinely empty trusted-issuer list.
func computeTrustedNonUNIIssuers(ctx context.Context, cli client.Client, namespace string) ([]string, error) {
	var providers unikornv1.OAuth2ProviderList

	if err := cli.List(ctx, &providers, &client.ListOptions{Namespace: namespace}); err != nil {
		return nil, err
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

	return result, nil
}
