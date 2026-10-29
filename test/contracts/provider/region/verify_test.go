//go:build integration

/*
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

package region_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	chi "github.com/go-chi/chi/v5"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"github.com/pact-foundation/pact-go/v2/models"
	"github.com/pact-foundation/pact-go/v2/provider"
	"github.com/spf13/pflag"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"
	"github.com/unikorn-cloud/identity/test/api"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	testingT *testing.T //nolint:gochecknoglobals
)

func TestContracts(t *testing.T) {
	t.Parallel()
	testingT = t

	RegisterFailHandler(Fail)
	RunSpecs(t, "Identity Provider Contract Verification Suite")
}

var _ = Describe("Identity Provider Verification", func() {
	var (
		testServer     *http.Server
		serverURL      string
		ctx            context.Context
		cancel         context.CancelFunc
		k8sClient      client.Client
		stateManager   *StateManager
		handlerOptions *handler.Options
		jwtIssuer      *jose.JWTIssuer
		authenticator  *oauth2.Authenticator
		pactBrokerURL  string
		brokerUsername string
		brokerPassword string
	)

	BeforeEach(func() {
		//nolint:fatcontext
		ctx, cancel = context.WithCancel(context.Background())

		pactBrokerURL = os.Getenv("PACT_BROKER_URL")
		if pactBrokerURL == "" {
			pactBrokerURL = "http://localhost:9292"
		}
		brokerUsername = os.Getenv("PACT_BROKER_USERNAME")
		if brokerUsername == "" {
			brokerUsername = "pact"
		}
		brokerPassword = os.Getenv("PACT_BROKER_PASSWORD")
		if brokerPassword == "" {
			brokerPassword = "pact"
		}

		cfg, err := ctrl.GetConfig()
		Expect(err).NotTo(HaveOccurred())

		scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
		Expect(err).NotTo(HaveOccurred())

		k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
		Expect(err).NotTo(HaveOccurred())

		err = SetupBaseNamespace(ctx, k8sClient)
		Expect(err).NotTo(HaveOccurred())

		cleanupAllTestUserOrganizationUsers(ctx, k8sClient)

		stateManager = NewStateManager(k8sClient, TestNamespace)

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())

		addr, ok := listener.Addr().(*net.TCPAddr)
		Expect(ok).To(BeTrue(), "listener address should be a TCP address")
		port := addr.Port
		listener.Close()

		serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)

		handlerOptions = buildHandlerOptions(serverURL)

		jwtIssuer, authenticator, err = SetupTokenIssuer(ctx, k8sClient, handlerOptions.Issuer)
		Expect(err).NotTo(HaveOccurred())

		testServer = startTestServer(ctx, k8sClient, handlerOptions, jwtIssuer, authenticator, fmt.Sprintf("127.0.0.1:%d", port))

		Eventually(func() error {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
			if err != nil {
				return err
			}
			conn.Close()

			return nil
		}, 10*time.Second, 100*time.Millisecond).Should(Succeed())
	})

	AfterEach(func() {
		if testServer != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()

			_ = testServer.Shutdown(shutdownCtx)
		}
		cancel()
	})

	Describe("Verifying pacts from Pact Broker", func() {
		It("should verify all consumer contracts", func() {
			verifier := provider.NewVerifier()
			stateHandlers := createStateHandlers(ctx, stateManager, authenticator, handlerOptions.Issuer)

			// Build base selectors for normal CI verification
			selectors := []provider.Selector{
				&provider.ConsumerVersionSelector{Consumer: "uni-compute", MainBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "uni-compute", MatchingBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "uni-kubernetes", MainBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "uni-kubernetes", MatchingBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "uni-region", MainBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "uni-region", MatchingBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "nscale-environments", MainBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "nscale-environments", MatchingBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "ai-gateway", MainBranch: true},
				&provider.ConsumerVersionSelector{Consumer: "ai-gateway", MatchingBranch: true},
			}

			// Add explicit branch selector only for webhook-triggered verification
			consumerBranch := strings.TrimSpace(os.Getenv("CONSUMER_BRANCH"))
			if consumerBranch != "" {
				selectors = append(selectors,
					&provider.ConsumerVersionSelector{Consumer: "uni-compute", Branch: consumerBranch},
					&provider.ConsumerVersionSelector{Consumer: "uni-kubernetes", Branch: consumerBranch},
					&provider.ConsumerVersionSelector{Consumer: "uni-region", Branch: consumerBranch},
					&provider.ConsumerVersionSelector{Consumer: "nscale-environments", Branch: consumerBranch},
					&provider.ConsumerVersionSelector{Consumer: "ai-gateway", Branch: consumerBranch},
				)
				fmt.Printf("Webhook mode: Including explicit branch selector for consumer branch '%s'\n", consumerBranch)
			} else {
				fmt.Printf("Normal mode: Using MainBranch and MatchingBranch selectors only\n")
			}

			request := func(selectors []provider.Selector, pending bool) provider.VerifyRequest {
				return provider.VerifyRequest{
					ProviderBaseURL:            serverURL,
					Provider:                   "uni-identity",
					BrokerURL:                  pactBrokerURL,
					BrokerUsername:             brokerUsername,
					BrokerPassword:             brokerPassword,
					PublishVerificationResults: os.Getenv("CI") == "true" || os.Getenv("PUBLISH_VERIFICATION") == "true",
					ProviderVersion:            getProviderVersion(),
					ProviderBranch:             getProviderBranch(),
					ConsumerVersionSelectors:   selectors,
					EnablePending:              pending,
					StateHandlers:              stateHandlers,
					RequestFilter:              envirRequestFilter,
				}
			}

			err := verifier.VerifyProvider(testingT, request(selectors, true))
			Expect(err).NotTo(HaveOccurred(), "Provider verification should succeed")

			// Envir's released versions are verified without pending, so breaking one fails this build:
			// under pending, a pact that has never verified green stays pending, and the build passes
			// however its interactions fail. Envir's main stays pending above: its can-i-deploy runs after
			// Envir's CI, from workflow_run, and gates no Envir merge, so a main pact this provider can't
			// serve yet would otherwise fail every build here. The selector matches whatever Envir has
			// recorded as released and still supported; until Envir records releases it matches nothing.
			strict := []provider.Selector{
				&provider.ConsumerVersionSelector{Consumer: "nscale-environments", DeployedOrReleased: true},
			}

			err = provider.NewVerifier().VerifyProvider(testingT, request(strict, false))
			Expect(err).NotTo(HaveOccurred(), "Envir's supported releases must verify")
		})
	})

	Describe("Verifying pacts from local files", func() {
		It("should verify local pact files", func() {
			pactFile := os.Getenv("PACT_FILE")
			if pactFile == "" {
				Skip("PACT_FILE environment variable not set, skipping local file verification")
			}

			verifier := provider.NewVerifier()

			stateHandlers := createStateHandlers(ctx, stateManager, authenticator, handlerOptions.Issuer)

			err := verifier.VerifyProvider(testingT, provider.VerifyRequest{
				ProviderBaseURL: serverURL,
				Provider:        "uni-identity",
				PactFiles:       []string{pactFile},
				StateHandlers:   stateHandlers,
				RequestFilter:   envirRequestFilter,
			})

			Expect(err).NotTo(HaveOccurred(), "Provider verification should succeed")
		})
	})
})

func createStateHandlers(ctx context.Context, stateManager *StateManager, authenticator *oauth2.Authenticator, issuer common.IssuerValue) models.StateHandlers {
	automation := func(name string) models.StateHandler {
		return func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleAutomationIdentity(ctx, name, setup, state.Parameters)
		}
	}

	return models.StateHandlers{
		StateCallerHasProjectAccess: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleCallerHasProjectAccess(ctx, setup, state.Parameters, authenticator, issuer)
		},
		StateServiceAccountBearer: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleServiceAccountBearer(ctx, setup, state.Parameters, authenticator, issuer)
		},
		StateUserBearer: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleUserBearer(ctx, setup, state.Parameters, authenticator, issuer)
		},
		StateSystemBearer: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleSystemBearer(ctx, setup, state.Parameters, authenticator, issuer)
		},
		StatePublicCloudOrgUser: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandlePublicCloudOrgUser(ctx, setup, state.Parameters, authenticator, issuer)
		},
		StateExpiredBearer: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleExpiredBearer(ctx, setup, state.Parameters, authenticator, issuer)
		},
		StateOrganizationNoProject: func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleOrganizationWithoutProject(ctx, setup, state.Parameters)
		},
		StateNoAutomationIdentity:   automation(StateNoAutomationIdentity),
		StateAutomationGroupOnly:    automation(StateAutomationGroupOnly),
		StateAutomationAccountBound: automation(StateAutomationAccountBound),
		"project exists": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleProjectExists(ctx, setup, state.Parameters)
		},
		"allocation exists": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleAllocationExists(ctx, setup, state.Parameters)
		},
	}
}

// buildHandlerOptions creates handler options for the test server.
// It parses the server's own flags so every tunable, such as the service account token
// lifetime, takes its production default.
func buildHandlerOptions(serverURL string) *handler.Options {
	options := &handler.Options{}

	flags := pflag.NewFlagSet("contract-test", pflag.PanicOnError)
	options.AddFlags(flags)

	if err := flags.Parse([]string{"--host", serverURL, "--cache-max-age", "0s"}); err != nil {
		panic(fmt.Sprintf("failed to parse handler options: %v", err))
	}

	return options
}

// envirExampleBearer is the bearer Envir's and ai-gateway's pacts send on userinfo, the ACL and the
// organization list; it is never a token.
const envirExampleBearer = "Bearer user-access-token" //nolint:gosec // the pact's placeholder, not a credential

// envirRequestFilter does what sits in front of uni-identity in production for Envir's requests:
// it presents the token the provider state issued on userinfo, the ACL and the organization list, and on a
// client_credentials grant it adds the client certificate headers the ingress forwards after
// verifying Envir's mTLS certificate. The token endpoint looks up no registered client: production
// trusts the ingress's verification and takes the subject from the certificate's common name.
func envirRequestFilter(next http.Handler) http.Handler {
	endpoints := api.NewEndpoints()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case endpoints.GetUserinfo(), endpoints.GetGlobalACL(), endpoints.ListOrganizations():
			bearer := envirBearer.get()
			if bearer == "" && r.Header.Get("Authorization") == envirExampleBearer {
				// No Envir state issued a token, so the state didn't run; fail rather than let the
				// example bearer's rejection stand in for the interaction's real outcome.
				http.Error(w, "no Envir provider state issued a bearer", http.StatusInternalServerError)

				return
			}

			if bearer != "" {
				r.Header.Set("Authorization", "Bearer "+bearer)
			}
		case endpoints.Token():
			if isClientCredentialsGrant(r) {
				r.Header.Set("Ssl-Client-Cert", envirClientCertificate())
				r.Header.Set("Ssl-Client-Verify", "SUCCESS")
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isClientCredentialsGrant reads the form body and puts it back for the handler.
func isClientCredentialsGrant(r *http.Request) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}

	r.Body = io.NopCloser(bytes.NewReader(body))

	form, err := url.ParseQuery(string(body))

	return err == nil && form.Get("grant_type") == "client_credentials"
}

// createHandlerInterface creates the handler interface with minimal dependencies for contract testing.
func createHandlerInterface(k8sClient client.Client, handlerOptions *handler.Options, jwtIssuer *jose.JWTIssuer, authenticator *oauth2.Authenticator) openapi.ServerInterface {
	// The issuer and authenticator are real, so service account creation, the token endpoint,
	// userinfo and JWKS run as in production; the handlers' RBAC stays nil because
	// MockACLMiddleware, or EnvirACLMiddleware for Envir's /api/v1/acl, provides the ACL.
	handlerInterface, err := handler.New(
		k8sClient,
		k8sClient,
		TestNamespace,
		jwtIssuer,
		authenticator,
		// ai-gateway's organization list finds the caller's user here.
		userdb.NewUserDatabase(k8sClient, TestNamespace),
		nil, // RBAC not used in contract tests - MockACLMiddleware handles authorization
		handlerOptions,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create handler: %v", err))
	}

	return handlerInterface
}

// buildRouter creates and configures the chi router with middleware.
func buildRouter(schema *helpers.Schema, aclAuthorizer *local.Authorizer) *chi.Mux {
	router := chi.NewRouter()

	// Add route resolver middleware
	routeResolver := routeresolver.New(schema)
	router.Use(routeResolver.Middleware)

	// Mock ACL middleware allows all organizations for contract testing
	router.Use(MockACLMiddleware(nil)) // Inject mock ACL for contract testing
	router.Use(EnvirACLMiddleware(aclAuthorizer))

	return router
}

// buildChiServerOptions creates the chi server options for OpenAPI handler registration.
// Authorization middleware is skipped to allow Pact verification without real auth tokens.
func buildChiServerOptions(router *chi.Mux) openapi.ChiServerOptions {
	return openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares:      []openapi.MiddlewareFunc{
			// Authorization middleware is skipped for contract testing
		},
	}
}

// buildHTTPServer creates the HTTP server with configured timeouts.
func buildHTTPServer(listenAddr string, router *chi.Mux) *http.Server {
	return &http.Server{
		Addr:              listenAddr,
		Handler:           router,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
}

// startServerAsync starts the HTTP server in a background goroutine.
func startServerAsync(httpServer *http.Server) {
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Server error: %v\n", err)
		}
	}()
}

// startTestServer creates and starts a test instance of the identity server.
// Note: This is a simplified version for contract testing that uses MockACLMiddleware
// to bypass RBAC checks, reducing setup complexity and potential failure points.
func startTestServer(_ context.Context, k8sClient client.Client, handlerOptions *handler.Options, jwtIssuer *jose.JWTIssuer, authenticator *oauth2.Authenticator, listenAddr string) *http.Server {
	schema, err := helpers.NewSchema(openapi.GetSwagger)
	if err != nil {
		panic(fmt.Sprintf("failed to create schema: %v", err))
	}

	handlerInterface := createHandlerInterface(k8sClient, handlerOptions, jwtIssuer, authenticator)
	router := buildRouter(schema, local.NewAuthorizer(authenticator, rbac.New(k8sClient, TestNamespace, &rbac.Options{})))
	chiServerOptions := buildChiServerOptions(router)

	openapi.HandlerWithOptions(handlerInterface, chiServerOptions)

	httpServer := buildHTTPServer(listenAddr, router)
	startServerAsync(httpServer)

	return httpServer
}

func getProviderVersion() string {
	version := os.Getenv("PROVIDER_VERSION")
	if version == "" {
		version = "dev"
	}

	return version
}

func getProviderBranch() string {
	return os.Getenv("GIT_BRANCH")
}

func cleanupAllTestUserOrganizationUsers(ctx context.Context, k8sClient client.Client) {
	for _, userName := range []string{"test-user", "admin-user"} {
		orgUserList := &unikornv1.OrganizationUserList{}
		if err := k8sClient.List(ctx, orgUserList, client.MatchingLabels{
			"unikorn-cloud.org/user": userName,
		}); err != nil {
			ctrl.Log.WithName("cleanup").Info("warning: failed to list organization users during cleanup", "user", userName, "error", err)
		}

		for i := range orgUserList.Items {
			if err := k8sClient.Delete(ctx, &orgUserList.Items[i]); err != nil {
				ctrl.Log.WithName("cleanup").Info("warning: failed to delete organization user during cleanup", "name", orgUserList.Items[i].Name, "error", err)
			}
		}
	}
}

// envirClientCertificate returns a self-signed certificate for Envir's service client, URL-escaped
// as the ingress forwards it in Ssl-Client-Cert. uni-identity binds the issued token to it.
//
//nolint:gochecknoglobals
var envirClientCertificate = sync.OnceValue(func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "envir-resource-manager"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}

	return url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
})
