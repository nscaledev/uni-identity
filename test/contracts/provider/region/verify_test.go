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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	chi "github.com/go-chi/chi/v5"
	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"github.com/pact-foundation/pact-go/v2/models"
	"github.com/pact-foundation/pact-go/v2/provider"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/openapi"

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

		testServer = startTestServer(ctx, k8sClient, serverURL, fmt.Sprintf("127.0.0.1:%d", port))

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
			stateHandlers := createStateHandlers(ctx, stateManager)

			err := verifier.VerifyProvider(testingT, provider.VerifyRequest{
				ProviderBaseURL:            serverURL,
				Provider:                   "uni-identity",
				BrokerURL:                  pactBrokerURL,
				BrokerUsername:             brokerUsername,
				BrokerPassword:             brokerPassword,
				PublishVerificationResults: os.Getenv("CI") == "true" || os.Getenv("PUBLISH_VERIFICATION") == "true",
				ProviderVersion:            getProviderVersion(),
				ProviderBranch:             getProviderBranch(),
				ConsumerVersionSelectors: []provider.Selector{
					&provider.ConsumerVersionSelector{MainBranch: true},
					&provider.ConsumerVersionSelector{MatchingBranch: true},
				},
				EnablePending: true,
				StateHandlers: stateHandlers,
			})

			Expect(err).NotTo(HaveOccurred(), "Provider verification should succeed")
		})
	})

	Describe("Verifying pacts from local files", func() {
		It("should verify local pact files", func() {
			pactFile := os.Getenv("PACT_FILE")
			if pactFile == "" {
				Skip("PACT_FILE environment variable not set, skipping local file verification")
			}

			verifier := provider.NewVerifier()

			stateHandlers := createStateHandlers(ctx, stateManager)

			err := verifier.VerifyProvider(testingT, provider.VerifyRequest{
				ProviderBaseURL: serverURL,
				Provider:        "uni-identity",
				PactFiles:       []string{pactFile},
				StateHandlers:   stateHandlers,
			})

			Expect(err).NotTo(HaveOccurred(), "Provider verification should succeed")
		})
	})
})

func createStateHandlers(ctx context.Context, stateManager *StateManager) models.StateHandlers {
	return models.StateHandlers{
		"project exists": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleProjectExists(ctx, setup, state.Parameters)
		},
		"allocation exists": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			return nil, stateManager.HandleAllocationExists(ctx, setup, state.Parameters)
		},
	}
}

// buildHandlerOptions creates handler options for the test server.
func buildHandlerOptions(serverURL string) *handler.Options {
	return &handler.Options{
		Issuer:      common.IssuerValue{URL: serverURL},
		CacheMaxAge: 0,
	}
}

// createHandlerInterface creates the handler interface with minimal dependencies for contract testing.
func createHandlerInterface(k8sClient client.Client, serverURL string) openapi.ServerInterface {
	handlerOptions := buildHandlerOptions(serverURL)

	// Pass nil for JWT issuer, OAuth2, and RBAC - not used due to MockACLMiddleware providing all auth context
	handlerInterface, err := handler.New(
		k8sClient,
		k8sClient,
		TestNamespace,
		nil, // JWT issuer not used in contract tests
		nil, // OAuth2 not used in contract tests
		nil, // RBAC not used in contract tests - MockACLMiddleware handles authorization
		handlerOptions,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create handler: %v", err))
	}

	return handlerInterface
}

// buildRouter creates and configures the chi router with middleware.
func buildRouter(schema *helpers.Schema) *chi.Mux {
	router := chi.NewRouter()

	// Add route resolver middleware
	routeResolver := routeresolver.New(schema)
	router.Use(routeResolver.Middleware)

	// Mock ACL middleware allows all organizations for contract testing
	router.Use(MockACLMiddleware(nil)) // Inject mock ACL for contract testing

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
func startTestServer(_ context.Context, k8sClient client.Client, serverURL, listenAddr string) *http.Server {
	schema, err := helpers.NewSchema(openapi.GetSwagger)
	if err != nil {
		panic(fmt.Sprintf("failed to create schema: %v", err))
	}

	handlerInterface := createHandlerInterface(k8sClient, serverURL)
	router := buildRouter(schema)
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
