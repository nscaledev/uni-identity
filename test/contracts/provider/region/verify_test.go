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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive
	"github.com/pact-foundation/pact-go/v2/models"
	"github.com/pact-foundation/pact-go/v2/provider"
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

		stateManager = NewStateManager()

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())

		addr, ok := listener.Addr().(*net.TCPAddr)
		Expect(ok).To(BeTrue(), "listener address should be a TCP address")
		port := addr.Port
		listener.Close()

		serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)

		testServer = startTestServer(ctx, stateManager, fmt.Sprintf("127.0.0.1:%d", port))

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

			if err := testServer.Shutdown(shutdownCtx); err != nil {
				fmt.Printf("failed to shutdown server: %v\n", err)
			}
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
				StateHandlers:              stateHandlers,
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
		"organization exists with global read permission": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			return nil, stateManager.HandleOrganizationWithGlobalPermission(ctx, setup, state.Parameters)
		},
		"organization exists without global permission": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			return nil, stateManager.HandleOrganizationWithoutGlobalPermission(ctx, setup, state.Parameters)
		},
		"organization exists with organization scope read permission": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			return nil, stateManager.HandleOrganizationScopePermission(ctx, setup, state.Parameters)
		},
		"project exists with project scope read permission": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			return nil, stateManager.HandleProjectScopePermission(ctx, setup, state.Parameters)
		},
		"organization does not exist": func(setup bool, state models.ProviderState) (models.ProviderStateResponse, error) {
			fmt.Printf("State: %s, Parameters: %+v\n", state.Name, state.Parameters)
			return nil, stateManager.HandleNonExistentOrganization(ctx, setup, state.Parameters)
		},
	}
}

func startTestServer(_ context.Context, stateManager *StateManager, listenAddr string) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/organizations/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/organizations/")
		parts := strings.Split(path, "/")

		if len(parts) < 2 || parts[1] != "acl" {
			http.NotFound(w, r)

			return
		}

		organizationID := parts[0]
		orgState, exists := stateManager.organizationStates[organizationID]

		if !exists {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": "organization not found",
			})

			return
		}

		response := make(map[string]interface{})

		if orgState.HasGlobal {
			response["global"] = []map[string]interface{}{
				{
					"name":       "region:regions",
					"operations": []string{"read"},
				},
			}
		}

		if orgState.HasOrganization {
			response["organizations"] = []map[string]interface{}{
				{
					"id":   organizationID,
					"name": "Test Organization",
					"endpoints": []map[string]interface{}{
						{
							"name":       "region:networks",
							"operations": []string{"read"},
						},
					},
				},
			}
		}

		if orgState.HasProject {
			response["projects"] = []map[string]interface{}{
				{
					"id":   orgState.ProjectID,
					"name": "Test Project",
					"endpoints": []map[string]interface{}{
						{
							"name":       "region:servers:v2",
							"operations": []string{"read"},
						},
					},
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	})

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	return httpServer
}

func getProviderVersion() string {
	version := os.Getenv("PROVIDER_VERSION")
	if version == "" {
		version = "dev"
	}

	return version
}
