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

package openapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// benchmarkAuthorizer accepts every request, so the benchmark measures
// response handling only.
type benchmarkAuthorizer struct{}

func (benchmarkAuthorizer) Authorize(*openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	return authInfoFixture(identityapi.User), nil
}

func (benchmarkAuthorizer) GetACL(context.Context, string) (*identityapi.Acl, error) {
	return &identityapi.Acl{}, nil
}

// organizationsBody returns a schema-valid organization list of n rows.
func organizationsBody(b *testing.B, n int) []byte {
	b.Helper()

	description := "An organization that measures response validation cost."
	domain := "example.com"
	organizations := make(identityapi.Organizations, n)

	for i := range organizations {
		organizations[i] = identityapi.OrganizationRead{
			Metadata: coreapi.ResourceReadMetadata{
				Id:                 fmt.Sprintf("%08x-0000-4000-8000-000000000000", i),
				Name:               fmt.Sprintf("organization-%d", i),
				Description:        &description,
				CreationTime:       time.Unix(1700000000, 0).UTC(),
				HealthStatus:       coreapi.ResourceHealthStatusHealthy,
				ProvisioningStatus: coreapi.ResourceProvisioningStatusProvisioned,
			},
			Spec: identityapi.OrganizationSpec{
				OrganizationType: identityapi.Domain,
				Domain:           &domain,
			},
		}
	}

	body, err := json.Marshal(organizations)
	if err != nil {
		b.Fatal(err)
	}

	return body
}

// organizationsMux serves body on the real organization list route behind
// the validation middleware.
func organizationsMux(b *testing.B, validate bool, body []byte) http.Handler {
	b.Helper()

	options := &openapi.Options{}

	flags := pflag.NewFlagSet("benchmark", pflag.ContinueOnError)
	options.AddFlags(flags)

	if err := flags.Parse([]string{fmt.Sprintf("--runtime-schema-validation=%t", validate)}); err != nil {
		b.Fatal(err)
	}

	schema, err := helpers.NewSchema(identityapi.GetSwagger)
	if err != nil {
		b.Fatal(err)
	}

	r := chi.NewRouter()
	r.Use(routeresolver.New(schema).Middleware)
	r.Use(openapi.NewValidator(options, benchmarkAuthorizer{}).Middleware)
	r.Get("/api/v1/organizations", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(body)
	})

	return r
}

// BenchmarkResponseValidation measures the cost of response-body validation
// on the organization list.
func BenchmarkResponseValidation(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		body := organizationsBody(b, n)

		for _, validate := range []bool{true, false} {
			b.Run(fmt.Sprintf("organizations=%d/validation=%t", n, validate), func(b *testing.B) {
				m := organizationsMux(b, validate, body)

				b.SetBytes(int64(len(body)))
				b.ReportAllocs()

				for b.Loop() {
					r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/api/v1/organizations", nil)
					addAuthorizationHeader(b, r)

					w := httptest.NewRecorder()
					m.ServeHTTP(w, r)

					if w.Code != http.StatusOK {
						b.Fatalf("unexpected status %d", w.Code)
					}
				}
			})
		}
	}
}
