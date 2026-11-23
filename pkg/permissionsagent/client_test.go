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

//nolint:revive // dot imports are the standard Ginkgo DSL
package permissionsagent_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/identity/pkg/permissionsagent"
	"github.com/unikorn-cloud/identity/pkg/permissionsagent/openapi"
)

func TestPermissionsAgent(t *testing.T) {
	t.Parallel()

	RegisterFailHandler(Fail)
	RunSpecs(t, "Permissions Agent Client Suite")
}

const (
	organizationID = "d4600d6e-e965-4b44-a808-84fb2fa36702"
	projectID      = "a4e7fddc-4812-4bfa-94b4-2b1174ac7e0e"
	regionID       = "7c3e8f1a-2b4d-4e6f-8a9b-0c1d2e3f4a5b"
	copyVersion    = "3f2c9a1b7d4e"
)

//nolint:gochecknoglobals
var since = time.Date(2026, 11, 20, 10, 15, 0, 0, time.UTC)

// seen is one request as the fake agent received it.
type seen struct {
	method string
	path   string
	header http.Header
	query  url.Values
	body   []byte
}

// fakeAgent records each request and replies with a fixed status and body.
type fakeAgent struct {
	server   *httptest.Server
	requests []seen
	status   int
	reply    any
	delay    time.Duration
}

func newFakeAgent() *fakeAgent {
	f := &fakeAgent{status: http.StatusOK}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.requests = append(f.requests, seen{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), query: r.URL.Query(), body: body})

		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(f.reply)
	}))

	DeferCleanup(f.server.Close)

	return f
}

func (f *fakeAgent) last() seen {
	Expect(f.requests).NotTo(BeEmpty())

	return f.requests[len(f.requests)-1]
}

func (f *fakeAgent) client() *permissionsagent.Client {
	c, err := permissionsagent.New(permissionsagent.Options{URL: f.server.URL})
	Expect(err).NotTo(HaveOccurred())

	return c
}

func errorBody(code, description string) map[string]string {
	return map[string]string{"error": code, "error_description": description, "trace_id": "57bc14d9bd461f0b5a72db830149b67a"}
}

var _ = Describe("Permissions agent client", func() {
	var (
		agent  *fakeAgent
		client *permissionsagent.Client
		ctx    context.Context
		caller permissionsagent.Caller
	)

	BeforeEach(func() {
		agent = newFakeAgent()
		client = agent.client()
		ctx = context.Background()
		caller = permissionsagent.Caller{Token: "user-token"}
	})

	Context("When constructing a client", func() {
		Describe("Given no agent URL", func() {
			It("returns an error", func() {
				_, err := permissionsagent.New(permissionsagent.Options{})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidOptions))
			})
		})
	})

	Context("When checking one item", func() {
		item := openapi.CheckItem{Kind: "identity:projects", Action: "read", OrganizationId: new(organizationID), ProjectId: new(projectID)}

		BeforeEach(func() {
			agent.reply = openapi.CheckResult{Subject: "user@acme.com", Allowed: true, Version: copyVersion, Since: since}
		})

		Describe("Given a caller acting for itself", func() {
			It("returns the agent's answer", func() {
				result, err := client.Check(ctx, caller, item)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.Allowed).To(BeTrue())
				Expect(result.Subject).To(Equal("user@acme.com"))
				Expect(result.Version).To(Equal(copyVersion))
				Expect(result.Since.Equal(since)).To(BeTrue())
			})

			It("posts the item to /v1/check with the user's bearer token", func() {
				_, err := client.Check(ctx, caller, item)
				Expect(err).NotTo(HaveOccurred())

				req := agent.last()
				Expect(req.method).To(Equal(http.MethodPost))
				Expect(req.path).To(Equal("/v1/check"))
				Expect(req.header.Get("Authorization")).To(Equal("Bearer user-token"))
				Expect(req.header.Get("X-Actor")).To(BeEmpty())

				var sent openapi.CheckItem
				Expect(json.Unmarshal(req.body, &sent)).To(Succeed())
				Expect(sent).To(Equal(item))
			})
		})

		Describe("Given a service acting on the user's behalf", func() {
			It("sends the actor header", func() {
				caller.Actor = "service-account@acme.com"

				_, err := client.Check(ctx, caller, item)
				Expect(err).NotTo(HaveOccurred())
				Expect(agent.last().header.Get("X-Actor")).To(Equal("service-account@acme.com"))
			})
		})

		Describe("Given no token", func() {
			It("sends no Authorization header", func() {
				_, err := client.Check(ctx, permissionsagent.Caller{}, item)
				Expect(err).NotTo(HaveOccurred())
				Expect(agent.last().header.Values("Authorization")).To(BeEmpty())
			})
		})
	})

	Context("When checking a batch", func() {
		items := []openapi.CheckItem{
			{Kind: "identity:projects", Action: "read", OrganizationId: new(organizationID)},
			{Kind: "identity:projects", Action: "delete", OrganizationId: new(organizationID), ProjectId: new(projectID)},
		}

		Describe("Given an answer per item", func() {
			BeforeEach(func() {
				agent.reply = openapi.BatchCheckResult{Subject: "user@acme.com", Allowed: []bool{true, false}, Version: copyVersion, Since: since}
			})

			It("returns the answers in request order", func() {
				result, err := client.BatchCheck(ctx, caller, items)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.Allowed).To(Equal([]bool{true, false}))
				Expect(result.Version).To(Equal(copyVersion))
			})

			It("posts every item to /v1/check/batch in one call", func() {
				_, err := client.BatchCheck(ctx, caller, items)
				Expect(err).NotTo(HaveOccurred())
				Expect(agent.requests).To(HaveLen(1))

				req := agent.last()
				Expect(req.method).To(Equal(http.MethodPost))
				Expect(req.path).To(Equal("/v1/check/batch"))
				Expect(req.header.Get("Authorization")).To(Equal("Bearer user-token"))

				var sent openapi.BatchCheckRequest
				Expect(json.Unmarshal(req.body, &sent)).To(Succeed())
				Expect(sent.Items).To(Equal(items))
			})
		})

		Describe("Given an answer count that does not match the items", func() {
			It("returns a response error and no answers", func() {
				agent.reply = openapi.BatchCheckResult{Subject: "user@acme.com", Allowed: []bool{true}, Version: copyVersion, Since: since}

				result, err := client.BatchCheck(ctx, caller, items)
				Expect(err).To(MatchError(permissionsagent.ErrResponse))
				Expect(result).To(BeNil())
			})
		})

		Describe("Given no items", func() {
			It("returns a bad request error without calling the agent", func() {
				_, err := client.BatchCheck(ctx, caller, nil)
				Expect(err).To(MatchError(permissionsagent.ErrBadRequest))
				Expect(agent.requests).To(BeEmpty())
			})
		})
	})

	Context("When listing permissions", func() {
		BeforeEach(func() {
			agent.reply = openapi.PermissionList{
				Subject:        "user@acme.com",
				OrganizationId: organizationID,
				Form:           openapi.Trimmed,
				RegionId:       new(regionID),
				Version:        copyVersion,
				Since:          since,
				Permissions: []openapi.Permission{
					{Kind: "identity:projects", Action: "read"},
					{Kind: "identity:projects", Action: "delete", ProjectId: new(projectID)},
				},
			}
		})

		Describe("Given a region", func() {
			It("sends the query and returns the list", func() {
				params := openapi.ListPermissionsParams{OrganizationId: organizationID, ProjectId: &[]string{projectID}, RegionId: new(regionID)}

				list, err := client.Permissions(ctx, caller, params)
				Expect(err).NotTo(HaveOccurred())
				Expect(list.Form).To(Equal(openapi.Trimmed))
				Expect(*list.RegionId).To(Equal(regionID))
				Expect(list.Permissions).To(HaveLen(2))
				Expect(*list.Permissions[1].ProjectId).To(Equal(projectID))

				req := agent.last()
				Expect(req.method).To(Equal(http.MethodGet))
				Expect(req.path).To(Equal("/v1/permissions"))
				Expect(req.query.Get("organization_id")).To(Equal(organizationID))
				Expect(req.query["project_id"]).To(Equal([]string{projectID}))
				Expect(req.query.Get("region_id")).To(Equal(regionID))
				Expect(req.header.Get("Authorization")).To(Equal("Bearer user-token"))
			})
		})
	})

	Context("When listing untrimmed permissions", func() {
		Describe("Given the agent returns the untrimmed list", func() {
			BeforeEach(func() {
				agent.reply = openapi.PermissionList{Subject: "user@acme.com", OrganizationId: organizationID, Form: openapi.Untrimmed, Version: copyVersion, Since: since, Permissions: []openapi.Permission{{Kind: "identity:projects", Action: "read"}}}
			})

			It("asks for untrimmed=true with no region and returns the list", func() {
				list, err := permissionsagent.UntrimmedPermissions(ctx, client, caller, organizationID, []string{projectID})
				Expect(err).NotTo(HaveOccurred())
				Expect(list.Form).To(Equal(openapi.Untrimmed))
				Expect(list.Permissions).To(HaveLen(1))

				req := agent.last()
				Expect(req.query.Get("untrimmed")).To(Equal("true"))
				Expect(req.query.Has("region_id")).To(BeFalse())
				Expect(req.query["project_id"]).To(Equal([]string{projectID}))
			})
		})

		Describe("Given the agent returns a trimmed list", func() {
			BeforeEach(func() {
				agent.reply = openapi.PermissionList{Subject: "user@acme.com", OrganizationId: organizationID, Form: openapi.Trimmed, RegionId: new(regionID), Version: copyVersion, Since: since, Permissions: []openapi.Permission{}}
			})

			It("refuses the list", func() {
				list, err := permissionsagent.UntrimmedPermissions(ctx, client, caller, organizationID, nil)
				Expect(err).To(MatchError(permissionsagent.ErrTrimmed))
				Expect(list).To(BeNil())
			})
		})
	})

	Context("When reading status", func() {
		Describe("Given a fresh copy", func() {
			It("returns versions, region and copy age", func() {
				agent.reply = openapi.Status{
					AgentVersion:   "0.1.0",
					PolicyVersion:  new("9c1d2e3f4a5b"),
					Version:        new(copyVersion),
					Since:          &since,
					RegionId:       regionID,
					Fresh:          true,
					CopyAgeSeconds: new(4),
					Organizations:  &[]openapi.OrganizationCopyAge{{OrganizationId: organizationID, CopyAgeSeconds: 6}},
				}

				status, err := client.Status(ctx, caller)
				Expect(err).NotTo(HaveOccurred())
				Expect(status.AgentVersion).To(Equal("0.1.0"))
				Expect(*status.PolicyVersion).To(Equal("9c1d2e3f4a5b"))
				Expect(*status.Version).To(Equal(copyVersion))
				Expect(status.RegionId).To(Equal(regionID))
				Expect(status.Fresh).To(BeTrue())
				Expect(*status.CopyAgeSeconds).To(Equal(4))
				Expect((*status.Organizations)[0].CopyAgeSeconds).To(Equal(6))

				req := agent.last()
				Expect(req.method).To(Equal(http.MethodGet))
				Expect(req.path).To(Equal("/v1/status"))
			})
		})
	})

	Context("When the agent returns an error", func() {
		item := openapi.CheckItem{Kind: "identity:projects", Action: "read"}

		DescribeTable("maps the status to a typed error",
			func(status int, code string, want error) {
				agent.status = status
				agent.reply = errorBody(code, "something went wrong")

				result, err := client.Check(ctx, caller, item)
				Expect(err).To(MatchError(want))
				Expect(result).To(BeNil())

				var agentErr *permissionsagent.Error
				Expect(err).To(BeAssignableToTypeOf(agentErr))
				agentErr, _ = err.(*permissionsagent.Error) //nolint:errorlint
				Expect(agentErr.StatusCode).To(Equal(status))
				Expect(agentErr.Code).To(Equal(code))
				Expect(agentErr.Description).To(Equal("something went wrong"))
			},
			Entry("400 is a bad request", http.StatusBadRequest, "invalid_request", permissionsagent.ErrBadRequest),
			Entry("401 is unauthorized", http.StatusUnauthorized, "access_denied", permissionsagent.ErrUnauthorized),
			Entry("403 is forbidden", http.StatusForbidden, "forbidden", permissionsagent.ErrForbidden),
			Entry("500 is a server error", http.StatusInternalServerError, "server_error", permissionsagent.ErrServer),
			Entry("503 is unavailable", http.StatusServiceUnavailable, "server_error", permissionsagent.ErrUnavailable),
		)

		Describe("Given a list request with an unknown region", func() {
			It("returns a bad request error with the agent's description", func() {
				agent.status = http.StatusBadRequest
				agent.reply = errorBody("invalid_request", "unknown region")

				_, err := client.Permissions(ctx, caller, openapi.ListPermissionsParams{OrganizationId: organizationID, RegionId: new("nowhere")})
				Expect(err).To(MatchError(permissionsagent.ErrBadRequest))
				Expect(err.Error()).To(ContainSubstring("unknown region"))
			})
		})

		Describe("Given a body that is not JSON", func() {
			It("still returns a typed error from the status", func() {
				agent.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusBadGateway)
					_, _ = w.Write([]byte("<html>bad gateway</html>"))
				})

				_, err := client.Status(ctx, caller)
				Expect(err).To(MatchError(permissionsagent.ErrUnavailable))
			})
		})
	})

	Context("When the agent is slow", func() {
		Describe("Given a call that takes longer than the timeout", func() {
			It("gives up and returns an unavailable error", func() {
				agent.delay = time.Second
				agent.reply = openapi.CheckResult{Subject: "user@acme.com", Allowed: true, Version: copyVersion, Since: since}

				c, err := permissionsagent.New(permissionsagent.Options{URL: agent.server.URL, Timeout: 20 * time.Millisecond})
				Expect(err).NotTo(HaveOccurred())

				start := time.Now()
				_, err = c.Check(ctx, caller, openapi.CheckItem{Kind: "identity:projects", Action: "read"})
				Expect(err).To(MatchError(permissionsagent.ErrUnavailable))
				Expect(err).To(MatchError(context.DeadlineExceeded))
				Expect(time.Since(start)).To(BeNumerically("<", 500*time.Millisecond))
			})
		})
	})

	Context("When a caller depends on the Agent interface", func() {
		Describe("Given the HTTP client", func() {
			It("satisfies the interface", func() {
				var a permissionsagent.Agent = client
				Expect(a).NotTo(BeNil())
			})
		})
	})
})
