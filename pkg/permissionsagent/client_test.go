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
	"sync"
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
	subject        = "c1a7e0b2-5d3f-4a8e-9b6c-2f4d8e1a3b5c"
	serviceToken   = "service-token"
	actor          = "serviceaccount:0b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e"
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

// fakeAgent records each request and replies with a set status and body.  The
// mutex guards everything the handler goroutines share with the test.
type fakeAgent struct {
	server *httptest.Server

	lock     sync.Mutex
	requests []seen
	status   int
	reply    any
	delay    time.Duration
}

func newFakeAgent() *fakeAgent {
	f := &fakeAgent{status: http.StatusOK}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		f.lock.Lock()
		f.requests = append(f.requests, seen{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), query: r.URL.Query(), body: body})
		status, reply, delay := f.status, f.reply, f.delay
		f.lock.Unlock()

		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))

	DeferCleanup(f.server.Close)

	return f
}

func (f *fakeAgent) respond(status int, reply any) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.status, f.reply = status, reply
}

func (f *fakeAgent) slow(delay time.Duration) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.delay = delay
}

func (f *fakeAgent) recorded() []seen {
	f.lock.Lock()
	defer f.lock.Unlock()

	return append([]seen(nil), f.requests...)
}

func (f *fakeAgent) last() seen {
	requests := f.recorded()
	Expect(requests).NotTo(BeEmpty())

	return requests[len(requests)-1]
}

// rawServer serves a fixed reply that need not be JSON.
func rawServer(status int, contentType, body string) string {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))

	DeferCleanup(server.Close)

	return server.URL
}

func newClient(opts permissionsagent.Options) *permissionsagent.Client {
	c, err := permissionsagent.New(opts)
	Expect(err).NotTo(HaveOccurred())

	return c
}

func errorBody(code, description string) map[string]string {
	return map[string]string{"error": code, "error_description": description, "trace_id": "57bc14d9bd461f0b5a72db830149b67a"}
}

func checks(n int) []openapi.CheckItem {
	out := make([]openapi.CheckItem, n)
	for i := range out {
		out[i] = openapi.CheckItem{Kind: "identity:projects", Action: "read", OrganizationId: new(organizationID)}
	}

	return out
}

func results(n int) []openapi.BatchCheckAnswer {
	return make([]openapi.BatchCheckAnswer, n)
}

var _ = Describe("Permissions agent client", func() {
	var (
		agent  *fakeAgent
		client *permissionsagent.Client
		ctx    context.Context
	)

	item := openapi.CheckItem{Kind: "identity:projects", Action: "read", OrganizationId: new(organizationID), ProjectId: new(projectID)}

	BeforeEach(func() {
		agent = newFakeAgent()
		client = newClient(permissionsagent.Options{URL: agent.server.URL, Token: serviceToken})
		ctx = context.Background()
	})

	Context("When constructing a client", func() {
		Describe("Given no agent URL", func() {
			It("returns an invalid options error", func() {
				_, err := permissionsagent.New(permissionsagent.Options{})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidOptions))
			})
		})
	})

	Context("When checking one item", func() {
		BeforeEach(func() {
			agent.respond(http.StatusOK, openapi.CheckResult{Allowed: true, Version: copyVersion, Since: since})
		})

		Describe("Given a subject", func() {
			It("returns the agent's answer", func() {
				result, err := client.Check(ctx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.Allowed).To(BeTrue())
				Expect(result.Version).To(Equal(copyVersion))
				Expect(result.Since.Equal(since)).To(BeTrue())
			})

			It("posts the subject and item to /v1/check with the service token", func() {
				_, err := client.Check(ctx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).NotTo(HaveOccurred())

				req := agent.last()
				Expect(req.method).To(Equal(http.MethodPost))
				Expect(req.path).To(Equal("/v1/check"))
				Expect(req.header.Get("Authorization")).To(Equal("Bearer " + serviceToken))

				var sent openapi.CheckRequest
				Expect(json.Unmarshal(req.body, &sent)).To(Succeed())
				Expect(sent.Subject).To(Equal(subject))
				Expect(sent.Actor).To(BeNil())
				Expect(sent.Check).To(Equal(item))
			})
		})

		Describe("Given a service acting on the subject's behalf", func() {
			It("sends the actor in the body", func() {
				_, err := client.Check(ctx, openapi.CheckRequest{Subject: subject, Actor: new(actor), Check: item})
				Expect(err).NotTo(HaveOccurred())

				var sent openapi.CheckRequest
				Expect(json.Unmarshal(agent.last().body, &sent)).To(Succeed())
				Expect(*sent.Actor).To(Equal(actor))
			})
		})

		Describe("Given no subject", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.Check(ctx, openapi.CheckRequest{Check: item})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})

		Describe("Given an actor that is set but empty", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.Check(ctx, openapi.CheckRequest{Subject: subject, Actor: new(""), Check: item})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})

		Describe("Given a client with no service token", func() {
			It("sends no Authorization header", func() {
				c := newClient(permissionsagent.Options{URL: agent.server.URL})

				_, err := c.Check(ctx, openapi.CheckRequest{Subject: subject, Check: item})
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

		Describe("Given a result per item", func() {
			BeforeEach(func() {
				agent.respond(http.StatusOK, openapi.BatchCheckResult{Results: []openapi.BatchCheckAnswer{{Allowed: true}, {Allowed: false}}, Version: copyVersion, Since: since})
			})

			It("returns the results in request order", func() {
				result, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Subject: subject, Checks: items})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.Results).To(Equal([]openapi.BatchCheckAnswer{{Allowed: true}, {Allowed: false}}))
				Expect(result.Version).To(Equal(copyVersion))
			})

			It("posts every item to /v1/check/batch in one call", func() {
				_, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Subject: subject, Checks: items})
				Expect(err).NotTo(HaveOccurred())
				Expect(agent.recorded()).To(HaveLen(1))

				req := agent.last()
				Expect(req.method).To(Equal(http.MethodPost))
				Expect(req.path).To(Equal("/v1/check/batch"))
				Expect(req.header.Get("Authorization")).To(Equal("Bearer " + serviceToken))

				var sent openapi.BatchCheckRequest
				Expect(json.Unmarshal(req.body, &sent)).To(Succeed())
				Expect(sent.Subject).To(Equal(subject))
				Expect(sent.Checks).To(Equal(items))
			})
		})

		Describe("Given a result count that does not match the items", func() {
			It("returns a response error and no results", func() {
				agent.respond(http.StatusOK, openapi.BatchCheckResult{Results: results(1), Version: copyVersion, Since: since})

				result, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Subject: subject, Checks: items})
				Expect(err).To(MatchError(permissionsagent.ErrResponse))
				Expect(result).To(BeNil())
			})
		})

		Describe("Given exactly the maximum number of items", func() {
			It("sends them", func() {
				agent.respond(http.StatusOK, openapi.BatchCheckResult{Results: results(permissionsagent.MaxBatchChecks), Version: copyVersion, Since: since})

				result, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Subject: subject, Checks: checks(permissionsagent.MaxBatchChecks)})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.Results).To(HaveLen(permissionsagent.MaxBatchChecks))
			})
		})

		Describe("Given more than the maximum number of items", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Subject: subject, Checks: checks(permissionsagent.MaxBatchChecks + 1)})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(err).NotTo(MatchError(permissionsagent.ErrBadRequest))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})

		Describe("Given no items", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Subject: subject})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(err).NotTo(MatchError(permissionsagent.ErrBadRequest))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})

		Describe("Given no subject", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Checks: items})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})

		Describe("Given an actor that is set but empty", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.BatchCheck(ctx, openapi.BatchCheckRequest{Subject: subject, Actor: new(""), Checks: items})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})
	})

	Context("When listing permissions", func() {
		Describe("Given a region", func() {
			BeforeEach(func() {
				agent.respond(http.StatusOK, openapi.PermissionList{
					OrganizationId: organizationID,
					Form:           openapi.Trimmed,
					RegionId:       new(regionID),
					Version:        copyVersion,
					Since:          since,
					Permissions: []openapi.Permission{
						{Kind: "identity:organizations", Action: "read", Scope: openapi.ScopeGlobal},
						{Kind: "identity:projects", Action: "read", Scope: openapi.ScopeOrganization},
						{Kind: "identity:projects", Action: "delete", Scope: openapi.ScopeProject, ProjectId: new(projectID)},
					},
				})
			})

			It("sends the camelCase query and returns the list with each entry's scope", func() {
				params := openapi.ListPermissionsParams{
					Subject:        subject,
					Actor:          new(actor),
					OrganizationId: organizationID,
					ProjectId:      &[]string{projectID},
					RegionId:       new(regionID),
				}

				list, err := client.Permissions(ctx, params)
				Expect(err).NotTo(HaveOccurred())
				Expect(list.Form).To(Equal(openapi.Trimmed))
				Expect(*list.RegionId).To(Equal(regionID))
				Expect(list.Permissions).To(HaveLen(3))
				Expect(list.Permissions[0].Scope).To(Equal(openapi.ScopeGlobal))
				Expect(list.Permissions[0].ProjectId).To(BeNil())
				Expect(list.Permissions[1].Scope).To(Equal(openapi.ScopeOrganization))
				Expect(list.Permissions[1].ProjectId).To(BeNil())
				Expect(list.Permissions[2].Scope).To(Equal(openapi.ScopeProject))
				Expect(*list.Permissions[2].ProjectId).To(Equal(projectID))

				req := agent.last()
				Expect(req.method).To(Equal(http.MethodGet))
				Expect(req.path).To(Equal("/v1/permissions"))
				Expect(req.query.Get("subject")).To(Equal(subject))
				Expect(req.query.Get("actor")).To(Equal(actor))
				Expect(req.query.Get("organizationId")).To(Equal(organizationID))
				Expect(req.query["projectId"]).To(Equal([]string{projectID}))
				Expect(req.query.Get("regionId")).To(Equal(regionID))
				Expect(req.header.Get("Authorization")).To(Equal("Bearer " + serviceToken))
			})
		})

		Describe("Given a subject with no access in the organization", func() {
			It("returns an empty list", func() {
				agent.respond(http.StatusOK, openapi.PermissionList{OrganizationId: organizationID, Form: openapi.Trimmed, RegionId: new(regionID), Version: copyVersion, Since: since, Permissions: []openapi.Permission{}})

				list, err := client.Permissions(ctx, openapi.ListPermissionsParams{Subject: subject, OrganizationId: organizationID})
				Expect(err).NotTo(HaveOccurred())
				Expect(list.Permissions).To(BeEmpty())
			})
		})

		Describe("Given no subject", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.Permissions(ctx, openapi.ListPermissionsParams{OrganizationId: organizationID})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})

		Describe("Given an actor that is set but empty", func() {
			It("returns an invalid input error without calling the agent", func() {
				_, err := client.Permissions(ctx, openapi.ListPermissionsParams{Subject: subject, Actor: new(""), OrganizationId: organizationID})
				Expect(err).To(MatchError(permissionsagent.ErrInvalidInput))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})
	})

	Context("When listing untrimmed permissions", func() {
		params := openapi.ListPermissionsParams{Subject: subject, OrganizationId: organizationID, Untrimmed: new(true)}

		Describe("Given the agent returns the untrimmed list", func() {
			It("asks for untrimmed=true and returns the list", func() {
				agent.respond(http.StatusOK, openapi.PermissionList{OrganizationId: organizationID, Form: openapi.Untrimmed, Version: copyVersion, Since: since, Permissions: []openapi.Permission{{Kind: "identity:projects", Action: "read", Scope: openapi.ScopeOrganization}}})

				list, err := client.Permissions(ctx, params)
				Expect(err).NotTo(HaveOccurred())
				Expect(list.Form).To(Equal(openapi.Untrimmed))
				Expect(list.Permissions).To(HaveLen(1))
				Expect(agent.last().query.Get("untrimmed")).To(Equal("true"))
			})
		})

		Describe("Given the agent returns a trimmed list", func() {
			It("refuses the list", func() {
				agent.respond(http.StatusOK, openapi.PermissionList{OrganizationId: organizationID, Form: openapi.Trimmed, RegionId: new(regionID), Version: copyVersion, Since: since, Permissions: []openapi.Permission{}})

				list, err := client.Permissions(ctx, params)
				Expect(err).To(MatchError(permissionsagent.ErrTrimmed))
				Expect(list).To(BeNil())
			})
		})
	})

	Context("When reading status", func() {
		Describe("Given a fresh copy", func() {
			It("returns versions, region and copy age", func() {
				agent.respond(http.StatusOK, openapi.Status{
					AgentVersion:   "0.1.0",
					PolicyVersion:  new("9c1d2e3f4a5b"),
					Version:        new(copyVersion),
					Since:          &since,
					RegionId:       regionID,
					Fresh:          true,
					CopyAgeSeconds: new(4),
					Organizations:  &[]openapi.OrganizationCopyAge{{OrganizationId: organizationID, CopyAgeSeconds: 6}},
				})

				status, err := client.Status(ctx)
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
				Expect(req.header.Get("Authorization")).To(Equal("Bearer " + serviceToken))
			})
		})
	})

	Context("When the agent returns an error status", func() {
		Describe("Given a platform error body on a check", func() {
			DescribeTable("maps the status to a typed error",
				func(status int, code string, want error) {
					agent.respond(status, errorBody(code, "something went wrong"))

					result, err := client.Check(ctx, openapi.CheckRequest{Subject: subject, Check: item})
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
				Entry("403 is forbidden: the caller is not trusted", http.StatusForbidden, "forbidden", permissionsagent.ErrForbidden),
				Entry("500 is a server error", http.StatusInternalServerError, "server_error", permissionsagent.ErrServer),
				Entry("503 is unavailable", http.StatusServiceUnavailable, "server_error", permissionsagent.ErrUnavailable),
			)
		})

		Describe("Given a list request with an unknown region", func() {
			It("returns a bad request error with the agent's description", func() {
				agent.respond(http.StatusBadRequest, errorBody("invalid_request", "unknown region"))

				_, err := client.Permissions(ctx, openapi.ListPermissionsParams{Subject: subject, OrganizationId: organizationID, RegionId: new("nowhere")})
				Expect(err).To(MatchError(permissionsagent.ErrBadRequest))
				Expect(err.Error()).To(ContainSubstring("unknown region"))
			})
		})

		Describe("Given a list request when the agent has no fresh copy", func() {
			It("returns an unavailable error and no list", func() {
				agent.respond(http.StatusServiceUnavailable, errorBody("server_error", "permissions are not available"))

				list, err := client.Permissions(ctx, openapi.ListPermissionsParams{Subject: subject, OrganizationId: organizationID})
				Expect(err).To(MatchError(permissionsagent.ErrUnavailable))
				Expect(list).To(BeNil())
			})
		})

		Describe("Given an error body that is not JSON", func() {
			It("still returns a typed error from the status", func() {
				c := newClient(permissionsagent.Options{URL: rawServer(http.StatusBadGateway, "text/html", "<html>bad gateway</html>")})

				_, err := c.Status(ctx)
				Expect(err).To(MatchError(permissionsagent.ErrUnavailable))
			})
		})
	})

	Context("When the agent replies 200 with a body that is not JSON", func() {
		Describe("Given a check", func() {
			It("returns a response error, not an unavailable error", func() {
				c := newClient(permissionsagent.Options{URL: rawServer(http.StatusOK, "application/json", "{not json")})

				result, err := c.Check(ctx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).To(MatchError(permissionsagent.ErrResponse))
				Expect(err).NotTo(MatchError(permissionsagent.ErrUnavailable))
				Expect(result).To(BeNil())
			})
		})
	})

	Context("When the agent cannot be reached", func() {
		Describe("Given nothing listening at the URL", func() {
			It("returns an unavailable error", func() {
				down := httptest.NewServer(http.NotFoundHandler())
				down.Close()

				c := newClient(permissionsagent.Options{URL: down.URL})

				_, err := c.Check(ctx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).To(MatchError(permissionsagent.ErrUnavailable))
			})
		})
	})

	Context("When a call does not finish in time", func() {
		BeforeEach(func() {
			agent.respond(http.StatusOK, openapi.CheckResult{Allowed: true, Version: copyVersion, Since: since})
			agent.slow(time.Second)
		})

		Describe("Given the client timeout is shorter than the call", func() {
			It("gives up and returns an unavailable error", func() {
				c := newClient(permissionsagent.Options{URL: agent.server.URL, Timeout: 20 * time.Millisecond})

				start := time.Now()
				_, err := c.Check(ctx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).To(MatchError(permissionsagent.ErrUnavailable))
				Expect(err).To(MatchError(context.DeadlineExceeded))
				Expect(time.Since(start)).To(BeNumerically("<", 500*time.Millisecond))
			})
		})

		Describe("Given the caller's own deadline is shorter than the client timeout", func() {
			It("returns the deadline error, not an unavailable error", func() {
				c := newClient(permissionsagent.Options{URL: agent.server.URL, Timeout: 5 * time.Second})

				callerCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
				DeferCleanup(cancel)

				_, err := c.Check(callerCtx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).To(MatchError(context.DeadlineExceeded))
				Expect(err).NotTo(MatchError(permissionsagent.ErrUnavailable))
			})
		})

		Describe("Given the caller cancels during the call", func() {
			It("returns the cancel error, not an unavailable error", func() {
				callerCtx, cancel := context.WithCancel(ctx)
				DeferCleanup(cancel)

				time.AfterFunc(20*time.Millisecond, cancel)

				_, err := client.Check(callerCtx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).To(MatchError(context.Canceled))
				Expect(err).NotTo(MatchError(permissionsagent.ErrUnavailable))
			})
		})

		Describe("Given the caller cancelled before the call", func() {
			It("returns the cancel error without calling the agent", func() {
				callerCtx, cancel := context.WithCancel(ctx)
				cancel()

				_, err := client.Check(callerCtx, openapi.CheckRequest{Subject: subject, Check: item})
				Expect(err).To(MatchError(context.Canceled))
				Expect(err).NotTo(MatchError(permissionsagent.ErrUnavailable))
				Expect(agent.recorded()).To(BeEmpty())
			})
		})
	})
})
