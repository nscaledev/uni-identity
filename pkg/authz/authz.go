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

// Package authz carries the authorization decisions made while serving a
// request, so that later middleware can describe what happened without having
// to reconstruct it from the request's shape.  See the package README.
package authz

import (
	"context"
	"sync"

	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// Scope is the tenancy an operation was authorized within.
//
// This is the fact that cannot be recovered from the URL.  v1 APIs carried the
// organization and project in the path; v2 APIs address resources by ID alone
// and resolve tenancy from the resource's labels, so only the component that
// performed the check knows it.
type Scope struct {
	// OrganizationID is the zero value for a globally scoped decision.
	OrganizationID ids.OrganizationID
	// ProjectID is the zero value for an organization scoped decision.
	ProjectID ids.ProjectID
}

// Organization reports whether the scope names an organization.
func (s Scope) Organization() bool {
	return s.OrganizationID != ids.OrganizationID{}
}

// Project reports whether the scope names a project.
func (s Scope) Project() bool {
	return s.ProjectID != ids.ProjectID{}
}

// Decision is one authorization check and its outcome.
type Decision struct {
	// Endpoint is the RBAC endpoint checked, which names the resource type,
	// for example "identity:groups".
	Endpoint string
	// Operation is the access the check required.
	Operation openapi.AclOperation
	// Scope is the tenancy the check was performed against.
	Scope Scope
	// Allowed is the outcome.
	//
	// Only allowed decisions are recorded today.  Refusals are representable
	// so that the type does not have to change when they start being audited,
	// but recording them has to wait until every service distinguishes a gate
	// from a predicate: a predicate refusing is a resource being filtered out
	// of a list, which is routine and must not be reported as a refusal.  See
	// pkg/rbac's gates and predicates section.
	Allowed bool
}

// Recorder accumulates the decisions made while serving one request.
//
// A single request may produce several: one for the operation the request is,
// and further ones for preconditions, such as checking the caller may grant
// each role they are adding to a group.  The recorder keeps them all, in the
// order they were made, and leaves the question of which describes the request
// to the consumer.
type Recorder struct {
	mu sync.Mutex
	// decisions is append-only for the life of a request.
	decisions []Decision
}

// Record appends a decision.
func (r *Recorder) Record(decision Decision) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.decisions = append(r.decisions, decision)
}

// Decisions returns a copy of what has been recorded, so a consumer cannot
// alter the record it is describing.
func (r *Recorder) Decisions() []Decision {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]Decision(nil), r.decisions...)
}

type keyType int

//nolint:gochecknoglobals
var key keyType

// NewContext returns a context carrying the recorder.
func NewContext(ctx context.Context, recorder *Recorder) context.Context {
	return context.WithValue(ctx, key, recorder)
}

// FromContext returns the recorder, if one was installed.
func FromContext(ctx context.Context) (*Recorder, bool) {
	recorder, ok := ctx.Value(key).(*Recorder)

	return recorder, ok
}

// Record adds a decision to the context's recorder, and does nothing when
// there is none.
//
// Absence is normal rather than exceptional: authorization also runs in
// controllers, tests and internal paths that never pass through the audit
// middleware.  Those must not be made to fail by a recording concern.
func Record(ctx context.Context, decision Decision) {
	if recorder, ok := FromContext(ctx); ok {
		recorder.Record(decision)
	}
}
