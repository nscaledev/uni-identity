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
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/unikorn-cloud/identity/pkg/ids"
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
	// Target is what was checked: the resource type, the operation, whether
	// this describes the request or a precondition of it, and the resource
	// acted on.
	Target
	// Scope is the tenancy the check was performed against.
	Scope Scope
	// Allowed is the outcome.  Refusals are kept only for the request's own
	// decision: a refused precondition is never read, and keeping it would
	// turn routine list filtering into noise.
	Allowed bool
}

// RequestState says how much is known about what the request is.
type RequestState int

const (
	// NotDescribed means nothing was declared or checked.
	NotDescribed RequestState = iota
	// Declared means the handler stated the request, but its own check has
	// not run, as when the object was not found or a dependency was refused.
	Declared
	// Checked means the request's own check ran, allowed or refused.
	Checked
)

// Recorder accumulates the decisions made while serving one request.
//
// A request has exactly one decision describing it, the request decision, and
// any number of allowed preconditions, such as checking the caller may grant
// each role they are adding to a group.  The first statement of what the
// request is, a declaration or its own check, names the target; later checks
// of it only add the scope and the outcome.  See the README.
type Recorder struct {
	mu sync.Mutex
	// decisions are in the order first made.
	decisions []Decision
	// request indexes the request decision in decisions.  It is only
	// meaningful once state is not NotDescribed.
	request int
	// state is how much is known about the request.
	state RequestState
	// defects are handler mistakes found while recording.
	defects []string
}

// Declare states what the request is before anything can fail.  It does
// nothing when the request is already described.
func (r *Recorder) Declare(target Target) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != NotDescribed {
		return
	}

	target.Kind = Primary

	r.decisions = append(r.decisions, Decision{Target: target})
	r.request = len(r.decisions) - 1
	r.state = Declared
}

// Record adds a decision.  The request's own decision is merged into the one
// request decision, and a refused precondition is dropped.
func (r *Recorder) Record(decision Decision) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if decision.Kind != Primary {
		if decision.Allowed {
			r.decisions = append(r.decisions, decision)
		}

		return
	}

	if r.state == NotDescribed {
		r.decisions = append(r.decisions, decision)
		r.request = len(r.decisions) - 1
		r.state = Checked

		return
	}

	request := &r.decisions[r.request]

	// A check about something else says nothing about this request: taking
	// its scope or outcome would describe one thing with another's facts.
	if !describes(request.Target, decision.Target) {
		r.defects = append(r.defects, fmt.Sprintf("request described as %s %q %s but checked as %s %q %s",
			request.Endpoint, request.Operation.Action, request.ObjectID,
			decision.Endpoint, decision.Operation.Action, decision.ObjectID))

		return
	}

	if request.ObjectID == uuid.Nil {
		request.ObjectID = decision.ObjectID
	}

	if request.ObjectName == "" {
		request.ObjectName = decision.ObjectName
	}

	request.Scope = decision.Scope
	request.Allowed = decision.Allowed
	r.state = Checked
}

// describes reports whether a check is about the request already described:
// the same endpoint and action, and the same object where both name one.
func describes(request, check Target) bool {
	if request.Endpoint != check.Endpoint || request.Operation.Action != check.Operation.Action {
		return false
	}

	return request.ObjectID == uuid.Nil || check.ObjectID == uuid.Nil || request.ObjectID == check.ObjectID
}

// Request returns the decision describing the request and how much is known.
func (r *Recorder) Request() (Decision, RequestState) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state == NotDescribed {
		return Decision{}, NotDescribed
	}

	return r.decisions[r.request], r.state
}

// Defects returns handler mistakes found while recording.
func (r *Recorder) Defects() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.defects...)
}

// Name sets the display name on the request decision.  See the package level
// Name.
func (r *Recorder) Name(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != NotDescribed {
		r.decisions[r.request].ObjectName = name
	}
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

// Declare states what the request is on the context's recorder, and does
// nothing when there is none.  A handler that can fail before its own check,
// for example on fetching the object it checks, declares first so that the
// failure is still described.  See the README.
func Declare(ctx context.Context, target Target) {
	if recorder, ok := FromContext(ctx); ok {
		recorder.Declare(target)
	}
}
