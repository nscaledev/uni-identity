/*
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

package audit

import (
	"time"
)

type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Actor struct {
	Subject string `json:"subject"`
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
	// Name is the resource's display name at the time of the operation.  A
	// reader should not have to resolve an identifier to understand what was
	// touched, and after a deletion they cannot.  Absent where the operation
	// returns no body to read it from.
	Name string `json:"name,omitempty"`
}

type Operation struct {
	Verb string `json:"verb"`
}

type Result struct {
	Status int `json:"status"`
}

// Source is where the request came from.
type Source struct {
	// IP is the client address, taken from the forwarding headers where the
	// service sits behind a proxy, and the connection otherwise.
	IP string `json:"ip,omitempty"`
}

// Grant is a permission the caller had to hold for the operation to proceed.
//
// These are the checks made before the operation itself, such as proving the
// caller may grant each role they are adding to a group.  They are not separate
// events, they are why this one was allowed, which is the question an auditor
// asks after "what happened".
type Grant struct {
	Endpoint  string `json:"endpoint"`
	Operation string `json:"operation"`
	// ID and Name identify what was relied on.  "A role was granted" does not
	// distinguish a rename from somebody handing themselves administrator.
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Scope is the tenancy the operation affected.
//
// It comes from the authorization decision, not the URL.  v1 APIs happened to
// carry it in the path and v2 APIs do not, so the path was never a dependable
// source and is not consulted.
type Scope struct {
	OrganizationID string `json:"organizationId,omitempty"`
	ProjectID      string `json:"projectId,omitempty"`
}

// Client is what the actor used, which is a different fact from who they are:
// it distinguishes a UI call from a CLI or direct API one.  A struct rather
// than a bare string so a derived client type can be added later without
// changing the field's shape on the wire.
type Client struct {
	UserAgent string `json:"userAgent,omitempty"`
}

// Record is one audit event.  The field set is mandated by the platform
// specification, and the JSON tags are additionally the wire format a collector
// consumes, so changing either breaks a published contract.  See the README.
type Record struct {
	// Timestamp is when the operation happened, not when it was delivered.
	// The signature carries a creation time, but that is a property of the
	// transport: it moves on a retry, covers a whole batch rather than one
	// event, and is gone once the record is stored.  A party holding only the
	// record must still be able to say when.
	Timestamp time.Time  `json:"timestamp"`
	Component *Component `json:"component"`
	Actor     *Actor     `json:"actor"`
	Operation *Operation `json:"operation"`
	// Scope is the organisation and project the operation affected, taken from
	// the authorization decision.  It was a map of whatever the URL happened to
	// carry, which v2 APIs do not carry at all.
	Scope    *Scope    `json:"scope"`
	Resource *Resource `json:"resource"`
	Result   *Result   `json:"result"`
	// Client is nil when the request carried no User-Agent, so an absent
	// client is not reported as an empty one.
	Client *Client `json:"client,omitempty"`
	// Source is where the request came from.
	Source *Source `json:"source,omitempty"`
	// Grants are the permissions relied on to allow the operation.
	Grants []Grant `json:"grants,omitempty"`
}
