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

package authz

import (
	"context"

	"github.com/google/uuid"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// Operation is what was done, held as two facts because they answer different
// questions and conflating them loses one of them.
//
// Access is the permission required, and is what RBAC matches against.  Action
// is what actually happened, and is what an audit record needs.  For plain CRUD
// the two agree.  They part company on an action sub-resource: starting an
// instance and creating one are both POST, so the HTTP method cannot tell them
// apart, and describing a start as "update" tells a reader nothing about what
// occurred.
//
// Keeping them separate also forces a deliberate answer to "what permission
// should starting an instance require?", which is a question an implementation
// can otherwise avoid by reusing whichever check was nearest.
type Operation struct {
	Access openapi.AclOperation
	Action string
}

// The CRUD operations, where the action is the access.
//
//nolint:gochecknoglobals
var (
	Create = Operation{Access: openapi.Create, Action: "create"}
	Read   = Operation{Access: openapi.Read, Action: "read"}
	Update = Operation{Access: openapi.Update, Action: "update"}
	Delete = Operation{Access: openapi.Delete, Action: "delete"}
)

// Action names an operation that is not plain CRUD, such as starting an
// instance, and states the access it requires.
func Action(access openapi.AclOperation, action string) Operation {
	return Operation{
		Access: access,
		Action: action,
	}
}

// Kind says whether a decision describes the request itself or one of its
// preconditions.
//
// A request often makes several checks.  Updating a group checks that the
// caller may update groups, and then, for each role being added, that the
// caller may grant that role.  Only the first describes what happened; the
// others are the evidence for why it was permitted.
type Kind int

const (
	// Subordinate is a precondition of the request.  It is the zero value
	// deliberately: a decision whose kind was never stated must not be taken
	// for the request's own operation, because that would silently relabel a
	// precondition as the event.  A mutating request that records no primary
	// decision is a defect, and a loud one is better than a wrong record.
	Subordinate Kind = iota
	// Primary is the operation the request is.
	Primary
)

// Target is what an authorization check was about.
type Target struct {
	// Endpoint is the RBAC endpoint, which names the resource type.
	Endpoint string
	// Operation is the access required and the action performed.
	Operation Operation
	// Kind says whether this describes the request or a precondition of it.
	Kind Kind
	// ObjectName is the resource's display name, so a reader does not have to
	// resolve an identifier to know what was touched, and can still tell after
	// the resource is gone.  Empty where the caller does not hold it.
	ObjectName string
	// ObjectID identifies the resource acted on.  It is the zero value for a
	// create, where the resource does not exist at the point it is authorized,
	// and for operations that address no single resource.
	//
	// A bare UUID rather than one of the typed ids, because a resource here may
	// belong to any service and this package cannot name their identifier types.
	// Convert at the call site, which keeps the caller's own type checked.
	ObjectID uuid.UUID
}

// Name sets the display name on the decision describing the request.
//
// A caller that only learns the name after authorizing uses this to supply it:
// a create names a resource that did not exist when it was authorized, and a
// resource whose name is not its metadata.name, such as a user named by its
// subject, is only known once it has been read.
//
// It does nothing where no decision describes the request, and names the most
// recent one where several do.
func Name(ctx context.Context, name string) {
	if recorder, ok := FromContext(ctx); ok {
		recorder.Name(name)
	}
}

// Primaries returns the decisions describing requests rather than their
// preconditions.
func Primaries(decisions []Decision) []Decision {
	out := make([]Decision, 0, len(decisions))

	for _, decision := range decisions {
		if decision.Kind == Primary {
			out = append(out, decision)
		}
	}

	return out
}
