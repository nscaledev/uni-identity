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

package cerbos

import (
	"errors"
	"fmt"
	"slices"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// This file is the A4 request builder: a pure function from identity's
// resolved principal (bindings) plus a resource and actions to the SDK types
// CheckResources sends.  It renders the byte-exact wire contract the
// generated policies match against (see the package README's "Request
// builder" section); the Kubernetes-reading resolver that produces the
// bindings, and the decision mapping, are the A5 decision layer.

var (
	// ErrInvalidBinding is returned for a RoleBinding the wire format cannot
	// represent: an empty role ID, or a project scope with no organization.
	ErrInvalidBinding = errors.New("invalid role binding")

	// ErrInvalidPrincipal is returned for a principal the engine proto would
	// reject (empty subject ID).
	ErrInvalidPrincipal = errors.New("invalid principal")

	// ErrInvalidResource is returned for a resource with no kind, or a scope
	// shape the attribute contract cannot express (project without
	// organization).
	ErrInvalidResource = errors.New("invalid resource")

	// ErrInvalidBatch is returned for a batch the SDK would silently
	// truncate: no resources, a nil resource, or an entry without actions.
	ErrInvalidBatch = errors.New("invalid resource batch")
)

const (
	// principalParentRole is the static Cerbos parent role sent with every
	// principal.  It is MANDATORY: every generated derived role declares
	// parentRoles [principal] (see generate.go's parentRole), so a request
	// without it can never activate any derived role — every check would
	// deny.
	principalParentRole = "principal"

	// attrBindings is the principal attribute carrying the rendered binding
	// strings, matched by the generated CEL conditions as P.attr.bindings.
	// The list form is part of the wire contract pinned by the committed
	// policy fixtures.
	attrBindings = "bindings"

	// attrOrganization and attrProject are the resource attribute keys the
	// generated CEL conditions read as R.attr.organization and
	// R.attr.project.  Scope is encoded by attribute ABSENCE (see
	// BuildResource), so these keys are only ever set with non-empty values.
	attrOrganization = "organization"
	attrProject      = "project"

	// CoarseResourceID is the synthetic resource id for coarse (no specific
	// instance) checks: the engine proto requires a non-empty resource id
	// (engine.proto Resource.id min_len 1).  The constant is pinned because
	// it is part of the future A15 decision-cache key.
	CoarseResourceID = "*"
)

// RoleBinding is one (role, scope) grant held by a principal.  A zero
// OrganizationID means a global grant; a zero ProjectID means an org-level
// grant.  RoleID is the Role CR metadata.name, treated as opaque.
type RoleBinding struct {
	RoleID         string
	OrganizationID string
	ProjectID      string
}

// BindingString renders the byte-exact wire form matched by the generated
// CEL conditions (generate.bindingExpr): <roleID>#global,
// <roleID>#org#<organizationID>, or
// <roleID>#project#<organizationID>#<projectID>.
func (b RoleBinding) BindingString() (string, error) {
	if b.RoleID == "" {
		return "", fmt.Errorf("%w: role ID is empty", ErrInvalidBinding)
	}

	if b.ProjectID != "" && b.OrganizationID == "" {
		return "", fmt.Errorf("%w: project %q binding has no organization", ErrInvalidBinding, b.ProjectID)
	}

	switch {
	case b.OrganizationID == "":
		return b.RoleID + "#global", nil
	case b.ProjectID == "":
		return b.RoleID + "#org#" + b.OrganizationID, nil
	default:
		return b.RoleID + "#project#" + b.OrganizationID + "#" + b.ProjectID, nil
	}
}

// BuildPrincipal renders a resolved principal for CheckResources: the subject
// ID (engine proto min_len 1, so empty is refused here rather than as an
// opaque PDP error), the mandatory static principal parent role, and the
// bindings attribute in list form.  Bindings are deduplicated and sorted so
// semantically identical inputs produce byte-identical requests
// (deterministic requests aid caching and logging); an invalid binding is a
// loud error, never silently dropped — a dropped binding would be a silently
// narrowed grant.
func BuildPrincipal(subjectID string, bindings []RoleBinding) (*sdk.Principal, error) {
	if subjectID == "" {
		return nil, fmt.Errorf("%w: subject ID is empty", ErrInvalidPrincipal)
	}

	rendered := make([]string, 0, len(bindings))

	for _, binding := range bindings {
		bindingString, err := binding.BindingString()
		if err != nil {
			return nil, err
		}

		rendered = append(rendered, bindingString)
	}

	slices.Sort(rendered)
	rendered = slices.Compact(rendered)

	return sdk.NewPrincipal(subjectID, principalParentRole).WithAttr(attrBindings, rendered), nil
}

// BuildResource renders a resource for CheckResources.  An empty id becomes
// CoarseResourceID (the proto requires a non-empty id).  Scope is encoded by
// attribute ABSENCE, never by empty values:
//
//   - GLOBAL check (organizationID==""): NO attributes at all, and projectID
//     must be empty;
//   - ORG check: the organization attribute ONLY.  The project attribute must
//     be ABSENT, not empty — a present-and-matching project attribute on an
//     org-level check would let project bindings activate (flow-up).  The
//     no-flow-up invariant depends on this absence;
//   - PROJECT check: both organization and project.  One request activates
//     global + matching-org + matching-project bindings simultaneously — the
//     Go three-level cascade collapses into a single Cerbos check.
func BuildResource(kind, id, organizationID, projectID string) (*sdk.Resource, error) {
	if kind == "" {
		return nil, fmt.Errorf("%w: kind is empty", ErrInvalidResource)
	}

	if projectID != "" && organizationID == "" {
		return nil, fmt.Errorf("%w: project %q without an organization", ErrInvalidResource, projectID)
	}

	if id == "" {
		id = CoarseResourceID
	}

	resource := sdk.NewResource(kind, id)

	if organizationID != "" {
		resource.WithAttr(attrOrganization, organizationID)
	}

	if projectID != "" {
		resource.WithAttr(attrProject, projectID)
	}

	return resource, nil
}

// BatchEntry pairs a built resource with the operations to check on it.
type BatchEntry struct {
	Resource *sdk.Resource
	Actions  []openapi.AclOperation
}

// BuildBatch assembles the CheckResources batch.  It guards the SDK's
// silent-drop footgun: ResourceBatch.Add silently no-ops on nil resources and
// empty action lists (cerbos-sdk-go model.go), which would turn a coding
// error into an authorization request that checks NOTHING.  The builder fails
// LOUDLY instead: no resources, a nil resource, an entry without actions and
// an empty action string (proto min_len 1) are all errors.  Actions pass
// through as string(openapi.AclOperation) verbatim, deduplicated (the proto
// requires unique actions) and sorted for deterministic requests.
func BuildBatch(entries []BatchEntry) (*sdk.ResourceBatch, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: no resources", ErrInvalidBatch)
	}

	batch := sdk.NewResourceBatch()

	for i, entry := range entries {
		if entry.Resource == nil {
			return nil, fmt.Errorf("%w: entry %d has a nil resource", ErrInvalidBatch, i)
		}

		actions, err := renderActions(entry.Actions)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}

		batch.Add(entry.Resource, actions...)
	}

	return batch, nil
}

// renderActions converts operations to wire actions, refusing shapes the SDK
// or proto would mishandle (see BuildBatch).
func renderActions(operations []openapi.AclOperation) ([]string, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("%w: no actions", ErrInvalidBatch)
	}

	actions := make([]string, 0, len(operations))

	for _, operation := range operations {
		if operation == "" {
			return nil, fmt.Errorf("%w: empty action", ErrInvalidBatch)
		}

		actions = append(actions, string(operation))
	}

	slices.Sort(actions)

	return slices.Compact(actions), nil
}
