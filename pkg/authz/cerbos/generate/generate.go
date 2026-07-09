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

// Package generate converts Role custom resources into Cerbos policy
// documents: one shared derived-roles document (binding-match conditions) and
// one root-scope resource policy per endpoint name.  It is a pure function
// over its inputs: no I/O, no Kubernetes client, no logging.  See the package
// README for the binding-string contract and the policy-model rationale.
package generate

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// apiVersion is the Cerbos policy API version for all emitted documents.
	apiVersion = "api.cerbos.dev/v1"

	// derivedRolesName names the single shared derived-roles document that
	// every resource policy imports.
	derivedRolesName = "uni_roles"

	// derivedRolesFileName is the store-relative path of that document.
	derivedRolesFileName = "derived_roles.yaml"

	// parentRole is the static Cerbos principal role every derived role
	// builds on; the request builder always sends it.
	parentRole = "principal"

	// policyVersion is the Cerbos policy version for all resource policies.
	policyVersion = "default"

	// rootScope is the top of the Cerbos scope chain.  M1 emits root-only
	// policies; org/project overlay scopes arrive with M2.
	rootScope = ""

	// scopePermissionsOverrideParent makes the root policy the grantor (the
	// RBAC ceiling).  The top of the chain must be a grantor: a consent-mode
	// policy cannot originate a grant, so an all-consent chain denies
	// everything (spike A13).
	scopePermissionsOverrideParent = "SCOPE_PERMISSIONS_OVERRIDE_PARENT"

	// effectAllow is the effect on every generated rule.  Grants are
	// additive, mirroring pkg/rbac's additive role union; denies are an M2
	// overlay concern.
	effectAllow = "EFFECT_ALLOW"
)

// bucket identifies one of the three RoleScopes buckets.  The literals are
// part of the naming contract: derived roles are named role_<roleID>_<bucket>
// and binding strings embed the same token.
type bucket string

const (
	bucketGlobal  bucket = "global"
	bucketOrg     bucket = "org"
	bucketProject bucket = "project"
)

// bucketScopes pairs a bucket with its scope list for iteration in emission
// order (global, org, project).
type bucketScopes struct {
	bucket bucket
	scopes []unikornv1.RoleScope
}

// bucketsOf returns a role's scope buckets in emission order.
func bucketsOf(role *unikornv1.Role) []bucketScopes {
	return []bucketScopes{
		{bucketGlobal, role.Spec.Scopes.Global},
		{bucketOrg, role.Spec.Scopes.Organization},
		{bucketProject, role.Spec.Scopes.Project},
	}
}

// derivedRoleName returns the derived-role definition name for a role and
// bucket.  The role_ prefix guards against Role IDs starting with a digit,
// which Cerbos would reject as an identifier.
func derivedRoleName(roleID string, b bucket) string {
	return "role_" + roleID + "_" + string(b)
}

// bindingExpr returns the CEL binding-match condition activating a derived
// role.  The binding-string formats embedded here — <roleID>#global,
// <roleID>#org#<organizationID>, <roleID>#project#<organizationID>#<projectID>
// — are a byte-exact cross-component contract shared with the request builder
// (see the package README).  Flow-down lives entirely in these conditions: a
// global binding matches any resource, an org binding needs a matching
// organization attribute, and a project binding needs both organization and
// project attributes, so a resource without a project attribute can never
// activate a project-bound role (no flow-up).
func bindingExpr(roleID string, b bucket) (string, error) {
	switch b {
	case bucketGlobal:
		return `"` + roleID + `#global" in P.attr.bindings`, nil
	case bucketOrg:
		return `("` + roleID + `#org#" + R.attr.organization) in P.attr.bindings`, nil
	case bucketProject:
		return `("` + roleID + `#project#" + R.attr.organization + "#" + R.attr.project) in P.attr.bindings`, nil
	default:
		// Fail closed: an unhandled bucket must never silently receive the
		// global (widest) condition.
		return "", fmt.Errorf("%w: %q", ErrUnknownBucket, b)
	}
}

// resourceKindPattern mirrors the declared (buf.validate) constraint on a
// resource policy's kind: github.com/cerbos/cerbos
// api/public/cerbos/policy/v1/policy.proto (ResourcePolicy.resource, tag
// v0.53.0, L73-76).  Verified against the pinned image: neither the disk
// loader nor `cerbos compile` enforces this pattern at v0.53.0 — only
// proto-validated surfaces (the Admin API) do — so this generation-time
// check is the sole line of defense keeping emitted stores inside the
// declared schema; CI compile cannot backstop this particular constraint.
// The pattern is deliberately loose: only the glob metacharacters !*?[]{}
// (and the empty string) are rejected.
var resourceKindPattern = regexp.MustCompile(`^[^!*?\[\]{}]+$`)

// grant is one endpoint's operations within a single (role, bucket).
type grant struct {
	endpoint string
	actions  []string
}

// collectGrants merges a bucket's scopes into sorted (endpoint, actions)
// grants: duplicate endpoint names union their operations, duplicate
// operations dedup, and entries with no operations grant nothing (matching
// pkg/rbac semantics).  Endpoint names are opaque open-vocabulary tokens and
// are never parsed, but granting operations on a name outside Cerbos's
// declared resource-kind schema (empty, or containing a glob metacharacter)
// is an error: the emitted store would violate ResourcePolicy's declared
// constraints (see resourceKindPattern).
func collectGrants(roleID string, scopes []unikornv1.RoleScope) ([]grant, error) {
	merged := map[string][]string{}

	for _, scope := range scopes {
		if len(scope.Operations) == 0 {
			continue
		}

		if scope.Name == "" {
			return nil, fmt.Errorf("%w: role %s grants operations on an empty endpoint name", ErrInvalidScope, roleID)
		}

		if !resourceKindPattern.MatchString(scope.Name) {
			return nil, fmt.Errorf("%w: role %s grants operations on endpoint name %q, which is not a valid Cerbos resource kind", ErrInvalidScope, roleID, scope.Name)
		}

		for _, operation := range scope.Operations {
			merged[scope.Name] = append(merged[scope.Name], string(operation))
		}
	}

	grants := make([]grant, 0, len(merged))

	for _, endpoint := range slices.Sorted(maps.Keys(merged)) {
		actions := merged[endpoint]
		slices.Sort(actions)

		grants = append(grants, grant{endpoint: endpoint, actions: slices.Compact(actions)})
	}

	return grants, nil
}

// validateRoleID rejects Role IDs the binding contract cannot represent.
// Role CR names are Kubernetes object names (identity generates UUIDs), so
// the canonical DNS-1123 subdomain rule applies: lower-case alphanumerics,
// '-' and '.'.  Enforcing that here guarantees the ID embeds verbatim into
// '#'-delimited binding strings and CEL string literals without any escaping.
func validateRoleID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty role ID", ErrInvalidRole)
	}

	if errs := validation.IsDNS1123Subdomain(id); len(errs) != 0 {
		return fmt.Errorf("%w: role ID %q is not a Kubernetes object name: %s", ErrInvalidRole, id, strings.Join(errs, "; "))
	}

	return nil
}

// policyFileName returns the store-relative file name for an endpoint's
// resource policy.  Endpoint names may contain characters that are unsafe in
// file names (e.g. '/'), so anything outside [a-zA-Z0-9._-] becomes '_'.
// File names are presentation only — the resource kind inside the document is
// the verbatim endpoint name — but two distinct endpoints must not silently
// share a file, so the caller checks for collisions (case-insensitively: the
// golden store is written on case-insensitive file systems such as macOS).
func policyFileName(endpoint string) string {
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, endpoint)

	return "resource_" + sanitized + ".yaml"
}

// Generate converts the given Role custom resources into a Cerbos policy
// store.  Output is deterministic in the input set: roles are sorted by CR
// name, endpoints and actions lexicographically, so input order is
// irrelevant and the emitted bytes are stable.
func Generate(roles []unikornv1.Role) (*Output, error) {
	sorted := slices.Clone(roles)

	slices.SortFunc(sorted, func(a, b unikornv1.Role) int {
		return strings.Compare(a.Name, b.Name)
	})

	seen := map[string]bool{}

	var definitions []DerivedRole

	rules := map[string][]Rule{}

	for i := range sorted {
		role := &sorted[i]

		if err := validateRoleID(role.Name); err != nil {
			return nil, err
		}

		if seen[role.Name] {
			return nil, fmt.Errorf("%w: duplicate role ID %q", ErrInvalidRole, role.Name)
		}

		seen[role.Name] = true

		for _, bucketed := range bucketsOf(role) {
			grants, err := collectGrants(role.Name, bucketed.scopes)
			if err != nil {
				return nil, err
			}

			if len(grants) == 0 {
				continue
			}

			name := derivedRoleName(role.Name, bucketed.bucket)

			expr, err := bindingExpr(role.Name, bucketed.bucket)
			if err != nil {
				return nil, err
			}

			definitions = append(definitions, DerivedRole{
				Name:        name,
				ParentRoles: []string{parentRole},
				Condition:   Condition{Match: Match{Expr: expr}},
			})

			for _, grant := range grants {
				rules[grant.endpoint] = append(rules[grant.endpoint], Rule{
					Actions:      grant.actions,
					DerivedRoles: []string{name},
					Effect:       effectAllow,
				})
			}
		}
	}

	return assemble(definitions, rules)
}

// assemble collects the definitions and per-endpoint rules into the final
// output documents, checking that every endpoint maps to a distinct policy
// file name.
func assemble(definitions []DerivedRole, rules map[string][]Rule) (*Output, error) {
	output := &Output{}

	if len(definitions) == 0 {
		return output, nil
	}

	output.DerivedRoles = &DerivedRolesDocument{
		APIVersion:   apiVersion,
		DerivedRoles: DerivedRoles{Name: derivedRolesName, Definitions: definitions},
	}

	endpoints := map[string]string{}

	for _, endpoint := range slices.Sorted(maps.Keys(rules)) {
		document := &ResourcePolicyDocument{
			APIVersion: apiVersion,
			ResourcePolicy: ResourcePolicy{
				Resource:           endpoint,
				Version:            policyVersion,
				Scope:              rootScope,
				ScopePermissions:   scopePermissionsOverrideParent,
				ImportDerivedRoles: []string{derivedRolesName},
				Rules:              rules[endpoint],
			},
		}

		output.ResourcePolicies = append(output.ResourcePolicies, document)

		name := policyFileName(endpoint)

		if other, collision := endpoints[strings.ToLower(name)]; collision {
			return nil, fmt.Errorf("%w: endpoints %q and %q both map to %q", ErrFileNameCollision, other, endpoint, name)
		}

		endpoints[strings.ToLower(name)] = endpoint
	}

	return output, nil
}

var (
	// ErrInvalidRole is returned for a Role CR the binding contract cannot
	// represent (empty, duplicate, or non-Kubernetes-name metadata.name).
	ErrInvalidRole = errors.New("invalid role")

	// ErrInvalidScope is returned for a RoleScope that grants operations
	// against an empty endpoint name.
	ErrInvalidScope = errors.New("invalid role scope")

	// ErrFileNameCollision is returned when two distinct endpoint names map
	// to the same sanitized policy file name, compared case-insensitively.
	ErrFileNameCollision = errors.New("policy file name collision")

	// ErrMarshal is returned when a policy document cannot be rendered.
	ErrMarshal = errors.New("cannot marshal policy document")

	// ErrUnknownBucket is returned when a scope bucket has no binding
	// expression; it guards against a future bucket silently widening to
	// the global condition.
	ErrUnknownBucket = errors.New("unknown scope bucket")
)

// Output holds the generated policy documents.
type Output struct {
	// DerivedRoles is the single shared derived-roles document, nil when no
	// role grants anything.
	DerivedRoles *DerivedRolesDocument

	// ResourcePolicies holds one root-scope resource policy per endpoint
	// name, sorted by endpoint name.
	ResourcePolicies []*ResourcePolicyDocument
}

// Files returns the serialized policy store as relative path to file
// content, marshaling the documents on demand.
func (o *Output) Files() (map[string][]byte, error) {
	files := map[string][]byte{}

	if o.DerivedRoles != nil {
		data, err := marshalDocument(o.DerivedRoles)
		if err != nil {
			return nil, err
		}

		files[derivedRolesFileName] = data
	}

	for _, document := range o.ResourcePolicies {
		data, err := marshalDocument(document)
		if err != nil {
			return nil, err
		}

		files[policyFileName(document.ResourcePolicy.Resource)] = data
	}

	return files, nil
}
