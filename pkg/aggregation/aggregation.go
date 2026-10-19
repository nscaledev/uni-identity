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

// Package aggregation computes the effective scopes of aggregating roles.
// It is pure: it reads a snapshot of every role and returns what each
// aggregating role's status should be.  The role controller writes the
// result, and tests use it to check the chart's role catalogue.
package aggregation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Placeholder IDs used to build a holder ACL for the grantable check.  The
// check only compares scopes, so any valid IDs will do.
const (
	grantCheckOrganizationID = "00000000-0000-0000-0000-000000000001"
	grantCheckProjectID      = "00000000-0000-0000-0000-000000000002"
)

// Condition is the desired state of one status condition.
type Condition struct {
	Status  corev1.ConditionStatus
	Reason  string
	Message string
}

// Result is the desired status of one aggregating role.
type Result struct {
	// EffectiveScopes are the scopes the role holds.
	EffectiveScopes unikornv1.RoleScopes
	// AggregatedFrom lists each source in use, sorted by ID.
	AggregatedFrom []unikornv1.RoleAggregationSource
	// Available is the Available condition.
	Available Condition
	// Grantable is the Grantable condition.
	Grantable Condition
	// Skipped lists selector matches that were not used, with the reason.
	Skipped []string
}

// ErrInvalidSelector is returned for a role selector that cannot be used.
var ErrInvalidSelector = errors.New("invalid role selector")

type visitState int

const (
	unvisited visitState = iota
	visiting
	visited
)

type computer struct {
	roles   map[string]*unikornv1.Role
	ids     []string
	state   map[string]visitState
	stack   []string
	inCycle map[string]bool
	results map[string]*Result
	// sources records, per aggregating role, the sources its selectors
	// matched and used, for the grantable check.
	selected map[string][]string
}

// Compute returns the desired status of every aggregating role in roles,
// keyed by role ID.  roles is keyed by role ID and must hold every role in
// the namespace.
func Compute(ctx context.Context, roles map[string]*unikornv1.Role) map[string]*Result {
	c := &computer{
		roles:    roles,
		state:    map[string]visitState{},
		inCycle:  map[string]bool{},
		results:  map[string]*Result{},
		selected: map[string][]string{},
	}

	for id := range roles {
		c.ids = append(c.ids, id)
	}

	slices.Sort(c.ids)

	for _, id := range c.ids {
		if roles[id].IsAggregating() {
			c.resolve(id)
		}
	}

	for _, id := range c.ids {
		if result, ok := c.results[id]; ok {
			result.Grantable = c.grantable(ctx, result, c.selected[id])
		}
	}

	return c.results
}

// scopesOf returns the scopes a role holds, using the computed result for an
// aggregating role.
func (c *computer) scopesOf(id string) unikornv1.RoleScopes {
	role := c.roles[id]

	if !role.IsAggregating() {
		return role.Spec.Scopes
	}

	return c.resolve(id)
}

// lastScopes returns what an aggregating role held before this pass.
func lastScopes(role *unikornv1.Role) unikornv1.RoleScopes {
	if role.Status.EffectiveScopes == nil {
		return unikornv1.RoleScopes{}
	}

	return *role.Status.EffectiveScopes.DeepCopy()
}

//nolint:cyclop,funlen
func (c *computer) resolve(id string) unikornv1.RoleScopes {
	role := c.roles[id]

	switch c.state[id] {
	case visited:
		return c.results[id].EffectiveScopes
	case visiting:
		// Every role on the stack from here up is part of the cycle.
		start := slices.Index(c.stack, id)

		for _, member := range c.stack[start:] {
			c.inCycle[member] = true
		}

		return lastScopes(role)
	case unvisited:
	}

	c.state[id] = visiting
	c.stack = append(c.stack, id)

	defer func() {
		c.stack = c.stack[:len(c.stack)-1]
		c.state[id] = visited
	}()

	rule := role.Spec.AggregationRule

	result := &Result{}

	var (
		missing  []string
		problems []string
	)

	sources := make([]string, 0, len(rule.RoleRefs))

	for _, ref := range rule.RoleRefs {
		if ref == id {
			continue
		}

		if _, ok := c.roles[ref]; !ok {
			missing = append(missing, ref)

			continue
		}

		sources = append(sources, ref)
	}

	selected, skipped, err := c.match(id, rule.RoleSelectors)
	if err != nil {
		problems = append(problems, err.Error())
	}

	result.Skipped = skipped
	c.selected[id] = selected

	for _, s := range selected {
		if !slices.Contains(sources, s) {
			sources = append(sources, s)
		}
	}

	slices.Sort(sources)

	effective := unikornv1.RoleScopes{}

	for _, source := range sources {
		scopes := c.scopesOf(source)

		effective = merge(effective, scopes, rule.FlattenToOrganization)

		result.AggregatedFrom = append(result.AggregatedFrom, describe(c.roles[source], scopes))
	}

	switch {
	case c.inCycle[id]:
		result.EffectiveScopes = lastScopes(role)
		result.Available = Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonCycle,
			Message: "role is part of an aggregation cycle, keeping the last effective scopes",
		}
	case len(missing) > 0:
		result.EffectiveScopes = lastScopes(role)
		result.Available = Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonMissingRoleRef,
			Message: "roleRefs name missing roles, keeping the last effective scopes: " + strings.Join(missing, ", "),
		}
	case len(problems) > 0:
		result.EffectiveScopes = lastScopes(role)
		result.Available = Condition{
			Status:  corev1.ConditionFalse,
			Reason:  string(unikornv1core.ConditionReasonErrored),
			Message: strings.Join(problems, "; ") + ", keeping the last effective scopes",
		}
	default:
		result.EffectiveScopes = effective
		result.Available = Condition{
			Status:  corev1.ConditionTrue,
			Reason:  unikornv1.RoleReasonAggregated,
			Message: availableMessage(len(sources), skipped),
		}
	}

	if result.Available.Status != corev1.ConditionTrue {
		// The sources listed must match the scopes held.
		result.AggregatedFrom = slices.Clone(role.Status.AggregatedFrom)
	}

	c.results[id] = result

	return result.EffectiveScopes
}

func availableMessage(sources int, skipped []string) string {
	message := fmt.Sprintf("aggregated from %d source roles", sources)

	if len(skipped) > 0 {
		message += "; skipped: " + strings.Join(skipped, ", ")
	}

	return message
}

// match returns the IDs of roles the selectors pick, sorted, and a note for
// each match that is not used.  A role never selects itself.  Protected roles
// and roles with global scopes are never selected: they would leak platform
// authority into an organization role.
func (c *computer) match(self string, selectors []metav1.LabelSelector) ([]string, []string, error) {
	parsed := make([]labels.Selector, 0, len(selectors))

	for i := range selectors {
		selector, err := metav1.LabelSelectorAsSelector(&selectors[i])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: roleSelectors[%d]: %w", ErrInvalidSelector, i, err)
		}

		// An empty selector matches everything.  Never allow that.
		if selector.Empty() {
			return nil, nil, fmt.Errorf("%w: roleSelectors[%d] is empty and would select every role", ErrInvalidSelector, i)
		}

		parsed = append(parsed, selector)
	}

	var (
		selected []string
		skipped  []string
	)

	for _, id := range c.ids {
		if id == self {
			continue
		}

		role := c.roles[id]

		matches := slices.ContainsFunc(parsed, func(s labels.Selector) bool {
			return s.Matches(labels.Set(role.Labels))
		})

		if !matches {
			continue
		}

		switch {
		case role.Spec.Protected:
			skipped = append(skipped, displayName(role)+" (protected)")
		case len(c.scopesOf(id).Global) > 0:
			skipped = append(skipped, displayName(role)+" (has global scopes)")
		default:
			selected = append(selected, id)
		}
	}

	return selected, skipped, nil
}

func displayName(role *unikornv1.Role) string {
	if name, ok := role.Labels[coreconstants.NameLabel]; ok {
		return name
	}

	return role.Name
}

func describe(role *unikornv1.Role, scopes unikornv1.RoleScopes) unikornv1.RoleAggregationSource {
	return unikornv1.RoleAggregationSource{
		ID:          role.Name,
		Name:        role.Labels[coreconstants.NameLabel],
		Description: role.Annotations[coreconstants.DescriptionAnnotation],
		ScopesHash:  Hash(scopes),
	}
}

// Hash returns a stable hash of a set of scopes: the same scopes always give
// the same hash, whatever order they are listed in.
func Hash(scopes unikornv1.RoleScopes) string {
	canonical := unikornv1.RoleScopes{
		Global:       union(nil, scopes.Global),
		Organization: union(nil, scopes.Organization),
		Project:      union(nil, scopes.Project),
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		// RoleScopes is plain data, so this cannot fail.
		panic(err)
	}

	sum := sha256.Sum256(data)

	return "sha256:" + hex.EncodeToString(sum[:])
}

// merge folds a source's scopes into an aggregating role's scopes.  Global
// scopes are never aggregated: they would hand out cross-organization
// authority.  Organization scopes stay at organization scope.  Project scopes
// stay at project scope, or move to organization scope when flatten is set.
func merge(into, source unikornv1.RoleScopes, flatten bool) unikornv1.RoleScopes {
	out := unikornv1.RoleScopes{
		Organization: union(into.Organization, source.Organization),
		Project:      into.Project,
	}

	if flatten {
		out.Organization = union(out.Organization, source.Project)
	} else {
		out.Project = union(out.Project, source.Project)
	}

	if len(out.Project) == 0 {
		out.Project = nil
	}

	if len(out.Organization) == 0 {
		out.Organization = nil
	}

	return out
}

// union returns the union of two scope lists, sorted by name, with the
// operations for each name merged and sorted.
func union(a, b []unikornv1.RoleScope) []unikornv1.RoleScope {
	operations := map[string][]unikornv1.Operation{}

	for _, list := range [][]unikornv1.RoleScope{a, b} {
		for _, scope := range list {
			operations[scope.Name] = append(operations[scope.Name], scope.Operations...)
		}
	}

	if len(operations) == 0 {
		return nil
	}

	out := make([]unikornv1.RoleScope, 0, len(operations))

	for name, ops := range operations {
		ops = slices.Clone(ops)
		slices.Sort(ops)

		out = append(out, unikornv1.RoleScope{Name: name, Operations: slices.Compact(ops)})
	}

	slices.SortFunc(out, func(x, y unikornv1.RoleScope) int {
		return strings.Compare(x.Name, y.Name)
	})

	return out
}

// grantable checks the role can grant every source its selectors picked,
// using the same AllowRole check the API runs when an org admin grants a
// role.  The check runs over the real roles in this environment, so it sees
// roles from every chart and per-environment config, which a chart unit test
// cannot.
func (c *computer) grantable(ctx context.Context, result *Result, selected []string) Condition {
	ctx = rbac.NewContext(ctx, holderACL(result.EffectiveScopes))
	organizationID := ids.MustParseOrganizationID(grantCheckOrganizationID)

	var refused []string

	for _, id := range selected {
		target := &unikornv1.Role{
			Spec: unikornv1.RoleSpec{
				Scopes: c.scopesOf(id),
			},
		}

		if err := rbac.AllowRole(ctx, target, organizationID); err != nil {
			refused = append(refused, displayName(c.roles[id]))
		}
	}

	if len(refused) > 0 {
		return Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonNotGrantable,
			Message: "cannot grant: " + strings.Join(refused, ", "),
		}
	}

	return Condition{
		Status:  corev1.ConditionTrue,
		Reason:  unikornv1.RoleReasonGrantable,
		Message: fmt.Sprintf("can grant all %d selected source roles", len(selected)),
	}
}

// holderACL builds the ACL a principal holding exactly these scopes gets in
// one organization: the organization block at organization scope and the
// project block in one project, as pkg/rbac builds it for group members.
func holderACL(scopes unikornv1.RoleScopes) *openapi.Acl {
	organization := openapi.AclOrganization{Id: grantCheckOrganizationID}

	if endpoints := toACLEndpoints(scopes.Organization); len(endpoints) > 0 {
		organization.Endpoints = &endpoints
	}

	if endpoints := toACLEndpoints(scopes.Project); len(endpoints) > 0 {
		projects := openapi.AclProjectList{
			{Id: grantCheckProjectID, Endpoints: endpoints},
		}

		organization.Projects = &projects
	}

	organizations := openapi.AclOrganizationList{organization}

	return &openapi.Acl{Organizations: &organizations}
}

func toACLEndpoints(scopes []unikornv1.RoleScope) openapi.AclEndpoints {
	endpoints := make(openapi.AclEndpoints, 0, len(scopes))

	for _, scope := range scopes {
		operations := make(openapi.AclOperations, len(scope.Operations))

		for i, operation := range scope.Operations {
			operations[i] = openapi.AclOperation(operation)
		}

		endpoints = append(endpoints, openapi.AclEndpoint{Name: scope.Name, Operations: operations})
	}

	return endpoints
}
