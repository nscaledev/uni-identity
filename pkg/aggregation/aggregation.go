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
	"fmt"
	"slices"
	"strings"

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
	// Skipped lists label matches that were not used, with the reason.
	Skipped []string
}

// plan is what one aggregating role is built from, before any scopes are
// resolved.
type plan struct {
	// sources are the role IDs used, refs and selector matches, sorted.
	sources []string
	// labelled are non-protected roles the selectors match, used or not.
	// The grantable check runs over these.
	labelled []string
	// skipped notes each match that is not used.
	skipped []string
	// missing are roleRefs that name no live role.
	missing []string
	// invalid is set when a selector is not allowed.
	invalid string
}

type computer struct {
	roles   map[string]*unikornv1.Role
	ids     []string
	plans   map[string]*plan
	inCycle map[string]bool
	results map[string]*Result
}

// Compute returns the desired status of every aggregating role in roles,
// keyed by role ID.  roles is keyed by role ID and must hold every role in
// the namespace.
func Compute(ctx context.Context, roles map[string]*unikornv1.Role) map[string]*Result {
	c := &computer{
		roles:   roles,
		plans:   map[string]*plan{},
		inCycle: map[string]bool{},
		results: map[string]*Result{},
	}

	for id := range roles {
		c.ids = append(c.ids, id)
	}

	slices.Sort(c.ids)

	for _, id := range c.ids {
		if c.live(id) && roles[id].IsAggregating() {
			c.plans[id] = c.plan(id)
		}
	}

	c.findCycles()

	for _, id := range c.ids {
		if _, ok := c.plans[id]; ok {
			c.resolve(id)
		}
	}

	for _, id := range c.ids {
		if result, ok := c.results[id]; ok {
			result.Grantable = c.grantable(ctx, result, c.plans[id].labelled)
		}
	}

	return c.results
}

// live tells whether a role exists and is not being deleted.  A role being
// deleted no longer counts as a source.
func (c *computer) live(id string) bool {
	role, ok := c.roles[id]

	return ok && role.DeletionTimestamp.IsZero()
}

// plan works out the sources of one aggregating role.
func (c *computer) plan(id string) *plan {
	rule := c.roles[id].Spec.AggregationRule

	p := &plan{}

	for _, ref := range rule.RoleRefs {
		switch {
		case ref == id:
		case !c.live(ref):
			p.missing = append(p.missing, ref)
		case !slices.Contains(p.sources, ref):
			p.sources = append(p.sources, ref)
		}
	}

	selectors, err := parseSelectors(rule.RoleSelectors)
	if err != nil {
		p.invalid = err.Error()

		return p
	}

	for _, candidate := range c.ids {
		if candidate != id && c.live(candidate) && matchesAny(selectors, c.roles[candidate]) {
			c.addMatch(p, candidate)
		}
	}

	slices.Sort(p.sources)

	return p
}

func matchesAny(selectors []labels.Selector, role *unikornv1.Role) bool {
	return slices.ContainsFunc(selectors, func(s labels.Selector) bool {
		return s.Matches(labels.Set(role.Labels))
	})
}

// addMatch records one selector match.  Protected roles are never used.
// Roles with global scopes are not used either, but are still checked by
// the grantable check, which then names them: no org admin can grant them.
func (c *computer) addMatch(p *plan, id string) {
	role := c.roles[id]

	switch {
	case role.Spec.Protected:
		p.skipped = append(p.skipped, displayName(role)+" (protected)")
	case len(role.Spec.Scopes.Global) > 0:
		p.skipped = append(p.skipped, displayName(role)+" (has global scopes)")
		p.labelled = append(p.labelled, id)
	default:
		p.labelled = append(p.labelled, id)

		if !slices.Contains(p.sources, id) {
			p.sources = append(p.sources, id)
		}
	}
}

// parseSelectors accepts only selectors made of aggregate-to-* match labels
// set to "true".  Anything looser, an empty selector or a match expression
// such as DoesNotExist, can select every role in the namespace, which would
// be a silent escalation.
func parseSelectors(in []metav1.LabelSelector) ([]labels.Selector, error) {
	out := make([]labels.Selector, 0, len(in))

	for i := range in {
		selector := &in[i]

		if len(selector.MatchExpressions) > 0 {
			return nil, fmt.Errorf("%w: roleSelectors[%d] uses matchExpressions, only aggregate-to-* matchLabels are allowed", ErrInvalidSelector, i)
		}

		if len(selector.MatchLabels) == 0 {
			return nil, fmt.Errorf("%w: roleSelectors[%d] is empty and would select every role", ErrInvalidSelector, i)
		}

		for key, value := range selector.MatchLabels {
			if !strings.HasPrefix(key, unikornv1.AggregateToLabelPrefix) || value != "true" {
				return nil, fmt.Errorf("%w: roleSelectors[%d] label %s=%s is not an aggregate-to-* label set to \"true\"", ErrInvalidSelector, i, key, value)
			}
		}

		parsed, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return nil, fmt.Errorf("%w: roleSelectors[%d]: %w", ErrInvalidSelector, i, err)
		}

		out = append(out, parsed)
	}

	return out, nil
}

// findCycles marks every aggregating role that is in a cycle, using
// Tarjan's strongly connected components.  A role is in a cycle when its
// component has more than one role: a role never depends on itself, as a
// self-ref and self-selection are ignored.
func (c *computer) findCycles() {
	t := &tarjan{
		c:       c,
		index:   map[string]int{},
		lowlink: map[string]int{},
		onStack: map[string]bool{},
	}

	for _, id := range c.ids {
		if _, aggregating := c.plans[id]; aggregating {
			if _, seen := t.index[id]; !seen {
				t.visit(id)
			}
		}
	}
}

type tarjan struct {
	c       *computer
	index   map[string]int
	lowlink map[string]int
	onStack map[string]bool
	stack   []string
	next    int
}

func (t *tarjan) visit(id string) {
	t.index[id] = t.next
	t.lowlink[id] = t.next
	t.next++

	t.stack = append(t.stack, id)
	t.onStack[id] = true

	for _, source := range t.c.plans[id].sources {
		if _, aggregating := t.c.plans[source]; !aggregating {
			continue
		}

		if _, seen := t.index[source]; !seen {
			t.visit(source)

			t.lowlink[id] = min(t.lowlink[id], t.lowlink[source])
		} else if t.onStack[source] {
			t.lowlink[id] = min(t.lowlink[id], t.index[source])
		}
	}

	if t.lowlink[id] == t.index[id] {
		t.popComponent(id)
	}
}

// popComponent pops one strongly connected component off the stack and
// marks its roles as in a cycle if it has more than one.
func (t *tarjan) popComponent(root string) {
	var component []string

	for {
		top := t.stack[len(t.stack)-1]
		t.stack = t.stack[:len(t.stack)-1]
		t.onStack[top] = false

		component = append(component, top)

		if top == root {
			break
		}
	}

	if len(component) > 1 {
		for _, member := range component {
			t.c.inCycle[member] = true
		}
	}
}

// scopesOf returns the scopes a source role holds.
func (c *computer) scopesOf(id string) unikornv1.RoleScopes {
	if _, aggregating := c.plans[id]; aggregating {
		return c.resolve(id)
	}

	return c.roles[id].Spec.Scopes
}

// lastScopes returns what an aggregating role should keep when it can't be
// computed: its last status, without global scopes, or, before the controller
// has ever written status, what its roleRefs hold, as the ACL build would
// give it.
func (c *computer) lastScopes(id string) unikornv1.RoleScopes {
	role := c.roles[id]

	if role.Status.EffectiveScopes != nil {
		scopes := role.EffectiveScopes()

		return *scopes.DeepCopy()
	}

	bootstrap := map[string]*unikornv1.Role{id: role.DeepCopy()}

	for _, ref := range role.Spec.AggregationRule.RoleRefs {
		if source, ok := c.roles[ref]; ok {
			bootstrap[ref] = source
		}
	}

	unikornv1.BootstrapRoles(bootstrap)

	return *bootstrap[id].Status.EffectiveScopes
}

// resolve computes one aggregating role.  Cycles are found up front, so a
// role in a cycle never recurses into it, and every other path is acyclic.
func (c *computer) resolve(id string) unikornv1.RoleScopes {
	if result, ok := c.results[id]; ok {
		return result.EffectiveScopes
	}

	role := c.roles[id]
	p := c.plans[id]

	result := &Result{Skipped: p.skipped}

	// Store before recursing, so a cycle member another role reaches gets
	// its kept scopes rather than a recomputation.
	c.results[id] = result

	switch {
	case c.inCycle[id]:
		result.EffectiveScopes = c.lastScopes(id)
		result.Available = Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonCycle,
			Message: "role is part of an aggregation cycle, keeping the last effective scopes",
		}
	case p.invalid != "":
		result.EffectiveScopes = c.lastScopes(id)
		result.Available = Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonInvalidSelector,
			Message: p.invalid + ", keeping the last effective scopes",
		}
	case len(p.missing) > 0:
		result.EffectiveScopes = c.lastScopes(id)
		result.Available = Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonMissingRoleRef,
			Message: "roleRefs name missing roles, keeping the last effective scopes: " + strings.Join(p.missing, ", "),
		}
	default:
		effective := unikornv1.RoleScopes{}

		for _, source := range p.sources {
			scopes := c.scopesOf(source)

			effective = unikornv1.MergeScopes(effective, scopes, role.Spec.AggregationRule.FlattenToOrganization)

			result.AggregatedFrom = append(result.AggregatedFrom, describe(c.roles[source], scopes))
		}

		result.EffectiveScopes = effective
		result.Available = Condition{
			Status:  corev1.ConditionTrue,
			Reason:  unikornv1.RoleReasonAggregated,
			Message: availableMessage(len(p.sources), p.skipped),
		}
	}

	if result.Available.Status != corev1.ConditionTrue {
		// The sources listed must match the scopes held.
		result.AggregatedFrom = slices.Clone(role.Status.AggregatedFrom)
	}

	return result.EffectiveScopes
}

func availableMessage(sources int, skipped []string) string {
	message := fmt.Sprintf("aggregated from %d source roles", sources)

	if len(skipped) > 0 {
		message += "; skipped: " + strings.Join(skipped, ", ")
	}

	return message
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
		Global:       unikornv1.UnionScopes(nil, scopes.Global),
		Organization: unikornv1.UnionScopes(nil, scopes.Organization),
		Project:      unikornv1.UnionScopes(nil, scopes.Project),
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		// RoleScopes is plain data, so this cannot fail.
		panic(err)
	}

	sum := sha256.Sum256(data)

	return "sha256:" + hex.EncodeToString(sum[:])
}

// grantable checks the role can grant every non-protected role labelled for
// it, using the same AllowRole check the API runs when an org admin grants a
// role.  A labelled role that is in use is held, so it passes unless the role
// is stuck on its last scopes.  The useful failures are a labelled role that
// was skipped for having global scopes, which no org admin can ever grant,
// and a stuck role that can't grant a newly labelled one.  The check runs
// over the real roles in each environment, so it sees roles from every chart
// and per-environment config, which a chart unit test cannot.
//
// The holder ACL puts project scopes in one linked project, as a group member
// with a linked project gets them.  A holder of a non-flattening role whose
// group has no linked project can grant less than this says.
func (c *computer) grantable(ctx context.Context, result *Result, labelled []string) Condition {
	ctx = rbac.NewContext(ctx, holderACL(result.EffectiveScopes))
	organizationID := ids.MustParseOrganizationID(grantCheckOrganizationID)

	var refused []string

	for _, id := range labelled {
		scopes := c.roles[id].Spec.Scopes

		if _, aggregating := c.plans[id]; aggregating {
			scopes = c.results[id].EffectiveScopes
			scopes.Global = c.roles[id].Spec.Scopes.Global
		}

		target := &unikornv1.Role{Spec: unikornv1.RoleSpec{Scopes: scopes}}

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
		Message: fmt.Sprintf("can grant all %d labelled roles", len(labelled)),
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
