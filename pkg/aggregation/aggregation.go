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

// Package aggregation computes aggregating roles' scopes from live role specs, never from status.
package aggregation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Condition is the desired state of one status condition.
type Condition struct {
	Status  corev1.ConditionStatus
	Reason  string
	Message string
}

// Result is the desired status of one aggregating role.
type Result struct {
	EffectiveScopes unikornv1.RoleScopes
	AggregatedFrom  []unikornv1.RoleAggregationSource
	Available       Condition
	// Labelled are the matched non-protected roles, used or not, for the Grantable check.
	Labelled []LabelledRole
	Skipped  []string
}

// LabelledRole is a role labelled for an aggregating role.
type LabelledRole struct {
	ID     string
	Name   string
	Scopes unikornv1.RoleScopes
}

type plan struct {
	sources []string
	// labelled are the matched non-protected roles, used or not.
	labelled []string
	skipped  []string
	// missing are roleRefs that name no live role.
	missing []string
	// refused are roleRefs to a protected role other than the base role.
	refused []string
	invalid string
}

type computer struct {
	roles   map[string]*unikornv1.Role
	ids     []string
	plans   map[string]*plan
	cycles  map[string][]string
	results map[string]*Result
}

// Compute returns the result of every aggregating role; roles must hold every role in the namespace.
func Compute(roles map[string]*unikornv1.Role) map[string]*Result {
	c := &computer{
		roles:   roles,
		plans:   map[string]*plan{},
		cycles:  map[string][]string{},
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
			result.Labelled = c.labelledTargets(c.plans[id].labelled)
		}
	}

	return c.results
}

func (c *computer) live(id string) bool {
	role, ok := c.roles[id]

	return ok && role.DeletionTimestamp.IsZero()
}

func (c *computer) plan(id string) *plan {
	role := c.roles[id]

	p := &plan{}

	for _, ref := range role.Spec.AggregationRule.RoleRefs {
		switch {
		case ref == id:
		case !c.live(ref):
			if !slices.Contains(p.missing, ref) {
				p.missing = append(p.missing, ref)
			}
		case !role.MayRef(c.roles[ref]):
			if !slices.Contains(p.refused, ref) {
				p.refused = append(p.refused, ref)
			}
		case !slices.Contains(p.sources, ref):
			p.sources = append(p.sources, ref)
		}
	}

	c.planSelectors(id, p)

	slices.Sort(p.sources)

	return p
}

func (c *computer) planSelectors(id string, p *plan) {
	rule := c.roles[id].Spec.AggregationRule

	selectors, err := parseSelectors(rule.RoleSelectors)
	if err != nil {
		p.invalid = err.Error()

		return
	}

	for _, candidate := range c.ids {
		if candidate != id && c.live(candidate) && matchesAny(selectors, c.roles[candidate]) {
			c.addMatch(p, candidate)
		}
	}
}

func matchesAny(selectors []labels.Selector, role *unikornv1.Role) bool {
	return slices.ContainsFunc(selectors, func(s labels.Selector) bool {
		return s.Matches(labels.Set(role.Labels))
	})
}

// Plain roles with global scopes are not used but stay labelled, so the Grantable check names them.
func (c *computer) addMatch(p *plan, id string) {
	role := c.roles[id]
	byRef := slices.Contains(p.sources, id)

	switch {
	case role.Spec.Protected:
		if !byRef {
			p.skipped = append(p.skipped, role.DisplayName()+" (protected)")
		}
	case !role.IsAggregating() && len(role.Spec.Scopes.Global) > 0:
		if !byRef {
			p.skipped = append(p.skipped, role.DisplayName()+" (has global scopes)")
		}

		p.labelled = append(p.labelled, id)
	default:
		p.labelled = append(p.labelled, id)

		if !slices.Contains(p.sources, id) {
			p.sources = append(p.sources, id)
		}
	}
}

// parseSelectors allows only aggregate-to-* match labels set to "true": anything looser can select every role.
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

		// Sorted, so the status message does not change between reconciles.
		var bad []string

		for _, key := range slices.Sorted(maps.Keys(selector.MatchLabels)) {
			if value := selector.MatchLabels[key]; !validAggregateLabel(key, value) {
				bad = append(bad, key+"="+value)
			}
		}

		if len(bad) > 0 {
			return nil, fmt.Errorf("%w: roleSelectors[%d] labels %s are not valid aggregate-to-* labels set to \"true\"", ErrInvalidSelector, i, strings.Join(bad, ", "))
		}

		parsed, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return nil, fmt.Errorf("%w: roleSelectors[%d]: %w", ErrInvalidSelector, i, err)
		}

		out = append(out, parsed)
	}

	return out, nil
}

func validAggregateLabel(key, value string) bool {
	return strings.HasPrefix(key, unikornv1.AggregateToLabelPrefix) &&
		value == "true" &&
		len(validation.IsQualifiedName(key)) == 0 &&
		len(validation.IsValidLabelValue(value)) == 0
}

// findCycles uses Tarjan's SCCs: a component with more than one role is a cycle.
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
		slices.Sort(component)

		for _, member := range component {
			t.c.cycles[member] = component
		}
	}
}

func (c *computer) scopesOf(id string) unikornv1.RoleScopes {
	if _, aggregating := c.plans[id]; !aggregating {
		return c.roles[id].Spec.Scopes
	}

	return c.resolve(id)
}

// inputs: every role in a cycle uses the sources outside the cycle, so this never recurses into it.
func (c *computer) inputs(id string) []string {
	cycle, ok := c.cycles[id]
	if !ok {
		return c.plans[id].sources
	}

	var sources []string

	for _, member := range cycle {
		for _, source := range c.plans[member].sources {
			if !slices.Contains(cycle, source) && !slices.Contains(sources, source) {
				sources = append(sources, source)
			}
		}
	}

	slices.Sort(sources)

	return sources
}

// resolve fails closed: a missing or refused ref, bad selector or cycle gives nothing.
func (c *computer) resolve(id string) unikornv1.RoleScopes {
	if result, ok := c.results[id]; ok {
		return result.EffectiveScopes
	}

	p := c.plans[id]
	flatten := c.roles[id].Spec.AggregationRule.FlattenToOrganization

	result := &Result{
		Skipped:   p.skipped,
		Available: c.available(id),
	}

	// One set per level, sorted once: merging per source is quadratic.
	organization := unikornv1.ScopeSet{}
	projects := unikornv1.ScopeSet{}

	for _, source := range c.inputs(id) {
		contributed := contribution(c.scopesOf(source))

		organization.Add(contributed.Organization)

		if flatten {
			organization.Add(contributed.Project)
		} else {
			projects.Add(contributed.Project)
		}

		result.AggregatedFrom = append(result.AggregatedFrom, describe(c.roles[source], contributed))
	}

	effective := unikornv1.RoleScopes{
		Organization: organization.List(),
		Project:      projects.List(),
	}

	result.EffectiveScopes = effective

	c.results[id] = result

	return effective
}

func contribution(scopes unikornv1.RoleScopes) unikornv1.RoleScopes {
	return unikornv1.RoleScopes{
		Organization: unikornv1.UnionScopes(nil, scopes.Organization),
		Project:      unikornv1.UnionScopes(nil, scopes.Project),
	}
}

func (c *computer) available(id string) Condition {
	p := c.plans[id]

	switch cycle, inCycle := c.cycles[id]; {
	case inCycle:
		return Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonCycle,
			Message: "role is part of an aggregation cycle (" + strings.Join(cycle, ", ") + "), each role in it holds only what the roles outside it give" + c.otherProblems(id),
		}
	case p.invalid != "":
		return Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonInvalidSelector,
			Message: p.invalid + ", selectors give nothing, only roleRefs are used",
		}
	case len(p.refused) > 0:
		return Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonInvalidRoleRef,
			Message: "roleRefs name protected roles that are not " + c.roles[id].BaseRoleName() + ", they give nothing: " + strings.Join(p.refused, ", "),
		}
	case len(p.missing) > 0:
		return Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonMissingRoleRef,
			Message: "roleRefs name missing roles, they give nothing: " + strings.Join(p.missing, ", "),
		}
	default:
		return Condition{
			Status:  corev1.ConditionTrue,
			Reason:  unikornv1.RoleReasonAggregated,
			Message: availableMessage(len(p.sources), p.skipped),
		}
	}
}

// otherProblems lists what the Cycle reason would otherwise hide.
func (c *computer) otherProblems(id string) string {
	p := c.plans[id]

	var out string

	if p.invalid != "" {
		out += "; " + p.invalid + ", selectors give nothing"
	}

	if len(p.refused) > 0 {
		out += "; roleRefs name protected roles that are not " + c.roles[id].BaseRoleName() + ", they give nothing: " + strings.Join(slices.Sorted(slices.Values(p.refused)), ", ")
	}

	if len(p.missing) > 0 {
		out += "; roleRefs name missing roles, they give nothing: " + strings.Join(slices.Sorted(slices.Values(p.missing)), ", ")
	}

	return out
}

func availableMessage(sources int, skipped []string) string {
	message := fmt.Sprintf("aggregated from %d source roles", sources)

	if len(skipped) > 0 {
		message += "; skipped: " + strings.Join(skipped, ", ")
	}

	return message
}

func describe(role *unikornv1.Role, contributed unikornv1.RoleScopes) unikornv1.RoleAggregationSource {
	return unikornv1.RoleAggregationSource{
		ID:          role.Name,
		Name:        role.Labels[coreconstants.NameLabel],
		Description: role.Annotations[coreconstants.DescriptionAnnotation],
		ScopesHash:  Hash(contributed),
		Scopes:      &contributed,
	}
}

// Hash returns a hash of scopes that does not depend on their order.
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

// labelledTargets checks an aggregating role on what it holds live, never its own spec.scopes.
func (c *computer) labelledTargets(labelled []string) []LabelledRole {
	out := make([]LabelledRole, 0, len(labelled))

	for _, id := range labelled {
		scopes := c.roles[id].Spec.Scopes

		if _, aggregating := c.plans[id]; aggregating {
			scopes = c.results[id].EffectiveScopes
		}

		out = append(out, LabelledRole{ID: id, Name: c.roles[id].DisplayName(), Scopes: scopes})
	}

	return out
}
