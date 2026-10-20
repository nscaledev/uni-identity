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

package role

import (
	"context"
	"fmt"
	"slices"
	"unicode/utf8"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// EventReasonEffectiveScopesChanged is the Event reason emitted when an
// aggregating role's effective scopes change.
const EventReasonEffectiveScopesChanged = "EffectiveScopesChanged"

// maxEventNote caps an Event note in bytes: events.k8s.io/v1 rejects notes
// of 1 KiB or more.
const maxEventNote = 1000

// Reconciler writes the status of aggregating roles.
type Reconciler struct {
	client   client.Client
	recorder events.EventRecorder
}

var _ reconcile.Reconciler = &Reconciler{}

// Reconcile computes one role's status from a snapshot of every role in its
// namespace.  It never writes spec, labels or annotations, and never adds a
// finalizer: there is nothing to clean up when a role goes.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := log.FromContext(ctx)

	role := &unikornv1.Role{}

	if err := r.client.Get(ctx, request.NamespacedName, role); err != nil {
		if kerrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}

		log.Error(err, "failed to get role")

		return reconcile.Result{RequeueAfter: coreconstants.DefaultYieldTimeout}, nil
	}

	// A plain role being deleted has no record to keep.
	if !role.DeletionTimestamp.IsZero() && !role.IsAggregating() {
		return reconcile.Result{}, nil
	}

	status, err := r.statusFor(ctx, role)
	if err != nil {
		log.Error(err, "failed to compute role status")

		return reconcile.Result{RequeueAfter: coreconstants.DefaultYieldTimeout}, nil
	}

	if equality.Semantic.DeepEqual(&role.Status, status) {
		return reconcile.Result{}, nil
	}

	previous := role.Status.DeepCopy()
	oldScopes := recordedScopes(&role.Status)

	role.Status = *status

	if err := r.client.Status().Update(ctx, role); err != nil {
		// A role that is gone needs no record.
		if kerrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}

		// Conflicts and API errors are transient: retry at a fixed interval.
		log.Info("failed to update role status, retrying", "error", err.Error())

		return reconcile.Result{RequeueAfter: coreconstants.DefaultYieldTimeout}, nil
	}

	r.recordChanges(ctx, role, previous, oldScopes)

	return reconcile.Result{}, nil
}

// statusFor returns what the role's status should be, whether or not it is
// being deleted.
func (r *Reconciler) statusFor(ctx context.Context, role *unikornv1.Role) (*unikornv1.RoleStatus, error) {
	if !role.DeletionTimestamp.IsZero() {
		return deletingStatus(role), nil
	}

	return r.desiredStatus(ctx, role)
}

// deletingStatus returns the status of an aggregating role that is being
// deleted, held by a finalizer.  The server gives it nothing (a role being
// deleted is never computed), so the record says so: it holds nothing, is
// not Available and cannot be granted.
func deletingStatus(role *unikornv1.Role) *unikornv1.RoleStatus {
	status := &unikornv1.RoleStatus{
		EffectiveScopes: &unikornv1.RoleScopes{},
		Conditions:      slices.Clone(role.Status.Conditions),
	}

	deleting := aggregation.Condition{
		Status:  corev1.ConditionFalse,
		Reason:  unikornv1.RoleReasonDeleting,
		Message: "role is being deleted, it holds nothing",
	}

	setCondition(status, role.Generation, unikornv1core.ConditionAvailable, deleting)
	setCondition(status, role.Generation, unikornv1.RoleConditionGrantable, deleting)

	return status
}

// desiredStatus returns what the role's status should be.  Status is a
// record for people: the identity server never reads it, it works the same
// answer out live.  A role that is not aggregating has no status: if it used
// to aggregate, the old record is cleared.
func (r *Reconciler) desiredStatus(ctx context.Context, role *unikornv1.Role) (*unikornv1.RoleStatus, error) {
	if !role.IsAggregating() {
		return &unikornv1.RoleStatus{}, nil
	}

	roles := &unikornv1.RoleList{}

	if err := r.client.List(ctx, roles, client.InNamespace(role.Namespace)); err != nil {
		return nil, err
	}

	snapshot := make(map[string]*unikornv1.Role, len(roles.Items))

	for i := range roles.Items {
		snapshot[roles.Items[i].Name] = &roles.Items[i]
	}

	// Use the copy this reconcile was asked about, in case the list differs.
	snapshot[role.Name] = role

	result, ok := aggregation.Compute(snapshot)[role.Name]
	if !ok {
		return nil, fmt.Errorf("%w: no aggregation result for role %s", errNoResult, role.Name)
	}

	scopes := result.EffectiveScopes

	status := &unikornv1.RoleStatus{
		EffectiveScopes: &scopes,
		AggregatedFrom:  result.AggregatedFrom,
		Conditions:      slices.Clone(role.Status.Conditions),
	}

	setCondition(status, role.Generation, unikornv1core.ConditionAvailable, result.Available)
	setCondition(status, role.Generation, unikornv1.RoleConditionGrantable, grantable(ctx, result))

	return status, nil
}

// recordedScopes returns the scopes a status records, without global scopes,
// for the change record.
func recordedScopes(status *unikornv1.RoleStatus) unikornv1.RoleScopes {
	if status.EffectiveScopes == nil {
		return unikornv1.RoleScopes{}
	}

	return unikornv1.RoleScopes{
		Organization: status.EffectiveScopes.Organization,
		Project:      status.EffectiveScopes.Project,
	}
}

func setCondition(status *unikornv1.RoleStatus, generation int64, t unikornv1core.ConditionType, c aggregation.Condition) {
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:               string(t),
		Status:             metav1.ConditionStatus(c.Status),
		Reason:             c.Reason,
		Message:            c.Message,
		ObservedGeneration: generation,
	})
}

// recordChanges emits an Event and a log line when the effective scopes
// change, naming each source that was added, removed or changed with its old
// and new hash.  The hashes let a reader see exactly which source moved.
func (r *Reconciler) recordChanges(ctx context.Context, role *unikornv1.Role, previous *unikornv1.RoleStatus, oldScopes unikornv1.RoleScopes) {
	log := log.FromContext(ctx)

	r.recordConditionChanges(ctx, role, previous)

	if len(role.Spec.Scopes.Global)+len(role.Spec.Scopes.Organization)+len(role.Spec.Scopes.Project) > 0 {
		log.Info("aggregating role has spec.scopes, they are ignored: move them to a base role in roleRefs")
	}

	oldHash := aggregation.Hash(oldScopes)
	newHash := aggregation.Hash(recordedScopes(&role.Status))

	// Compare by hash, so going from no status to empty scopes is no change.
	if oldHash == newHash {
		return
	}

	changes := sourceChanges(previous.AggregatedFrom, role.Status.AggregatedFrom)
	if len(changes) == 0 {
		changes = []sourceChange{{}}
	}

	for _, change := range changes {
		message := fmt.Sprintf("effective scopes changed from %s to %s", oldHash, newHash)

		if change.id != "" {
			message += fmt.Sprintf(": source %s (%s) %s, scopes hash %s -> %s", change.name, change.id, change.kind, orNone(change.oldHash), orNone(change.newHash))
		}

		r.recorder.Eventf(role, nil, corev1.EventTypeNormal, EventReasonEffectiveScopesChanged, "Aggregate", "%s", message)

		log.Info("effective scopes changed",
			"oldHash", oldHash, "newHash", newHash,
			"source", change.id, "sourceName", change.name, "change", change.kind,
			"oldSourceHash", change.oldHash, "newSourceHash", change.newHash)
	}
}

// recordConditionChanges emits a Warning Event and a log line when Available
// or Grantable turns False, or changes reason or message while False, so a
// stuck role is loud.  A stuck role holds only what its working sources give,
// so its admins may have just lost scopes, and the scope change record alone
// would not say why.  Grantable False because Available is False is not
// warned again: the Available warning already says why.
func (r *Reconciler) recordConditionChanges(ctx context.Context, role *unikornv1.Role, previous *unikornv1.RoleStatus) {
	for _, t := range []unikornv1core.ConditionType{unikornv1core.ConditionAvailable, unikornv1.RoleConditionGrantable} {
		current := meta.FindStatusCondition(role.Status.Conditions, string(t))
		if current == nil || current.Status != metav1.ConditionFalse {
			continue
		}

		if followsAvailable(t, current) {
			continue
		}

		old := meta.FindStatusCondition(previous.Conditions, string(t))
		if old != nil && old.Status == current.Status && old.Reason == current.Reason && old.Message == current.Message {
			continue
		}

		r.recorder.Eventf(role, nil, corev1.EventTypeWarning, current.Reason, "Aggregate", "%s", truncate(fmt.Sprintf("%s is False: %s", t, current.Message), maxEventNote))

		log.FromContext(ctx).Info("role condition is false", "condition", t, "reason", current.Reason, "message", current.Message)
	}
}

// followsAvailable tells whether a condition is Grantable False only because
// Available is False.
func followsAvailable(t unikornv1core.ConditionType, condition *metav1.Condition) bool {
	return t == unikornv1.RoleConditionGrantable &&
		(condition.Reason == unikornv1.RoleReasonNotAvailable || condition.Reason == unikornv1.RoleReasonDeleting)
}

type sourceChange struct {
	id      string
	name    string
	kind    string
	oldHash string
	newHash string
}

func sourceChanges(previous, current []unikornv1.RoleAggregationSource) []sourceChange {
	byID := func(sources []unikornv1.RoleAggregationSource) map[string]unikornv1.RoleAggregationSource {
		out := make(map[string]unikornv1.RoleAggregationSource, len(sources))

		for _, s := range sources {
			out[s.ID] = s
		}

		return out
	}

	oldSources := byID(previous)
	newSources := byID(current)

	var changes []sourceChange

	for _, s := range current {
		old, ok := oldSources[s.ID]

		switch {
		case !ok:
			changes = append(changes, sourceChange{id: s.ID, name: s.Name, kind: "added", newHash: s.ScopesHash})
		case old.ScopesHash != s.ScopesHash:
			changes = append(changes, sourceChange{id: s.ID, name: s.Name, kind: "changed", oldHash: old.ScopesHash, newHash: s.ScopesHash})
		}
	}

	for _, s := range previous {
		if _, ok := newSources[s.ID]; !ok {
			changes = append(changes, sourceChange{id: s.ID, name: s.Name, kind: "removed", oldHash: s.ScopesHash})
		}
	}

	return changes
}

// truncate cuts s to at most limit bytes, on a rune boundary, ending in "…"
// when anything was cut.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}

	const ellipsis = "…"

	end := limit - len(ellipsis)

	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}

	return s[:end] + ellipsis
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}

	return s
}
