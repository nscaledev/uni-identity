/*
Copyright 2025 the Unikorn Authors.

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

package v1alpha1

import (
	"errors"
	"iter"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var (
	ErrReference = errors.New("resource reference error")
)

// Paused implements the ReconcilePauser interface.
func (c *OAuth2Client) Paused() bool {
	return false
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *OAuth2Client) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (c *OAuth2Client) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, t, status, reason, message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *OAuth2Client) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

func (u *User) Session(clientID string) (*UserSession, error) {
	index := slices.IndexFunc(u.Spec.Sessions, func(session UserSession) bool {
		return session.ClientID == clientID
	})

	if index < 0 {
		return nil, ErrReference
	}

	return &u.Spec.Sessions[index], nil
}

func (l *OrganizationList) All() iter.Seq[*Organization] {
	return func(yield func(t *Organization) bool) {
		for i := range l.Items {
			if !yield(&l.Items[i]) {
				return
			}
		}
	}
}

func (l *ProjectList) All() iter.Seq[*Project] {
	return func(yield func(t *Project) bool) {
		for i := range l.Items {
			if !yield(&l.Items[i]) {
				return
			}
		}
	}
}

func (l *GroupList) All() iter.Seq[*Group] {
	return func(yield func(t *Group) bool) {
		for i := range l.Items {
			if !yield(&l.Items[i]) {
				return
			}
		}
	}
}
