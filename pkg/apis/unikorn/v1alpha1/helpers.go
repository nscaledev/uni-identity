/*
Copyright 2025 the Unikorn Authors.
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

package v1alpha1

import (
	"errors"
	"slices"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	quotaKindAnnotation        = "identity.unikorn-cloud.org/quota-kind"
	volumeGiBQuotaMetadataName = "volumegib"
	volumeGiBQuotaKind         = "volumeGiB"
)

var (
	ErrReference = errors.New("resource reference error")
)

// ResourceKind returns the quota kind exposed to allocation clients.
func (q *QuotaMetadata) ResourceKind() string {
	kind := q.Annotations[quotaKindAnnotation]
	if IsQuotaKindAlias(q.Name, kind) {
		return kind
	}

	return q.Name
}

// IsQuotaKindAlias reports whether a metadata name maps to a distinct public quota kind.
func IsQuotaKindAlias(metadataName, kind string) bool {
	return metadataName == volumeGiBQuotaMetadataName && kind == volumeGiBQuotaKind
}

// Paused implements the ReconcilePauser interface.
func (c *OAuth2Client) Paused() bool {
	return false
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *OAuth2Client) StatusConditionRead(t unikornv1core.ConditionType) (*metav1.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// SetProvisioningCondition sets the Available condition with a reason drawn from
// the provisioning vocabulary.
func (c *OAuth2Client) SetProvisioningCondition(status corev1.ConditionStatus, reason unikornv1core.ProvisioningConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, unikornv1core.ConditionAvailable, status, string(reason), message)
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
