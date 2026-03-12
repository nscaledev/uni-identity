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

package v1alpha1

import (
	unikornv1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (o *Auth0Organization) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

func (o *Auth0Organization) Paused() bool {
	return false
}

func (o *Auth0Organization) StatusConditionRead(t unikornv1.ConditionType) (*unikornv1.Condition, error) {
	return unikornv1.GetCondition(o.Status.Conditions, t)
}

func (o *Auth0Organization) StatusConditionWrite(t unikornv1.ConditionType, status corev1.ConditionStatus, reason unikornv1.ConditionReason, message string) {
	unikornv1.UpdateCondition(&o.Status.Conditions, t, status, reason, message)
}

func (u *Auth0User) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

func (u *Auth0User) Paused() bool {
	return false
}

func (u *Auth0User) StatusConditionRead(t unikornv1.ConditionType) (*unikornv1.Condition, error) {
	return unikornv1.GetCondition(u.Status.Conditions, t)
}

func (u *Auth0User) StatusConditionWrite(t unikornv1.ConditionType, status corev1.ConditionStatus, reason unikornv1.ConditionReason, message string) {
	unikornv1.UpdateCondition(&u.Status.Conditions, t, status, reason, message)
}

func (m *Auth0OrganizationMember) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

func (m *Auth0OrganizationMember) Paused() bool {
	return false
}

func (m *Auth0OrganizationMember) StatusConditionRead(t unikornv1.ConditionType) (*unikornv1.Condition, error) {
	return unikornv1.GetCondition(m.Status.Conditions, t)
}

func (m *Auth0OrganizationMember) StatusConditionWrite(t unikornv1.ConditionType, status corev1.ConditionStatus, reason unikornv1.ConditionReason, message string) {
	unikornv1.UpdateCondition(&m.Status.Conditions, t, status, reason, message)
}
