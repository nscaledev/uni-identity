/*
Copyright 2024-2025 the Unikorn Authors.

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
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GroupList is a typed list of user/role bindings.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type GroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Group `json:"items"`
}

// Group describes a binding between users and roles.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Group struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GroupSpec   `json:"spec"`
	Status            GroupStatus `json:"status,omitempty"`
}

type GroupSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// UserIDs are a list of users that are members of the group.
	// Deprecated: use Subjects instead.
	UserIDs []string `json:"userIDs,omitempty"`
	// Subjects is a list of user subjects that are members of the group. Unlike
	// UserIDs these do not have to refer to objects within the user database; they
	// can refer to users at an external IdP, for example.
	Subjects []GroupSubject `json:"subjects,omitempty"`
	// ServiceAccountIDs are a list of service accounts that are members of
	// the group.
	ServiceAccountIDs []string `json:"serviceAccountIDs,omitempty"`
	// RoleIDs are a list of roles users of the group inherit.
	RoleIDs []string `json:"roleIDs,omitempty"`
}

// GroupStatus defines the status of the group.
type GroupStatus struct{}

// GroupSubject represents a user that is a member of the group. The ID identifies the
// account at the issuer, and the email and issuer fields help with legibility, since
// the ID tends to be opaque.
type GroupSubject struct {
	ID     string `json:"ID"` //nolint:tagliatelle
	Issuer string `json:"issuer"`
	Email  string `json:"email,omitempty"`
}
