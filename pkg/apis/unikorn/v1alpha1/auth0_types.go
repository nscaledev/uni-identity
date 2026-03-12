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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Auth0Organization tracks the status of an Organization's migration to Auth0.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories={unikorn,auth0}
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="auth0 organization",type="string",JSONPath=".status.organizationID"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Auth0Organization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            Auth0OrganizationStatus `json:"status,omitempty"`
}

// Auth0OrganizationStatus defines the observed state of an Auth0Organization.
//
//nolint:tagliatelle
type Auth0OrganizationStatus struct {
	// Conditions represents the latest available observations of an Auth0Organization's current state.
	Conditions []unikornv1.Condition `json:"conditions,omitempty"`
	// OrganizationID is the ID of the Organization in Auth0, if it has been migrated.
	OrganizationID string `json:"organizationID,omitempty"`
}

// Auth0OrganizationList is a list of Auth0Organizations.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Auth0OrganizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Auth0Organization `json:"items"`
}

// Auth0User tracks the status of a User's migration to Auth0.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories={unikorn,auth0}
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="auth0 user",type="string",JSONPath=".status.userID"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Auth0User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            Auth0UserStatus `json:"status,omitempty"`
}

// Auth0UserStatus defines the observed state of an Auth0User.
//
//nolint:tagliatelle
type Auth0UserStatus struct {
	// Conditions represents the latest available observations of an Auth0User's current state.
	Conditions []unikornv1.Condition `json:"conditions,omitempty"`
	// UserID is the ID of the User in Auth0, if it has been migrated.
	UserID string `json:"userID,omitempty"`
}

// Auth0UserList is a list of Auth0Users.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Auth0UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Auth0User `json:"items"`
}

// Auth0OrganizationMember tracks the status of an OrganizationUser's migration to Auth0.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories={unikorn,auth0}
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="auth0 organization",type="string",JSONPath=".status.organizationID"
// +kubebuilder:printcolumn:name="auth0 user",type="string",JSONPath=".status.userID"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Auth0OrganizationMember struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            Auth0OrganizationMemberStatus `json:"status,omitempty"`
}

// Auth0OrganizationMemberStatus defines the observed state of an Auth0OrganizationMember.
//
//nolint:tagliatelle
type Auth0OrganizationMemberStatus struct {
	// Conditions represents the latest available observations of an Auth0OrganizationMember's current state.
	Conditions []unikornv1.Condition `json:"conditions,omitempty"`
	// OrganizationID is the ID of the Organization in Auth0, if it has been migrated.
	OrganizationID string `json:"organizationID,omitempty"`
	// UserID is the ID of the User in Auth0, if it has been migrated.
	UserID string `json:"userID,omitempty"`
}

// Auth0OrganizationMemberList is a list of Auth0OrganizationMembers.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Auth0OrganizationMemberList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Auth0OrganizationMember `json:"items"`
}
