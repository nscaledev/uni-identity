/*
Copyright 2024-2025 the Unikorn Authors.
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
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OrganizationList is a typed list of identity mappings.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OrganizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Organization `json:"items"`
}

// Organization describes an identity mapping.  The main job of this type
// is to take an email address identity, extract the domain and use it to
// resolve an identity provider.  It also is the place where users within
// that domain can be allowed based on groups/claims offered by that identity
// provider to limit access.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:printcolumn:name="namespace",type="string",JSONPath=".status.namespace"
// +kubebuilder:printcolumn:name="status",type="string",JSONPath=".status.conditions[?(@.type=='Available')].reason"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Organization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OrganizationSpec   `json:"spec"`
	Status            OrganizationStatus `json:"status,omitempty"`
}

// ProviderScope defines how to lookup the provider details.
type ProviderScope string

const (
	// ProviderScopeGlobal looks up the provider in the identity nanespace.
	ProviderScopeGlobal ProviderScope = "global"
	// ProviderScopeOrganization looks up the provider in the organization namespace.
	ProviderScopeOrganization ProviderScope = "organization"
)

// OrganizationSpec defines the required configuration for the server.
type OrganizationSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Domain is used by unikorn-identity to map an end-user provided
	// email address to an identity provider.  When this is set, then
	// the providerScope and providerName must be set.
	Domain *string `json:"domain,omitempty"`
	// ProviderScope tells the controller when to find the provider
	// details.
	ProviderScope *ProviderScope `json:"providerScope,omitempty"`
	// ProviderID is the ID of an oauth2/oidc provider when using a domain mapping.
	ProviderID *string `json:"providerId,omitempty"`
	// ProviderOptions is the configuration for a specific provider type.
	ProviderOptions *OrganizationProviderOptions `json:"providerOptions,omitempty"`
}

type OrganizationProviderOptions struct {
	// If the referenced provider is set to "google" then the following
	// parameters should be specified.
	Google *OrganizationProviderGoogleSpec `json:"google,omitempty"`
}

type OrganizationProviderGoogleSpec struct {
	// CustomerID is retrieved from the "Account Settings > Profile" page on
	// https://admin.google.com for your organisation and is required to
	// lookup user groups for fine-grained RBAC.
	CustomerID *string `json:"customerId,omitempty"`
}

// OrganizationStatus defines the status of the server.
type OrganizationStatus struct {
	// Namespace defines the namespace an organization's child resources reside in.
	Namespace string `json:"namespace,omitempty"`

	// Current service state of the resource.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}
