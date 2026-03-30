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

package principal

// Principal records information about what user insigated a request.
type Principal struct {
	// OrganizationID of the originating request (optional).
	OrganizationID string `json:"organizationId,omitempty"`
	// ProjectID of the originating request (optional).
	ProjectID string `json:"projectId,omitempty"`
	// Actor of the originating request, this may be an email address
	// for an end-user, a service identifier for a system service, or
	// the service account name.
	Actor string `json:"actor,omitempty"`
}
