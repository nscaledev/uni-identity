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

package audit

type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Actor struct {
	Subject string `json:"subject"`
	// Issuer is the identity provider that authenticated the subject (the token
	// issuer, or a marker for non-token identities).
	Issuer string `json:"issuer,omitempty"`
	// Delegate is the authenticated caller that performed the request on the
	// subject's behalf, present only for an impersonated/delegated call.
	Delegate *Delegate `json:"delegate,omitempty"`
}

// Delegate is the party that performed a request on another subject's behalf.
type Delegate struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer,omitempty"`
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

type Operation struct {
	Verb string `json:"verb"`
}

type Result struct {
	Status int `json:"status"`
}
