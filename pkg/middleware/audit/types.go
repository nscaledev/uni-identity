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

// Decision is one authorization decision reached while handling the
// request — the referenced resource, the action checked, and the
// allow/deny/unavailable verdict with its reason — read back from
// pkg/rbac's request-scoped decision accumulator (seeded by this middleware
// before calling the handler chain; see rbac.NewDecisionAccumulatorContext).
// Deliberately a local type rather than an alias of rbac.Decision, matching
// Resource/Operation/etc. above: the audit record's shape stays decoupled
// from pkg/rbac's internal type. The field vocabulary reuses
// pkg/rbac/decision_log.go's outcome/reason vocabulary so an audit record's
// decisions agree with the PDP decision log.
type Decision struct {
	ResourceKind string `json:"resourceKind"`
	ResourceID   string `json:"resourceId,omitempty"`
	Action       string `json:"action"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason"`
}
