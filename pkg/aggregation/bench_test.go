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

package aggregation_test

import (
	"fmt"
	"testing"

	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// BenchmarkResolve uses a namespace the size of a real one: 300 roles, 5 of them aggregating.
func BenchmarkResolve(b *testing.B) {
	const (
		plain       = 295
		aggregating = 5
		scopes      = 10
	)

	ops := []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}

	roles := map[string]*unikornv1.Role{}

	for i := range aggregating {
		role := newRole(fmt.Sprintf("aggregate-%d", i), aggregates(i%2 == 0))
		roles[role.Name] = role
	}

	for i := range plain {
		list := make([]unikornv1.RoleScope, 0, scopes)

		for j := range scopes {
			list = append(list, scope(fmt.Sprintf("svc-%d:thing-%d", i%40, j), ops[(i+j)%len(ops):]...))
		}

		role := newRole(fmt.Sprintf("plain-%d", i), aggregateTo(fmt.Sprintf("aggregate-%d", i%aggregating)), org(list...), project(list...))
		roles[role.Name] = role
	}

	for b.Loop() {
		aggregation.Resolve(roles)
	}
}
