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

package rbac_test

import (
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// globalACLBoth grants read on two endpoints at global scope, so the legacy
// walk would ALLOW both — letting a served deny on either be attributed solely
// to the PDP.
func globalACLBoth(a, b string) *openapi.Acl {
	return &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: a, Operations: openapi.AclOperations{openapi.Read}},
			{Name: b, Operations: openapi.AclOperations{openapi.Read}},
		},
	}
}
