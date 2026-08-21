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

package generate

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// TestBindingExprUnknownBucket pins the fail-closed guard: a bucket without a
// binding expression must error, never silently receive the global (widest)
// condition — that failure mode would be privilege-widening.
func TestBindingExprUnknownBucket(t *testing.T) {
	t.Parallel()

	if _, err := bindingExpr("some-role-id", bucket("bogus")); !errors.Is(err, ErrUnknownBucket) {
		t.Fatalf("expected ErrUnknownBucket, got %v", err)
	}
}

// TestBucketsOfCoversAllRoleScopesFields pins the CRD shape bucketsOf
// hardcodes: it iterates exactly the Global, Organization and Project fields,
// so a bucket added to unikornv1.RoleScopes would otherwise have its grants
// silently dropped from the generated policies.
func TestBucketsOfCoversAllRoleScopesFields(t *testing.T) {
	t.Parallel()

	handled := []string{"Global", "Organization", "Project"}

	typ := reflect.TypeOf(unikornv1.RoleScopes{})

	fields := make([]string, 0, typ.NumField())

	for i := range typ.NumField() {
		fields = append(fields, typ.Field(i).Name)
	}

	if !slices.Equal(fields, handled) {
		t.Fatalf("unikornv1.RoleScopes has fields %v but the generator handles %v: extend bucketsOf and bindingExpr for the new bucket, then update this test", fields, handled)
	}
}
