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

// Package userdbtest gives tests a fake client that serves the indexes the user
// database queries.
package userdbtest

import (
	"github.com/unikorn-cloud/identity/pkg/userdb"

	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// NewClientBuilder returns a fake client builder that serves every index in
// userdb.Indexes.
func NewClientBuilder(scheme *runtime.Scheme) *fake.ClientBuilder {
	b := fake.NewClientBuilder().WithScheme(scheme)

	for _, index := range userdb.Indexes() {
		b = b.WithIndex(index.Object, index.Field, index.Func)
	}

	return b
}
