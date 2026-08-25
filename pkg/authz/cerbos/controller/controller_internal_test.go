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

package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPolicyStoreSize pins the measurement the pre-publish size gate compares
// against the ConfigMap ceiling: the sum of key AND value bytes across Data.
// Counting keys (not values alone) is the deliberately conservative choice
// that lets the gate refuse an over-cap store at or before the API server
// would — so if the formula ever narrowed to values only this expectation must
// fail rather than let a store slip past the ceiling.
func TestPolicyStoreSize(t *testing.T) {
	t.Parallel()

	require.Equal(t, 0, policyStoreSize(nil), "an empty store measures zero")

	// len("role-a.yaml")=11 + len("hello")=5, plus len("b.yaml")=6 +
	// len("hi")=2 => 24.  A values-only sum would be 7 and fail here.
	data := map[string]string{
		"role-a.yaml": "hello",
		"b.yaml":      "hi",
	}
	require.Equal(t, 24, policyStoreSize(data), "size must sum key and value bytes across every entry")
}
