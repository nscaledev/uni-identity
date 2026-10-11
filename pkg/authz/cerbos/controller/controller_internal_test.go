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
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/validation"
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

// TestHashKeyRetainsCollisionResistantContentFingerprint pins the key material
// used to detect policy changes: at least 128 bits of SHA-256 must survive in
// the visible ConfigMap key so unrelated policy contents cannot realistically
// alias and suppress a Cerbos reload.
func TestHashKeyRetainsCollisionResistantContentFingerprint(t *testing.T) {
	t.Parallel()

	content := []byte("policy content")
	sum := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(sum[:])[:32]

	require.Equal(t, "resource_widget-"+expectedHash+".yaml", hashKey("resource_widget.yaml", content))
}

// TestHashKeyTruncatesLongBase pins the Kubernetes boundary independently of
// generator filename limits: even a future or older generator emitting an
// oversized sanitized base cannot make policy publication fail validation.
func TestHashKeyTruncatesLongBase(t *testing.T) {
	t.Parallel()

	key := hashKey(strings.Repeat("a", 400)+".yaml", []byte("policy content"))

	require.Len(t, key, maxConfigMapKeyLength)
	require.Empty(t, validation.IsConfigMapKey(key), "the bounded key must be accepted by Kubernetes")
	require.Regexp(t, `-[0-9a-f]{32}\.yaml$`, key, "truncation must preserve the complete 128-bit content suffix")
}
