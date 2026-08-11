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

package serviceaccounts

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestConvertRedactsAccessToken pins the read-path redaction that the ID-399
// read-surface audit's INCLUDE verdict for identity:serviceaccounts rests on:
// the stored long-lived access token is emitted only by convertCreate (create/
// rotate), never by the plain read conversion.
func TestConvertRedactsAccessToken(t *testing.T) {
	t.Parallel()

	const token = "live-long-lived-access-token"

	in := &unikornv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sa-id",
		},
		Spec: unikornv1.ServiceAccountSpec{
			AccessToken: token,
			// Fixed date: deterministic, and convert dereferences Expiry.Time,
			// so this must be non-nil (Expiry is *metav1.Time, types.go:410).
			Expiry: &metav1.Time{Time: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
	}

	out := convert(in, &unikornv1.GroupList{})

	serialized, err := json.Marshal(out)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), token,
		"serialized read response must not contain the access token")
	require.NotContains(t, string(serialized), "accessToken",
		"serialized read response must omit the accessToken key entirely")
}
