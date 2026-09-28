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

package oauth2providers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestConvertRedactsClientSecret pins the read-path redaction that the ID-399
// read-surface audit's INCLUDE verdict for identity:oauth2providers rests on:
// the stored client secret must never appear in a serialized read response.
func TestConvertRedactsClientSecret(t *testing.T) {
	t.Parallel()

	const secret = "super-secret-client-credential"

	in := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "provider-id",
		},
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer:       "https://login.example.com",
			ClientSecret: secret,
		},
	}

	out := convert(in)

	serialized, err := json.Marshal(out)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), secret,
		"serialized read response must not contain the client secret")
	require.NotContains(t, string(serialized), "clientSecret",
		"serialized read response must omit the clientSecret key entirely")
}
