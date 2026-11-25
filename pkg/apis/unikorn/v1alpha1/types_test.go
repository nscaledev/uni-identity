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

package v1alpha1_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/yaml"
)

func TestUserPendingAuthorizationCodesStoredForm(t *testing.T) {
	t.Parallel()

	user := unikornv1.User{
		Spec: unikornv1.UserSpec{
			PendingAuthorizationCodes: []unikornv1.PendingAuthorizationCode{{
				CodeID:   "code-id",
				ClientID: "client-id",
				Expiry:   metav1.NewTime(time.Date(2026, time.October, 8, 10, 0, 0, 0, time.UTC)),
			}},
		},
	}

	data, err := json.Marshal(user)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"metadata": {},
		"spec": {
			"subject": "",
			"state": "",
			"pendingAuthorizationCodes": [{
				"codeID": "code-id",
				"clientID": "client-id",
				"expiry": "2026-10-08T10:00:00Z"
			}]
		},
		"status": {}
	}`, string(data))
}

// The API server must reject a pending code list longer than the limit that
// the server applies, independently of the server code.
func TestUserCRDLimitsPendingAuthorizationCodes(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../../../charts/identity/crds/identity.unikorn-cloud.org_users.yaml")
	require.NoError(t, err)

	var crd struct {
		Spec struct {
			Versions []struct {
				Name   string `json:"name"`
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Properties struct {
									PendingAuthorizationCodes struct {
										MaxItems *int `json:"maxItems"`
									} `json:"pendingAuthorizationCodes"`
								} `json:"properties"`
							} `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"` //nolint:tagliatelle
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}

	require.NoError(t, yaml.Unmarshal(data, &crd))
	require.Len(t, crd.Spec.Versions, 1)
	require.Equal(t, "v1alpha1", crd.Spec.Versions[0].Name)

	maxItems := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec.Properties.PendingAuthorizationCodes.MaxItems
	require.NotNil(t, maxItems)
	require.Equal(t, unikornv1.MaxPendingAuthorizationCodes, *maxItems)
}
