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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
