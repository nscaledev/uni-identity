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

package principal_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/principal"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestControllerInjectorSendsUnsignedPrincipal checks that a controller sends the
// principal in the same form as Injector. The cluster has no client certificate
// Secret, so any attempt to sign the value fails the call.  The actor makes the
// encoded value contain - and _, and its length needs padding in the padded
// forms, so a change of the encoding fails the test.
func TestControllerInjectorSendsUnsignedPrincipal(t *testing.T) {
	t.Parallel()

	resource := &metav1.ObjectMeta{
		Labels: map[string]string{
			constants.OrganizationPrincipalLabel: "org-1",
			constants.ProjectPrincipalLabel:      "project-1",
		},
		Annotations: map[string]string{
			constants.CreatorPrincipalAnnotation: "joe?~?~@acme.com",
		},
	}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)

	inject := principal.ControllerInjector(fake.NewClientBuilder().Build(), &coreclient.HTTPClientOptions{}, resource)
	require.NoError(t, inject(t.Context(), r))

	data, err := base64.RawURLEncoding.DecodeString(r.Header.Get(principal.Header))
	require.NoError(t, err)

	got := &principal.Principal{}
	require.NoError(t, json.Unmarshal(data, got))

	want, err := principal.FromResource(resource)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
