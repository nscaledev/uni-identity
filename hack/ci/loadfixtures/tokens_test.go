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

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"

	"sigs.k8s.io/yaml"
)

// loadValues is the part of hack/ci/load-values.yaml that configures the
// bearer trust identity validates tokens with.
type loadValues struct {
	Providers map[string]struct {
		BearerTrust struct {
			Audience    string `json:"audience"`
			GroupsClaim string `json:"groupsClaim"`
		} `json:"bearerTrust"`
	} `json:"providers"`
}

// The tokens must pass the validator identity runs for a bearer-trusted
// issuer, configured with the audience and groups claim read from
// hack/ci/load-values.yaml.
func TestMintedTokensValidate(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../load-values.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var values loadValues

	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}

	trust := values.Providers["load-test-idp"].BearerTrust
	if trust.Audience == "" || trust.GroupsClaim != groupsClaim {
		t.Fatalf("load-values.yaml bearerTrust %+v does not match the minted groups claim %q", trust, groupsClaim)
	}

	var m *minter

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(m.jwks())
	}))
	defer server.Close()

	issuer := server.URL + "/"
	m = newMinter(issuer, trust.Audience)

	validator, err := auth0.NewValidator(auth0.Options{
		Issuer:      issuer,
		Audience:    trust.Audience,
		GroupsClaim: trust.GroupsClaim,
	})
	if err != nil {
		t.Fatal(err)
	}

	user, err := validator.Validate(t.Context(), m.mint("load-user-1-000@example.invalid", []string{"org"}))
	if err != nil {
		t.Fatal(err)
	}

	if user.Email != "load-user-1-000@example.invalid" || len(user.Groups) != 1 {
		t.Fatalf("unexpected user %+v", user)
	}
}
