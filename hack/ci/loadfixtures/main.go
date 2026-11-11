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

// load-fixtures builds the data and tokens for the load test (see
// test/load/README.md). It creates organizations, groups, projects, service
// accounts and users through the identity API, mints Auth0-shaped access
// tokens for those users with a throwaway key, and writes:
//   - tokens.json: the tokens the load tool reads
//   - jwks.json: the public key set to serve at <issuer>/.well-known/jwks.json
//
//nolint:forbidigo // stdout output is intentional
package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/unikorn-cloud/identity/hack/ci/internal/fixturelib"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

type tokenEntry struct {
	Token string `json:"token"`
	OrgID string `json:"orgId"`
	// Orgs is how many organizations the token's user belongs to.
	Orgs int `json:"orgs"`
}

type tokenFile struct {
	Dataset         string         `json:"dataset"`
	Auth0           []tokenEntry   `json:"auth0"`
	ServiceAccounts []tokenEntry   `json:"serviceAccounts"`
	Counts          map[string]int `json:"counts"`
}

func writeFile(dir, name string, data []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		fixturelib.Fatalf("failed to write %s: %v", name, err)
	}
}

// buildTokens mints the Auth0 tokens, cycling through the users, and collects
// the service account tokens.
func buildTokens(dataset string, m *minter, shp shape, users []user, orgs []org) tokenFile {
	out := tokenFile{Dataset: dataset}

	for i := range shp.tokens {
		u := users[i%len(users)]
		orgIDs := make([]string, 0, len(u.orgs))

		for _, index := range u.orgs {
			orgIDs = append(orgIDs, orgs[index].id)
		}

		out.Auth0 = append(out.Auth0, tokenEntry{Token: m.mint(u.email, orgIDs), OrgID: orgIDs[0], Orgs: len(orgIDs)})
	}

	for _, o := range orgs {
		out.ServiceAccounts = append(out.ServiceAccounts, tokenEntry{Token: o.saToken, OrgID: o.id, Orgs: 1})
	}

	return out
}

type options struct {
	baseURL, namespace, caCertPath string
	dataset, issuer, audience      string
	outDir                         string
}

func parseFlags() (options, shape) {
	var o options

	flag.StringVar(&o.baseURL, "base-url", os.Getenv("IDENTITY_BASE_URL"), "Identity service base URL")
	flag.StringVar(&o.namespace, "namespace", os.Getenv("IDENTITY_NAMESPACE"), "Namespace identity is deployed in")
	flag.StringVar(&o.caCertPath, "ca-cert", os.Getenv("IDENTITY_CA_CERT"), "Path to CA certificate bundle")
	flag.StringVar(&o.dataset, "dataset", "small", "Dataset size: small or large")
	flag.StringVar(&o.issuer, "issuer", "", "Issuer of the minted tokens (trailing slash included)")
	flag.StringVar(&o.audience, "audience", "", "Audience of the minted tokens")
	flag.StringVar(&o.outDir, "out-dir", ".", "Directory for tokens.json and jwks.json")
	flag.Parse()

	shp, ok := shapeFor(o.dataset)
	if !ok || o.baseURL == "" || o.namespace == "" || o.caCertPath == "" || o.issuer == "" || o.audience == "" {
		fixturelib.Fatalf("usage: load-fixtures --dataset small|large --base-url URL --namespace NS --ca-cert PATH --issuer URL --audience AUD [--out-dir DIR]")
	}

	return o, shp
}

func newBuilder(ctx context.Context, o options) *builder {
	cfg, err := config.GetConfig()
	if err != nil {
		fixturelib.Fatalf("failed to get kubeconfig: %v", err)
	}

	k8s, err := client.New(cfg, client.Options{Scheme: fixturelib.NewClientScheme()})
	if err != nil {
		fixturelib.Fatalf("failed to create Kubernetes client: %v", err)
	}

	certPEM, keyPEM := fixturelib.IssueCert(ctx, k8s, o.namespace, "ci-fixtures", "ci-fixtures")

	return &builder{
		ac:        fixturelib.NewAPIClient(o.baseURL, o.caCertPath, certPEM, keyPEM),
		k8s:       k8s,
		namespace: o.namespace,
	}
}

func main() {
	o, shp := parseFlags()
	ctx := context.Background()

	fixturelib.Quiet = true

	b := newBuilder(ctx, o)

	fixturelib.Logf("Creating %d organizations", shp.orgs)

	orgs := b.createOrgs(ctx, shp)

	users := plan(shp)

	fixturelib.Logf("Creating %d users", len(users))
	// In turn: adding a user updates its groups, and concurrent updates of
	// one group conflict (409) because the server does not retry them.
	for _, u := range users {
		b.createUser(ctx, orgs, u)
	}

	fixturelib.Logf("Minting %d tokens", shp.tokens)

	m := newMinter(o.issuer, o.audience)
	out := buildTokens(o.dataset, m, shp, users, orgs)

	out.Counts = map[string]int{
		"organizations":   shp.orgs,
		"groups":          shp.orgs * max(shp.groupsPerOrg, minGroups),
		"projects":        shp.orgs * shp.projectsPerOrg,
		"users":           len(users),
		"serviceAccounts": len(orgs),
		"auth0Tokens":     len(out.Auth0),
	}

	data, err := json.Marshal(out)
	if err != nil {
		fixturelib.Fatalf("failed to marshal tokens: %v", err)
	}

	writeFile(o.outDir, "tokens.json", data)
	writeFile(o.outDir, "jwks.json", m.jwks())

	fixturelib.Logf("dataset %s: %v", o.dataset, out.Counts)
}
