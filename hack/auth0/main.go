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

// auth0 mints a single Auth0 access token via the password-realm grant and
// prints it to stdout. Use it to seed AUTH0_EXPIRED_JWT_TOKEN for the Auth0
// exchange integration tests: mint a token against the primary audience,
// paste it into your test/.env, and let it expire on its own — once expired
// it stays expired indefinitely (until Auth0 rotates the tenant signing key).
//
// Usage:
//
//	echo "AUTH0_EXPIRED_JWT_TOKEN=$(go run ./hack/auth0)" >> test/.env
//
// Required env: AUTH0_DOMAIN, AUTH0_AUDIENCE, AUTH0_CLIENT_ID,
// AUTH0_CLIENT_SECRET, AUTH0_USERNAME, AUTH0_PASSWORD.
// Optional env: AUTH0_REALM (default Username-Password-Authentication),
// AUTH0_SCOPE (default "openid profile email identity:token:exchange").
//
//nolint:forbidigo // stdout output is intentional for env-var capture
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	errAuth0TokenEndpoint = errors.New("auth0 token endpoint returned non-200")
	errAuth0MissingToken  = errors.New("auth0 response missing access_token")
	errMissingEnv         = errors.New("missing required environment variable")
)

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}

	return def
}

func requireEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		fatalf("%v: %s", errMissingEnv, key)
	}

	return v
}

// auth0Mint executes a password-realm grant against Auth0 and returns the raw
// access_token.
func auth0Mint(ctx context.Context, domain, audience, clientID, clientSecret, realm, scope, username, password string) (string, error) {
	body := map[string]string{
		"grant_type":    "http://auth0.com/oauth/grant-type/password-realm",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"username":      username,
		"password":      password,
		"realm":         realm,
		"scope":         scope,
		"audience":      audience,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	url := "https://" + strings.TrimRight(domain, "/") + "/oauth/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 15 * time.Second}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %s: %s", errAuth0TokenEndpoint, resp.Status, strings.TrimSpace(string(raw)))
	}

	var result struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // Auth0 token response field name is RFC 6749.
	}

	if err := json.Unmarshal(raw, &result); err != nil {
		return "", err
	}

	if result.AccessToken == "" {
		return "", errAuth0MissingToken
	}

	return result.AccessToken, nil
}

func main() {
	domain := requireEnv("AUTH0_DOMAIN")
	audience := requireEnv("AUTH0_AUDIENCE")
	clientID := requireEnv("AUTH0_CLIENT_ID")
	clientSecret := requireEnv("AUTH0_CLIENT_SECRET")
	username := requireEnv("AUTH0_USERNAME")
	password := requireEnv("AUTH0_PASSWORD")
	realm := envOrDefault("AUTH0_REALM", "Username-Password-Authentication")
	scope := envOrDefault("AUTH0_SCOPE", "openid profile email identity:token:exchange")

	token, err := auth0Mint(context.Background(), domain, audience, clientID, clientSecret, realm, scope, username, password)
	if err != nil {
		fatalf("mint failed: %v", err)
	}

	fmt.Println(token)
}
