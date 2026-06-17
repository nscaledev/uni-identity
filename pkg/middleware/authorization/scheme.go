/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

package authorization

import (
	"net/http"
	"strings"

	"github.com/unikorn-cloud/core/pkg/server/errors"
)

// GetHTTPAuthenticationScheme extracts the authentication scheme and credential
// from the request's Authorization header (e.g. "bearer <token>"). It is shared
// by the local and remote authorizers so the header contract is parsed in one
// place.
func GetHTTPAuthenticationScheme(r *http.Request) (string, string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", "", errors.AccessDenied(r, "authorization header missing")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", "", errors.AccessDenied(r, "authorization header malformed")
	}

	return parts[0], parts[1], nil
}
