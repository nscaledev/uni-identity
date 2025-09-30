/*
Copyright 2025 the Unikorn Authors.

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

package common

import (
	"net/http"
	"strings"

	"github.com/unikorn-cloud/core/pkg/server/errors"
)

// BearerTokenExtractor extracts bearer tokens from HTTP Authorization headers.
type BearerTokenExtractor struct{}

// ExtractToken gets the bearer token from the Authorization header.
func (e *BearerTokenExtractor) ExtractToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.OAuth2InvalidRequest("authorization header missing")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", errors.OAuth2InvalidRequest("authorization header malformed")
	}

	scheme, token := parts[0], parts[1]
	if !strings.EqualFold(scheme, "bearer") {
		return "", errors.OAuth2InvalidRequest("authorization scheme not allowed").WithValues("scheme", scheme)
	}

	return token, nil
}
