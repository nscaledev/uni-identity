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

package authorizer

import "strings"

// tokenExchangePath is a URL path, not a credential — gosec G101 is a false positive here.
const tokenExchangePath = "/oauth2/v2/token" //nolint:gosec

// TokenExchangeURL returns the full token exchange endpoint URL for an identity host.
func TokenExchangeURL(identityHost string) string {
	return strings.TrimRight(identityHost, "/") + tokenExchangePath
}
