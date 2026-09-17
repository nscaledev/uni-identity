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

package oauth2

import (
	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/userdb"
)

// normalizeIDTokenSubject folds the email claim on an id_token in place.
//
// Callback resolves the user by this claim and stores the same token in the
// authorization code, so TokenAuthorizationCode and oidcIDToken both read the
// folded form from here.  Folding once at ingress saves every later consumer
// from needing its own fold, and it matches the trusted-issuer path, which
// already folds the claim before it resolves a user.
func normalizeIDTokenSubject(idToken *oidc.IDToken) {
	// A decoded authorization code or session cookie can carry no id_token.
	if idToken == nil {
		return
	}

	idToken.Email.Email = userdb.NormalizeSubject(idToken.Email.Email)
}
