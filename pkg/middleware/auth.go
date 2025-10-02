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

package middleware

import (
	// unikorn imports.
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	idclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/hybrid"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewAuthorizer is a convenience for constructing an authorizer that will, if necessary, distinguish between internal and external tokens.
// This is suitable for *consumers* of the identity service (for which, at least some tokens will be dispatched to the identity service); but,
// not for the identity service itself, which will want to use its own records to authenticate tokens that it issued itself.
func NewAuthorizer(kubeclient client.Client, clientopts *coreclient.HTTPClientOptions, internal, external *idclient.Options) openapi.Authorizer {
	if external.Host() == "" { // External OIDC has not been provided
		return remote.NewAuthorizer(kubeclient, internal, clientopts)
	}

	externalAuthn := remote.NewAuthenticator(kubeclient, external, clientopts)
	internalAuthn := remote.NewAuthenticator(kubeclient, internal, clientopts)

	return hybrid.NewAuthorizer(internalAuthn, externalAuthn, remote.NewACL(kubeclient, internal, clientopts))
}
