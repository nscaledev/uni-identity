/*
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

package providers

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/oauth2/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Provider interface {
	// Config returns an oauth2 configuration.
	Config(ctx context.Context, client client.Client, parameters *types.ConfigParameters) (*oauth2.Config, error)
	// Authorization gets the oauth2 authorization URL.
	AuthorizationURL(config *oauth2.Config, parameters *types.AuthorizationParamters) (string, error)
	// CodeExchange exchanges a code with an oauth2 server and returns a (possibly emulated) OIDC ID token.
	CodeExchange(ctx context.Context, client client.Client, parameters *types.CodeExchangeParameters) (*oauth2.Token, *oidc.IDToken, error)
}
