/*
Copyright 2024-2025 the Unikorn Authors.

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

package microsoft

import (
	"context"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/oauth2/types"
)

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (*Provider) Config(ctx context.Context, parameters *types.ConfigParameters) (*oauth2.Config, error) {
	// Handle non-stardard issuers.
	ctx = gooidc.InsecureIssuerURLContext(ctx, "https://login.microsoftonline.com/{tenantid}/v2.0")

	_, config, err := oidc.Config(ctx, parameters, nil)

	return config, err
}

func (*Provider) AuthorizationURL(config *oauth2.Config, parameters *types.AuthorizationParamters) (string, error) {
	return oidc.Authorization(config, parameters, nil)
}

func (*Provider) CodeExchange(ctx context.Context, parameters *types.CodeExchangeParameters) (*oauth2.Token, *oidc.IDToken, error) {
	// Handle non-stardard issuers.
	ctx = gooidc.InsecureIssuerURLContext(ctx, "https://login.microsoftonline.com/{tenantid}/v2.0")

	parameters.SkipIssuerCheck = true

	return oidc.CodeExchange(ctx, parameters)
}
