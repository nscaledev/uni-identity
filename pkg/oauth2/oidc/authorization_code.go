/*
Copyright 2025 the Unikorn Authors.
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

package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/core/pkg/util/retry"
	"github.com/unikorn-cloud/identity/pkg/oauth2/common"
	"github.com/unikorn-cloud/identity/pkg/oauth2/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrMissingField = errors.New("missing field")
)

// Config returns a oauth2 configuration via service discovery.
func Config(ctx context.Context, client client.Client, parameters *types.ConfigParameters, scopes []string) (*oidc.Provider, *oauth2.Config, error) {
	var provider *oidc.Provider

	callback := func() error {
		p, err := oidc.NewProvider(ctx, parameters.Provider.Spec.Issuer)
		if err != nil {
			return err
		}

		provider = p

		return nil
	}

	// The retry logic here is literally as a nicety for road-warriors whose
	// internet is going to take a while to come up, during which time service
	// discovery is going to fail.  The logic being your token will have expired
	// while the laptop was off, and will immediately try and refresh.  The first
	// API call as a result of that will be this.
	retryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := retry.Forever().DoWithContext(retryCtx, callback); err != nil {
		return nil, nil, err
	}

	scopes = slices.Concat([]string{oidc.ScopeOpenID, "profile", "email"}, scopes)

	config, err := common.Config(ctx, client, parameters, scopes)
	if err != nil {
		return nil, nil, err
	}

	config.Endpoint = provider.Endpoint()

	return provider, config, nil
}

// Authorization gets the oauth2 authorization URL.
func Authorization(config *oauth2.Config, parameters *types.AuthorizationParamters, requestParameters []oauth2.AuthCodeOption) (string, error) {
	requestParameters = append(requestParameters,
		oauth2.S256ChallengeOption(parameters.CodeVerifier),
		oidc.Nonce(parameters.Nonce),
	)

	// If the user provided an email as part of the loging screen, send that to the IdP to
	// optimize the process.
	if parameters.Email != "" {
		requestParameters = append(requestParameters, oauth2.SetAuthURLParam("login_hint", parameters.Email))
	}

	passThroughValues := []string{
		"prompt",
		"max_age",
		"acr_values",
	}

	for _, value := range passThroughValues {
		if parameters.Query.Has(value) {
			requestParameters = append(requestParameters, oauth2.SetAuthURLParam(value, parameters.Query.Get(value)))
		}
	}

	return common.Authorization(config, parameters, requestParameters), nil
}

// CodeExchange exchanges a code with an OIDC compliant server.
func CodeExchange(ctx context.Context, client client.Client, parameters *types.CodeExchangeParameters) (*oauth2.Token, *IDToken, error) {
	provider, config, err := Config(ctx, client, &parameters.ConfigParameters, nil)
	if err != nil {
		return nil, nil, err
	}

	// Exchange the code for an id_token, access_token and refresh_token with
	// the extracted code verifier.
	authURLParams := []oauth2.AuthCodeOption{
		oauth2.VerifierOption(parameters.CodeVerifier),
	}

	token, err := config.Exchange(ctx, parameters.Code, authURLParams...)
	if err != nil {
		return nil, nil, err
	}

	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, fmt.Errorf("%w: id_token not in response", ErrMissingField)
	}

	oidcConfig := &oidc.Config{
		ClientID:        config.ClientID,
		SkipIssuerCheck: parameters.SkipIssuerCheck,
	}

	idToken, err := provider.Verifier(oidcConfig).Verify(ctx, idTokenRaw)
	if err != nil {
		return nil, nil, err
	}

	idTokenClaims := &IDToken{}

	if err := idToken.Claims(idTokenClaims); err != nil {
		return nil, nil, err
	}

	return token, idTokenClaims, nil
}
