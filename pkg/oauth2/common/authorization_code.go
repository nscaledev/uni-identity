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

package common

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/identity/pkg/oauth2/types"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// TODO: use core error.
	ErrKey = errors.New("key error")
)

// getClientSecret fetches the client ID and secret.
func getClientSecret(ctx context.Context, cli client.Client, parameters *types.ConfigParameters) (string, string, error) {
	if parameters.Provider.Spec.ClientSecretName == "" {
		return parameters.Provider.Spec.ClientID, parameters.Provider.Spec.ClientSecret, nil
	}

	secret := &corev1.Secret{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: parameters.Provider.Namespace, Name: parameters.Provider.Spec.ClientSecretName}, secret); err != nil {
		return "", "", err
	}

	clientID, ok := secret.Data["id"]
	if !ok {
		return "", "", fmt.Errorf("%w: id key is not set", ErrKey)
	}

	clientSecret, ok := secret.Data["secret"]
	if !ok {
		return "", "", fmt.Errorf("%w: secrets key is not set", ErrKey)
	}

	return string(clientID), string(clientSecret), nil
}

// Config returns an oauth2 configuration.
func Config(ctx context.Context, cli client.Client, parameters *types.ConfigParameters, scopes []string) (*oauth2.Config, error) {
	clientID, clientSecret, err := getClientSecret(ctx, cli, parameters)
	if err != nil {
		return nil, err
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://" + parameters.Host + "/oidc/callback",
		Scopes:       scopes,
	}

	if parameters.Provider.Spec.AuthorizationURI != nil && parameters.Provider.Spec.TokenURI != nil {
		config.Endpoint.AuthURL = *parameters.Provider.Spec.AuthorizationURI
		config.Endpoint.TokenURL = *parameters.Provider.Spec.TokenURI
	}

	return config, nil
}

// Authorization gets the oauth2 authorization URL.
func Authorization(config *oauth2.Config, parameters *types.AuthorizationParamters, requestParameters []oauth2.AuthCodeOption) string {
	return config.AuthCodeURL(parameters.State, requestParameters...)
}

// CodeExchange exchanges a code with an oauth2 server.
func CodeExchange(ctx context.Context, client client.Client, parameters *types.CodeExchangeParameters) (*oauth2.Token, error) {
	config, err := Config(ctx, client, &parameters.ConfigParameters, nil)
	if err != nil {
		return nil, err
	}

	return config.Exchange(ctx, parameters.Code)
}
