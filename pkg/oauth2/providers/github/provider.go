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

package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/identity/pkg/oauth2/common"
	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/oauth2/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrEmailLookup = errors.New("failed to lookup email")
)

//nolint:tagliatelle
type User struct {
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type Email struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

const githubAPIBase = "https://api.github.com"

type Client struct {
	token string
}

func NewClient(token string) *Client {
	return &Client{
		token: token,
	}
}

func (p *Client) do(ctx context.Context, path string, data any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIBase+path, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "bearer "+p.token)
	req.Header.Set("X-Github-Api-Version", "2022-11-28")

	c := &http.Client{}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, data); err != nil {
		return err
	}

	return nil
}

func (p *Client) GetUser(ctx context.Context) (*User, error) {
	user := &User{}

	if err := p.do(ctx, "/user", user); err != nil {
		return nil, err
	}

	return user, nil
}

func (p *Client) GetEmails(ctx context.Context) ([]Email, error) {
	var emails []Email

	if err := p.do(ctx, "/user/emails", &emails); err != nil {
		return nil, err
	}

	return emails, nil
}

func (p *Client) GetPrimaryEmail(ctx context.Context) (*Email, error) {
	emails, err := p.GetEmails(ctx)
	if err != nil {
		return nil, err
	}

	i := slices.IndexFunc(emails, func(email Email) bool { return email.Primary })
	if i < 0 {
		return nil, ErrEmailLookup
	}

	return &emails[i], nil
}

func (p *Client) IDToken(ctx context.Context) (*oidc.IDToken, error) {
	// User gives us information about the user...
	user, err := p.GetUser(ctx)
	if err != nil {
		return nil, err
	}

	// ...but not always an email address.
	email, err := p.GetPrimaryEmail(ctx)
	if err != nil {
		return nil, err
	}

	out := &oidc.IDToken{
		Profile: oidc.Profile{
			Name:    user.Name,
			Picture: user.AvatarURL,
		},
		Email: oidc.Email{
			Email:         email.Email,
			EmailVerified: email.Verified,
		},
	}

	return out, nil
}

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (*Provider) Config(ctx context.Context, client client.Client, parameters *types.ConfigParameters) (*oauth2.Config, error) {
	return common.Config(ctx, client, parameters, nil)
}

func (*Provider) AuthorizationURL(config *oauth2.Config, parameters *types.AuthorizationParamters) (string, error) {
	return common.Authorization(config, parameters, nil), nil
}

func (*Provider) CodeExchange(ctx context.Context, client client.Client, parameters *types.CodeExchangeParameters) (*oauth2.Token, *oidc.IDToken, error) {
	token, err := common.CodeExchange(ctx, client, parameters)
	if err != nil {
		return nil, nil, err
	}

	idToken, err := NewClient(token.AccessToken).IDToken(ctx)
	if err != nil {
		return nil, nil, err
	}

	return token, idToken, nil
}
