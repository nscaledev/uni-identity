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

package webhooks

import (
	"net/http"

	"github.com/spf13/pflag"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Options struct {
	auth0MigrationWebhookSecret string
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.auth0MigrationWebhookSecret, "auth0-migration-webhook-secret", "", "The secret used to validate Auth0 webhook requests.")
}

type Client struct {
	kubeClient client.Client
	options    *Options
}

func NewClient(kubeClient client.Client, options *Options) *Client {
	return &Client{
		kubeClient: kubeClient,
		options:    options,
	}
}

func (c *Client) HandleAuth0MigrationWebhook(r *http.Request) error {
	return NewAuth0MigrationWebhookHandler(c.kubeClient, c.options.auth0MigrationWebhookSecret).Handle(r)
}
