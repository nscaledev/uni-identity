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

// Package client exposes internal References fields for white-box testing.
package client

import (
	"context"

	"github.com/unikorn-cloud/identity/pkg/openapi"

	crClient "sigs.k8s.io/controller-runtime/pkg/client"
)

// SetClientFactory replaces the HTTP client factory on r, allowing tests to
// inject a mock without going through the full Kubernetes service-discovery path.
func (r *References) SetClientFactory(f func(ctx context.Context, c crClient.Client, resource crClient.Object) (openapi.ClientWithResponsesInterface, error)) {
	r.clientFactory = f
}
