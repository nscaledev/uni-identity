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
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers/github"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers/google"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers/microsoft"
)

func New(providerType *unikornv1.IdentityProviderType) Provider {
	if providerType == nil {
		return newNullProvider()
	}

	switch *providerType {
	case unikornv1.GoogleIdentity:
		return google.New()
	case unikornv1.MicrosoftEntra:
		return microsoft.New()
	case unikornv1.GitHub:
		return github.New()
	}

	return newNullProvider()
}
