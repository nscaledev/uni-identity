//go:build integration

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

package region_test

import (
	"context"
	"fmt"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/oauth2"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// StatePublicCloudOrgUser is named by the ai-gateway consumer pact. ai-gateway admits a serverless
// caller only through an organization tagged cloud_type=public.
const StatePublicCloudOrgUser = "the bearer belongs to a user in a public cloud organization"

// publicCloudTag is the organization tag ai-gateway grants serverless access by.
//
//nolint:gochecknoglobals
var publicCloudTag = unikornv1core.Tag{Name: "cloud_type", Value: "public"}

// HandlePublicCloudOrgUser seeds a user bearer, as HandleUserBearer does, in an organization that
// carries the public cloud tag.
func (sm *StateManager) HandlePublicCloudOrgUser(ctx context.Context, setup bool, params map[string]any, authenticator *oauth2.Authenticator, issuer common.IssuerValue) error {
	if err := sm.HandleUserBearer(ctx, setup, params, authenticator, issuer); err != nil || !setup {
		return err
	}

	orgID := getStringParam(unwrapPactParams(params), "organizationID", defaultEnvirOrganizationID)

	org := &unikornv1.Organization{}
	if err := sm.client.Get(ctx, client.ObjectKey{Namespace: sm.namespace, Name: orgID}, org); err != nil {
		return fmt.Errorf("failed to get organization %s: %w", orgID, err)
	}

	org.Spec.Tags = append(org.Spec.Tags, publicCloudTag)

	if err := sm.client.Update(ctx, org); err != nil {
		return fmt.Errorf("failed to tag organization %s: %w", orgID, err)
	}

	return nil
}
