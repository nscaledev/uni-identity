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

package fixtures

import (
	"context"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

const (
	TokenActor = "ella.purnell"

	PrincipalActor          = "robert.denero"
	PrincipalOrganizationID = "f18ccbbe-e61b-4fe9-bc00-2661f792f39e"
	PrincipalProjectID      = "ec9145b2-91dd-408b-8d8f-d4b5e3c6c360"

	WithOrganization = 1 << iota
	WithProject
)

// HandlerContextFixture provides the necessary identity based context
// for a handler unit test.
func HandlerContextFixture(ctx context.Context, flags int) context.Context {
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: TokenActor,
		},
	}

	p := &principal.Principal{
		Actor: PrincipalActor,
	}

	if flags&(WithOrganization|WithProject) != 0 {
		p.OrganizationID = PrincipalOrganizationID
	}

	if flags&WithProject != 0 {
		p.ProjectID = PrincipalProjectID
	}

	ctx = authorization.NewContext(ctx, info)
	ctx = principal.NewContext(ctx, p)

	return ctx
}
