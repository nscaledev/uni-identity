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

package rbac

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	idconstants "github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// TestSrcIssDefaultMatchesMigrationGateSentinel pins the coupling between the
// empty-SrcIss default (srcIssOrUNISentinel) and the sentinel used for bare
// admin entries (idconstants.UNISentinel). Subjects with no propagated srcIss
// must land on the sentinel so they match only bare/sentinel admin entries —
// the legacy semantic deliberately reproduced by expandBareAdminSubjects in
// pkg/server. If either side changes independently, this test fails and calls
// attention to the other side needing the same change.
func TestSrcIssDefaultMatchesMigrationGateSentinel(t *testing.T) {
	t.Parallel()

	if got := srcIssOrUNISentinel(""); got != idconstants.UNISentinel {
		t.Fatalf("srcIssOrUNISentinel(\"\") = %q, want idconstants.UNISentinel (%q)", got, idconstants.UNISentinel)
	}

	if got := srcIssOrUNISentinel("https://staff.auth0.com"); got != "https://staff.auth0.com" {
		t.Fatalf("srcIssOrUNISentinel must not alter a non-empty srcIss, got %q", got)
	}
}

const (
	systemAccountNamespace = "system-account-test"
	systemAccountRoleID    = "region-service"
	systemAccountCN        = "unikorn-region"
	systemAccountSPIFFEID  = "spiffe://example.org/ns/region/sa/region"
)

// newSystemAccountRBAC returns an RBAC with one role that both a common name and
// a SPIFFE ID map to, and a count of the reads it makes from the cluster.
func newSystemAccountRBAC(t *testing.T) (*RBAC, *atomic.Int32) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	role := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: systemAccountNamespace,
			Name:      systemAccountRoleID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}

	reads := &atomic.Int32{}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(role).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			reads.Add(1)

			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			reads.Add(1)

			return c.List(ctx, list, opts...)
		},
	}).Build()

	options := &Options{
		SystemAccountRoleIDs: map[string]string{
			systemAccountCN:       systemAccountRoleID,
			systemAccountSPIFFEID: systemAccountRoleID,
		},
	}

	return New(c, systemAccountNamespace, options), reads
}

func systemAccountContext(t *testing.T, subject string) context.Context {
	t.Helper()

	info := &authorization.Info{
		SystemAccount: true,
		Userinfo: &openapi.Userinfo{
			Sub: subject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.System,
			},
		},
	}

	return authorization.NewContext(t.Context(), info)
}

func TestSystemAccountNotRegistered(t *testing.T) {
	t.Parallel()

	r, _ := newSystemAccountRBAC(t)

	_, err := r.GetACL(systemAccountContext(t, "unikorn-unknown"), "")
	require.ErrorIs(t, err, ErrSystemAccountNotRegistered)
}

// TestSystemAccountSPIFFEIDHasRoleOfCommonName checks that a SPIFFE ID key in the
// one registry map gives the same role as a common name key.
func TestSystemAccountSPIFFEIDHasRoleOfCommonName(t *testing.T) {
	t.Parallel()

	r, _ := newSystemAccountRBAC(t)

	commonNameACL, err := r.GetACL(systemAccountContext(t, systemAccountCN), "")
	require.NoError(t, err)
	require.NotNil(t, commonNameACL.Global)
	require.NotEmpty(t, *commonNameACL.Global)

	spiffeACL, err := r.GetACL(systemAccountContext(t, systemAccountSPIFFEID), "")
	require.NoError(t, err)
	require.Equal(t, commonNameACL, spiffeACL)
}

// TestSystemAccountNotRegisteredImpersonating checks that an unregistered subject
// is refused before identity reads anything for the impersonated principal.
func TestSystemAccountNotRegisteredImpersonating(t *testing.T) {
	t.Parallel()

	r, reads := newSystemAccountRBAC(t)

	ctx := systemAccountContext(t, "unikorn-unknown")
	ctx = principal.NewContext(ctx, &principal.Principal{
		Type:            openapi.User,
		Actor:           "joe@acme.com",
		OrganizationIDs: []string{"acme"},
	})
	ctx = principal.NewImpersonateContext(ctx)

	_, err := r.GetACL(ctx, "acme")
	require.ErrorIs(t, err, ErrSystemAccountNotRegistered)
	require.Zero(t, reads.Load())
}
