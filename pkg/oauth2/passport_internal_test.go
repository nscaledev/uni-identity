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

package oauth2

import (
	"context"
	goerrors "errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const passportTestNamespace = "passport-test"

var errPassportInternalBoom = goerrors.New("boom")

func getPassportInternalScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	return s
}

func newPassportInternalAuthenticator(t *testing.T, objects ...client.Object) *Authenticator {
	t.Helper()

	cli := fake.NewClientBuilder().WithScheme(getPassportInternalScheme(t)).WithObjects(objects...).Build()

	return &Authenticator{
		client:    cli,
		namespace: passportTestNamespace,
	}
}

func TestRequestedScope(t *testing.T) {
	t.Parallel()

	orgID := "org-1"
	projectID := "project-1"

	testCases := []struct {
		name         string
		options      *openapi.TokenRequestOptions
		expectedOrg  string
		expectedProj string
	}{
		{
			name:    "nil options",
			options: nil,
		},
		{
			name: "organization only",
			options: &openapi.TokenRequestOptions{
				XOrganizationId: &orgID,
			},
			expectedOrg: orgID,
		},
		{
			name: "organization and project",
			options: &openapi.TokenRequestOptions{
				XOrganizationId: &orgID,
				XProjectId:      &projectID,
			},
			expectedOrg:  orgID,
			expectedProj: projectID,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actualOrg, actualProject := requestedScope(test.options)
			assert.Equal(t, test.expectedOrg, actualOrg)
			assert.Equal(t, test.expectedProj, actualProject)
		})
	}
}

func TestValidateOrganizationScope(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		authz          *openapi.AuthClaims
		organizationID string
		expectError    string
	}{
		{
			name:           "empty organization scope is always allowed",
			authz:          nil,
			organizationID: "",
		},
		{
			name:           "nil authz fails closed",
			authz:          nil,
			organizationID: "org-1",
			expectError:    "organization not in scope",
		},
		{
			name: "user in organization succeeds",
			authz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  []string{"org-1"},
			},
			organizationID: "org-1",
		},
		{
			name: "user outside organization is denied",
			authz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  []string{"org-2"},
			},
			organizationID: "org-1",
			expectError:    "organization not in scope",
		},
		{
			name: "system account defers organization authorization to rbac",
			authz: &openapi.AuthClaims{
				Acctype: openapi.System,
			},
			organizationID: "org-1",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateOrganizationScope(test.authz, test.organizationID)

			if test.expectError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.expectError)
		})
	}
}

func TestNormalizeExchangeUserinfoError(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "https://test.example.com/oauth2/v2/token", nil)
	oauthErr := oauth2errors.OAuth2AccessDenied("token validation failed")
	coreErr := coreerrors.AccessDenied(req, "token validation failed")

	testCases := []struct {
		name string
		err  error
		test func(t *testing.T, err error)
	}{
		{
			name: "oauth2 error is preserved",
			err:  oauthErr,
			test: func(t *testing.T, err error) {
				t.Helper()

				assert.Same(t, oauthErr, err)
			},
		},
		{
			name: "core access denied is normalized",
			err:  coreErr,
			test: func(t *testing.T, err error) {
				t.Helper()

				var normalized *oauth2errors.Error
				require.ErrorAs(t, err, &normalized)
				assert.Equal(t, "token validation failed", normalized.Error())
			},
		},
		{
			name: "other errors are preserved",
			err:  errPassportInternalBoom,
			test: func(t *testing.T, err error) {
				t.Helper()

				assert.Same(t, errPassportInternalBoom, err)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			test.test(t, normalizeExchangeUserinfoError(test.err))
		})
	}
}

func TestHasBroaderScope(t *testing.T) {
	t.Parallel()

	globalACL := &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
		},
	}
	orgACL := &openapi.Acl{
		Organization: &openapi.AclOrganization{
			Id: "org-1",
			Endpoints: &openapi.AclEndpoints{
				{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
			},
		},
	}

	assert.False(t, hasBroaderScope(nil, "org-1"))
	assert.True(t, hasBroaderScope(globalACL, "org-1"))
	assert.True(t, hasBroaderScope(orgACL, "org-1"))
	assert.False(t, hasBroaderScope(orgACL, "org-2"))
	assert.False(t, hasBroaderScope(orgACL, ""))
}

func TestProjectInOrganization(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		objects      []client.Object
		organization string
		project      string
		expected     bool
	}{
		{
			name:         "organization missing",
			organization: "org-1",
			project:      "project-1",
			expected:     false,
		},
		{
			name: "organization has no namespace",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
				},
			},
			organization: "org-1",
			project:      "project-1",
			expected:     false,
		},
		{
			name: "project missing",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
					Status: unikornv1.OrganizationStatus{
						Namespace: "org-1-ns",
					},
				},
			},
			organization: "org-1",
			project:      "project-1",
			expected:     false,
		},
		{
			name: "project found",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
					Status: unikornv1.OrganizationStatus{
						Namespace: "org-1-ns",
					},
				},
				&unikornv1.Project{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "org-1-ns",
						Name:      "project-1",
						Labels: map[string]string{
							constants.OrganizationLabel: "org-1",
						},
					},
				},
			},
			organization: "org-1",
			project:      "project-1",
			expected:     true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			authenticator := newPassportInternalAuthenticator(t, test.objects...)
			ok, err := authenticator.projectInOrganization(t.Context(), test.organization, test.project)
			require.NoError(t, err)
			assert.Equal(t, test.expected, ok)
		})
	}
}

func TestValidateProjectScopeWithBroaderGrant(t *testing.T) {
	t.Parallel()

	authenticator := newPassportInternalAuthenticator(t,
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: passportTestNamespace,
				Name:      "org-1",
			},
			Status: unikornv1.OrganizationStatus{
				Namespace: "org-1-ns",
			},
		},
		&unikornv1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "org-1-ns",
				Name:      "project-1",
				Labels: map[string]string{
					constants.OrganizationLabel: "org-1",
				},
			},
		},
	)

	acl := &openapi.Acl{
		Organization: &openapi.AclOrganization{
			Id: "org-1",
			Endpoints: &openapi.AclEndpoints{
				{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
			},
		},
	}

	require.NoError(t, authenticator.validateProjectScope(t.Context(), acl, "org-1", "project-1"))

	err := authenticator.validateProjectScope(t.Context(), acl, "org-1", "project-2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project not in scope")
}

func TestValidateProjectScopeK8sFailure(t *testing.T) {
	t.Parallel()

	acl := &openapi.Acl{
		Organization: &openapi.AclOrganization{
			Id: "org-1",
			Endpoints: &openapi.AclEndpoints{
				{Name: "org:read", Operations: openapi.AclOperations{openapi.Read}},
			},
		},
	}

	testCases := []struct {
		name    string
		objects []client.Object
		get     func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
	}{
		{
			name: "organization lookup fails",
			get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*unikornv1.Organization); ok {
					return errPassportInternalBoom
				}

				return inner.Get(ctx, key, obj, opts...)
			},
		},
		{
			name: "project lookup fails",
			objects: []client.Object{
				&unikornv1.Organization{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: passportTestNamespace,
						Name:      "org-1",
					},
					Status: unikornv1.OrganizationStatus{
						Namespace: "org-1-ns",
					},
				},
			},
			get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*unikornv1.Project); ok {
					return errPassportInternalBoom
				}

				return inner.Get(ctx, key, obj, opts...)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cli := fake.NewClientBuilder().
				WithScheme(getPassportInternalScheme(t)).
				WithObjects(test.objects...).
				WithInterceptorFuncs(interceptor.Funcs{Get: test.get}).
				Build()

			authenticator := &Authenticator{
				client:    cli,
				namespace: passportTestNamespace,
			}

			err := authenticator.validateProjectScope(t.Context(), acl, "org-1", "project-1")
			require.Error(t, err)
			require.ErrorIs(t, err, errPassportInternalBoom)
			assert.Contains(t, err.Error(), "failed to verify project membership")
		})
	}
}
