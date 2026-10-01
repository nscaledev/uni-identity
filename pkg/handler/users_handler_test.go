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

package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	usersTestNamespace = "test-namespace"
	usersTestOrgID     = "00000000-0000-4000-8000-000000000001"
	usersTestOrgNS     = "test-org-ns"
	usersTestAccountID = "11111111-1111-4111-8111-111111111111"
	usersTestSubject   = "alice@example.com"
)

func usersTestOrganization() *unikornv1.Organization {
	return &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: usersTestNamespace, Name: usersTestOrgID},
		Status:     unikornv1.OrganizationStatus{Namespace: usersTestOrgNS},
	}
}

func usersTestAccount(name string) *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: usersTestNamespace, Name: name},
		Spec:       unikornv1.UserSpec{Subject: usersTestSubject, State: unikornv1.UserStateActive},
	}
}

func usersTestMembership(account string) *unikornv1.OrganizationUser {
	return &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: usersTestOrgNS,
			Name:      "orguser-alice",
			Labels: map[string]string{
				constants.OrganizationLabel: usersTestOrgID,
				constants.UserLabel:         account,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
	}
}

// newUsersTestHandler builds a handler over two different fake clients. The
// cached client stands in for the informer cache, the direct client for the
// API server. A test that puts different objects in each shows which one the
// handler reads.
func newUsersTestHandler(t *testing.T, cachedObjects, directObjects []client.Object) *handler.Handler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	subjectIndex := func(o client.Object) []string {
		user, ok := o.(*unikornv1.User)
		if !ok {
			return nil
		}

		return []string{user.Spec.Subject}
	}

	cached := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(append([]client.Object{usersTestOrganization()}, cachedObjects...)...).
		WithIndex(&unikornv1.User{}, "spec.subject", subjectIndex).Build()
	direct := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(append([]client.Object{usersTestOrganization()}, directObjects...)...).
		WithIndex(&unikornv1.User{}, "spec.subject", subjectIndex).Build()

	options := &handler.Options{
		Issuer: handlercommon.IssuerValue{URL: "https://identity.example.com", Hostname: "identity.example.com"},
	}

	h, err := handler.New(cached, direct, usersTestNamespace, nil, nil, nil, rbac.New(cached, usersTestNamespace, &rbac.Options{}), options)
	require.NoError(t, err)

	return h
}

// usersTestRequest returns a request whose context carries an ACL with the
// given global grants, and the caller identity that a create needs.
func usersTestRequest(t *testing.T, method, path string, body []byte, global openapi.AclEndpoints) *http.Request {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: "test-subject"},
	})
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "test-principal", OrganizationID: usersTestOrgID})
	ctx = rbac.NewContext(ctx, &openapi.Acl{Global: &global})

	return httptest.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
}

// TestDeleteGlobalUserNeedsItsOwnScope pins the permission on the account
// delete. Global identity:users delete also removes members from any
// organization. An account delete cannot be undone, so it has a scope of its
// own, and the membership grant alone must not reach it.
func TestDeleteGlobalUserNeedsItsOwnScope(t *testing.T) {
	t.Parallel()

	h := newUsersTestHandler(t, nil, nil)

	membershipGrant := openapi.AclEndpoints{{Name: "identity:users", Operations: openapi.AclOperations{openapi.Delete}}}

	w := httptest.NewRecorder()
	h.DeleteApiV1UsersGlobalUserID(w, usersTestRequest(t, http.MethodDelete, "/api/v1/users/"+usersTestAccountID, nil, membershipGrant), ids.MustParseGlobalUserID(usersTestAccountID))
	assert.Equal(t, http.StatusForbidden, w.Code, "global identity:users delete must not allow an account delete")

	accountGrant := openapi.AclEndpoints{{Name: "identity:users/global", Operations: openapi.AclOperations{openapi.Delete}}}

	w = httptest.NewRecorder()
	h.DeleteApiV1UsersGlobalUserID(w, usersTestRequest(t, http.MethodDelete, "/api/v1/users/"+usersTestAccountID, nil, accountGrant), ids.MustParseGlobalUserID(usersTestAccountID))
	assert.Equal(t, http.StatusNotFound, w.Code, "identity:users/global delete must reach the account lookup")
}

// TestDeleteGlobalUserReadsMembershipsFromTheAPIServer pins the uncached client
// in the account delete. A stale cache that reports no membership deletes an
// account that still has one, and nothing restores it. Here only the API
// server holds the membership, so the handler must refuse with 409.
func TestDeleteGlobalUserReadsMembershipsFromTheAPIServer(t *testing.T) {
	t.Parallel()

	h := newUsersTestHandler(t,
		[]client.Object{usersTestAccount(usersTestAccountID)},
		[]client.Object{usersTestAccount(usersTestAccountID), usersTestMembership(usersTestAccountID)},
	)

	accountGrant := openapi.AclEndpoints{{Name: "identity:users/global", Operations: openapi.AclOperations{openapi.Delete}}}

	w := httptest.NewRecorder()
	h.DeleteApiV1UsersGlobalUserID(w, usersTestRequest(t, http.MethodDelete, "/api/v1/users/"+usersTestAccountID, nil, accountGrant), ids.MustParseGlobalUserID(usersTestAccountID))

	require.Equal(t, http.StatusConflict, w.Code, "the membership that only the API server holds must block the delete")

	body := &coreopenapi.Error{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), body))
	assert.Equal(t, "the account holds 1 organization membership", body.ErrorDescription)
}

// TestCreateUserFindsTheAccountThroughTheAPIServer pins the uncached account
// reader in the membership create. The cache can still hold an account that
// the account delete removed. Here only the cache holds it, so the handler
// must create a new account and not reuse the deleted one.
func TestCreateUserFindsTheAccountThroughTheAPIServer(t *testing.T) {
	t.Parallel()

	const deletedAccount = "user-alice-deleted"

	h := newUsersTestHandler(t, []client.Object{usersTestAccount(deletedAccount)}, nil)

	body, err := json.Marshal(&openapi.UserWrite{Spec: openapi.UserSpec{Subject: usersTestSubject, State: openapi.Active}})
	require.NoError(t, err)

	createGrant := openapi.AclEndpoints{{Name: "identity:users", Operations: openapi.AclOperations{openapi.Create}}}

	w := httptest.NewRecorder()
	h.PostApiV1OrganizationsOrganizationIDUsers(w, usersTestRequest(t, http.MethodPost, "/api/v1/organizations/"+usersTestOrgID+"/users", body, createGrant), ids.MustParseOrganizationID(usersTestOrgID))

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	created := &openapi.UserRead{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), created))
	assert.NotEqual(t, deletedAccount, created.Status.GlobalUserId, "the membership must not point at an account that only the cache holds")
}
