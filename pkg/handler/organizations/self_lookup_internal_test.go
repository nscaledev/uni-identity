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

package organizations

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	selfTestNamespace = "organizations-test"
	selfCallerEmail   = "alice@example.com"
)

func selfTestUser(name, subject string) *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: selfTestNamespace,
			Name:      name,
		},
		Spec: unikornv1.UserSpec{
			Subject: subject,
			State:   unikornv1.UserStateActive,
		},
	}
}

// selfLookup asks for the user named by email, as the caller selfCallerEmail
// with no global permissions at all.
func selfLookup(t *testing.T, email string, objects ...client.Object) (*unikornv1.User, error) {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(s))

	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()

	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub:   selfCallerEmail,
			Email: ptr.To(selfCallerEmail),
		},
	}

	ctx := rbac.NewContext(t.Context(), &openapi.Acl{})

	return New(cli, selfTestNamespace).getUserbyEmail(ctx, userdb.NewUserDatabase(cli, selfTestNamespace), info, email)
}

// TestGetUserByEmailLetsACallerReadItselfInAnotherCase pins the self-check.  The
// address that a caller asks for can differ from its own only in case, for
// example when it comes from a stored record that the migration folded.  That
// is still the caller looking at itself, so it needs no global permission.
func TestGetUserByEmailLetsACallerReadItselfInAnotherCase(t *testing.T) {
	t.Parallel()

	user, err := selfLookup(t, "Alice@Example.com", selfTestUser("user-alice", selfCallerEmail))
	require.NoError(t, err)
	assert.Equal(t, "user-alice", user.Name)
}

// TestGetUserByEmailNeverAnswersForACaseTwin pins what the self-check lets
// through.  The check ignores case, but the lookup prefers an exact match.  If
// the lookup uses the address that the caller asked for, the caller can read a
// record that differs from its own only in case, with no global permission.
func TestGetUserByEmailNeverAnswersForACaseTwin(t *testing.T) {
	t.Parallel()

	user, err := selfLookup(t, "ALICE@example.com",
		selfTestUser("user-alice", selfCallerEmail),
		selfTestUser("user-twin", "ALICE@example.com"),
	)
	require.NoError(t, err)
	assert.Equal(t, "user-alice", user.Name, "a caller looking at itself must get its own record")
}

// TestGetUserByEmailStillGuardsOtherAddresses pins the reason the check exists.
// A caller with no global permission must not read another user.
func TestGetUserByEmailStillGuardsOtherAddresses(t *testing.T) {
	t.Parallel()

	_, err := selfLookup(t, "bob@example.com",
		selfTestUser("user-alice", selfCallerEmail),
		selfTestUser("user-bob", "bob@example.com"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted to read users globally")
}
