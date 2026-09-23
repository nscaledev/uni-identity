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

package userdb_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestErrUserInactiveWrapsErrResourceReference pins the compatibility contract:
// existing errors.Is(err, ErrResourceReference) callers must keep matching.
func TestErrUserInactiveWrapsErrResourceReference(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, userdb.ErrUserInactive, userdb.ErrResourceReference)
}

// TestErrAmbiguousSubjectWrapsErrResourceReference pins the same contract for
// a subject that folds onto more than one user.
func TestErrAmbiguousSubjectWrapsErrResourceReference(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, userdb.ErrAmbiguousSubject, userdb.ErrResourceReference)
}

func newSubjectUser(name, subject string) *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "userdb-test",
			Name:      name,
		},
		Spec: unikornv1.UserSpec{
			Subject: subject,
			State:   unikornv1.UserStateActive,
		},
	}
}

// TestGetUserRefusesAnAmbiguousFold checks that a subject which matches no
// record exactly, but folds onto two, resolves to neither.  Every login goes
// through GetUser, so a guess here can sign the caller in as another user.
func TestGetUserRefusesAnAmbiguousFold(t *testing.T) {
	t.Parallel()

	s := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(s))

	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(
		newSubjectUser("user-a", "Dave@Example.com"),
		newSubjectUser("user-b", "DAVE@example.com"),
	).Build()

	db := userdb.NewUserDatabase(cli, "userdb-test")

	_, err := db.GetUser(t.Context(), "dave@example.com")
	require.ErrorIs(t, err, userdb.ErrAmbiguousSubject)

	// An exact match still resolves, so a login that worked before still works.
	user, err := db.GetUser(t.Context(), "DAVE@example.com")
	require.NoError(t, err)
	assert.Equal(t, "user-b", user.Name)
}
