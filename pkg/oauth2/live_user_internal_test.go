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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/userdb"
	"github.com/unikorn-cloud/identity/pkg/userdb/userdbtest"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var errFieldSelectorOnLive = errors.New("field selector sent to the live client: the API server refuses these on a custom resource")

// newSplitAuthenticator returns an authenticator whose live client has no
// indexes and refuses any List with a field selector, as the API server does,
// and whose reader is a separate indexed fake standing in for the informer
// cache. Swapping the two, or listing by index through the live client, fails.
func newSplitAuthenticator(t *testing.T, cached, live []client.Object) *Authenticator {
	t.Helper()

	scheme := getPassportInternalScheme(t)

	liveClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(live...).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				options := client.ListOptions{}
				options.ApplyOptions(opts)

				if options.FieldSelector != nil {
					return errFieldSelectorOnLive
				}

				return c.List(ctx, list, opts...)
			},
		}).
		Build()

	reader := userdbtest.NewClientBuilder(scheme).WithObjects(cached...).Build()

	return &Authenticator{
		client:     liveClient,
		reader:     reader,
		namespace:  passportTestNamespace,
		userdb:     userdb.NewUserDatabase(reader, passportTestNamespace),
		tokenCache: cache.NewLRUExpireCache(16),
	}
}

func splitOAuth2Client() *unikornv1.OAuth2Client {
	return &unikornv1.OAuth2Client{
		ObjectMeta: metav1.ObjectMeta{Namespace: passportTestNamespace, Name: conflictClientID},
		Status:     unikornv1.OAuth2ClientStatus{Secret: conflictSecret},
	}
}

// splitUsers returns a record of each shape the lookup serves, for the same
// subject: named for the subject, random-named with the subject-ID label, and
// random-named with no label.
func splitUsers() map[string]*unikornv1.User {
	named := conflictUser()
	named.Name = unikornv1.GlobalUserName(conflictStored)

	labelled := conflictUser()
	labelled.Labels = map[string]string{unikornv1.UserSubjectIDLabel: unikornv1.GlobalUserName(conflictStored)}

	return map[string]*unikornv1.User{
		"named":    named,
		"labelled": labelled,
		"legacy":   conflictUser(),
	}
}

func TestGetLiveUserReadsLiveThroughTheCacheIndexes(t *testing.T) {
	t.Parallel()

	for name, user := range splitUsers() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := newSplitAuthenticator(t, []client.Object{user.DeepCopy()}, []client.Object{user.DeepCopy()})

			got, err := a.getLiveUser(t.Context(), conflictStored)
			require.NoError(t, err)
			assert.Equal(t, user.Name, got.Name)
		})
	}
}

func TestGetLiveUserReturnsTheLiveRecord(t *testing.T) {
	t.Parallel()

	for name, user := range splitUsers() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			stale := user.DeepCopy()
			stale.Spec.State = unikornv1.UserStateSuspended

			a := newSplitAuthenticator(t, []client.Object{stale}, []client.Object{user.DeepCopy()})

			got, err := a.getLiveUser(t.Context(), conflictStored)
			require.NoError(t, err)
			assert.Equal(t, unikornv1.UserStateActive, got.Spec.State, "the live copy decides, not the cache")
		})
	}
}

func TestGetLiveUserChecksTheSubjectOnTheLiveCopy(t *testing.T) {
	t.Parallel()

	for name, user := range splitUsers() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// The cache still names the record for this subject; the live record
			// has since been given to another subject.
			moved := user.DeepCopy()
			moved.Spec.Subject = "someone-else@example.com"

			a := newSplitAuthenticator(t, []client.Object{user.DeepCopy()}, []client.Object{moved})

			_, err := a.getLiveUser(t.Context(), conflictStored)
			require.ErrorIs(t, err, userdb.ErrResourceReference)
		})
	}
}

func TestGetLiveUserFindsTheCanonicalRecordWithAnEmptyCache(t *testing.T) {
	t.Parallel()

	named := splitUsers()["named"]
	a := newSplitAuthenticator(t, nil, []client.Object{named})

	got, err := a.getLiveUser(t.Context(), conflictStored)
	require.NoError(t, err)
	assert.Equal(t, named.Name, got.Name)
}

func TestGetLiveUserRefusesAUserOnlyTheCacheHas(t *testing.T) {
	t.Parallel()

	user := conflictUser()
	a := newSplitAuthenticator(t, []client.Object{user}, nil)

	_, err := a.getLiveUser(t.Context(), conflictStored)
	require.ErrorIs(t, err, userdb.ErrResourceReference)
}

func TestRefreshDecidesOnTheLiveState(t *testing.T) {
	t.Parallel()

	for name, user := range splitUsers() {
		t.Run(name+"/live suspended", func(t *testing.T) {
			t.Parallel()

			live := user.DeepCopy()
			live.Spec.State = unikornv1.UserStateSuspended

			a := newSplitAuthenticator(t, []client.Object{user.DeepCopy(), splitOAuth2Client()}, []client.Object{live, splitOAuth2Client()})

			r, claims := newConflictRefreshRequest(t)

			require.Error(t, a.validateRefreshToken(t.Context(), r, conflictRefresh, claims), "a user suspended live must not refresh")
		})

		t.Run(name+"/cache suspended", func(t *testing.T) {
			t.Parallel()

			stale := user.DeepCopy()
			stale.Spec.State = unikornv1.UserStateSuspended

			a := newSplitAuthenticator(t, []client.Object{stale, splitOAuth2Client()}, []client.Object{user.DeepCopy(), splitOAuth2Client()})

			r, claims := newConflictRefreshRequest(t)

			require.NoError(t, a.validateRefreshToken(t.Context(), r, conflictRefresh, claims), "a stale cache must not refuse a live active user")

			got := &unikornv1.User{}
			require.NoError(t, a.client.Get(t.Context(), client.ObjectKeyFromObject(user), got))
			assert.Empty(t, got.Spec.Sessions[0].RefreshToken, "the live record is the one written")
		})
	}
}
