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

package users_test

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/ids"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	accountAliceID  = "11111111-1111-4111-8111-111111111111"
	accountAbsentID = "22222222-2222-4222-8222-222222222222"
)

var (
	errSimulatedListFailure = goerrors.New("simulated list failure")
	errSimulatedConflict    = goerrors.New("simulated precondition conflict")
)

// stubBindings answers the global role binding question from a fixed
// list, so these tests do not have to build an RBAC.
type stubBindings struct {
	bound []string
}

func (s stubBindings) HasGlobalSubjectBinding(subject string) bool {
	return slices.Contains(s.bound, subject)
}

// stubSessionInvalidator records every token it is given, so a test can
// assert which tokens Delete evicted, and when, with no dependency on
// pkg/oauth2.
type stubSessionInvalidator struct {
	invalidated []string
}

func (s *stubSessionInvalidator) InvalidateToken(_ context.Context, token string) {
	s.invalidated = append(s.invalidated, token)
}

// newGlobalClient builds the client under test over the same fake client the
// rest of this package's tests use. interceptors lets a test reach a branch
// the fake client alone cannot, such as a List call that fails. sessions is
// a pointer so the caller keeps a live view of what it recorded.
func newGlobalClient(t *testing.T, bindings stubBindings, sessions *stubSessionInvalidator, interceptors interceptor.Funcs, objects ...client.Object) (*users.GlobalClient, client.Client) {
	t.Helper()

	fixture := newUserTestFixtureWithObjects(t, objects, interceptors)

	return users.NewGlobal(fixture.client, testNamespace, bindings, sessions), fixture.client
}

// writeErrorDescription renders err through Write, the same wire path a
// real response takes, and returns the description field the caller
// receives. The description is not reachable through an exported getter,
// so this is how a test pins it against a regression to core's canned
// text.
func writeErrorDescription(t *testing.T, err error) string {
	t.Helper()

	var httpErr *errors.Error

	require.ErrorAs(t, err, &httpErr, "the refusal must carry an HTTP error the caller can read")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "https://test.com/api/v1/users/"+accountAliceID, nil)

	httpErr.Write(w, r)

	body := &coreopenapi.Error{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), body))

	return body.ErrorDescription
}

// TestGlobalClient_DeleteRefusesWhileAMembershipRemains pins the refusal that
// makes this call safe to expose. An account with a live membership is an
// account someone is using. Deleting it strips a person's access with no
// caller asking for that, and nothing restores it.
func TestGlobalClient_DeleteRefusesWhileAMembershipRemains(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	invalidator := &stubSessionInvalidator{}

	globalClient, c := newGlobalClient(t, stubBindings{}, invalidator, interceptor.Funcs{},
		newGlobalUser(accountAliceID, userAliceSubject),
		newOrganizationUser(orgUserAliceID, accountAliceID))

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	require.ErrorIs(t, err, users.ErrMembership,
		"the caller removes memberships first, so the refusal must name which rule fired")
	assert.True(t, errors.IsConflict(err), "a live membership is a conflict, not a not-found or a server error")
	assert.Equal(t, "the account holds 1 organization membership", writeErrorDescription(t, err),
		"the count is the actionable fact, so the description must carry it, not core's canned text, and one membership must read as singular")

	// The account must still be there. A refusal that deleted anything
	// would be worse than no refusal at all.
	var survivor unikornv1.User

	require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &survivor))

	assert.Empty(t, invalidator.invalidated,
		"the account survives this refusal, so its cached tokens must stay valid")
}

// TestGlobalClient_DeleteRefusesAGloballyBoundSubject pins the second
// refusal. A global role binding grants authority with no membership at all,
// so a bound subject passes the membership check trivially. Deleting the
// record locks the subject out of a system that still grants it access
// through that binding.
func TestGlobalClient_DeleteRefusesAGloballyBoundSubject(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	invalidator := &stubSessionInvalidator{}

	globalClient, c := newGlobalClient(t, stubBindings{bound: []string{userAliceSubject}}, invalidator, interceptor.Funcs{},
		newGlobalUser(accountAliceID, userAliceSubject))

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	require.ErrorIs(t, err, users.ErrGlobalBinding)
	assert.True(t, errors.IsUnprocessableContent(err), "the platform's configuration blocks this, not the resource, so a retry must not see a conflict")
	assert.False(t, errors.IsConflict(err), "a regression back to 409 must fail this test, not pass it silently")

	description := writeErrorDescription(t, err)
	assert.Equal(t, "the account subject holds a configured global role binding", description)
	assert.NotContains(t, description, userAliceSubject,
		"the caller supplied only a UUID, so the description must not disclose the account's email address")

	var survivor unikornv1.User

	require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &survivor))

	assert.Empty(t, invalidator.invalidated,
		"the account survives this refusal, so its cached tokens must stay valid")
}

// TestGlobalClient_DeleteRemovesAnUnreferencedAccount pins the success path,
// which is the signup rollback: org-service has just removed the membership
// and now removes the account it created.
func TestGlobalClient_DeleteRemovesAnUnreferencedAccount(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	invalidator := &stubSessionInvalidator{}

	globalClient, c := newGlobalClient(t, stubBindings{}, invalidator, interceptor.Funcs{},
		newGlobalUser(accountAliceID, userAliceSubject))

	// Precondition. Without it the assertion below passes vacuously.
	var before unikornv1.User

	require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &before))

	require.NoError(t, globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID)))

	var after unikornv1.User
	err := c.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &after)
	assert.True(t, kerrors.IsNotFound(err), "the record and the sessions it carries must be gone")

	// This account has no sessions, so there is nothing to invalidate.
	assert.Empty(t, invalidator.invalidated)
}

// TestGlobalClient_DeleteIsIdempotent pins the contract a retrying rollback
// depends on. org-service retries its saga, so a second attempt must not
// report a failure for work the first attempt completed.
func TestGlobalClient_DeleteIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	globalClient, _ := newGlobalClient(t, stubBindings{}, &stubSessionInvalidator{}, interceptor.Funcs{})

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAbsentID))

	require.Error(t, err)
	assert.True(t, errors.IsHTTPNotFound(err),
		"a retry must see not found and treat it as success, not as a server error")
	assert.Equal(t, "the account does not exist", writeErrorDescription(t, err),
		"only this description means the account is gone; a 404 for a route the server does not have says something else")
}

// TestGlobalClient_DeleteReportsAnAccountThatGoesDuringTheDelete pins the not
// found branch of the record delete. Another delete can remove the record
// between this call's read and its delete. The answer is the same 404 as for
// an account that was already gone, because the result for the caller is the
// same.
func TestGlobalClient_DeleteReportsAnAccountThatGoesDuringTheDelete(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	globalClient, _ := newGlobalClient(t, stubBindings{}, &stubSessionInvalidator{}, interceptor.Funcs{
		Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
			return kerrors.NewNotFound(unikornv1.SchemeGroupVersion.WithResource("users").GroupResource(), accountAliceID)
		},
	}, newGlobalUser(accountAliceID, userAliceSubject))

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	assert.True(t, errors.IsHTTPNotFound(err))
	assert.Equal(t, "the account does not exist", writeErrorDescription(t, err))
}

// TestGlobalClient_DeleteEvictsAgainWhenTheDeleteCallFails pins the second
// eviction on a failed delete call. The API server can delete the record and
// the call can still fail, for example on a timeout. A retry then gets 404
// before it evicts anything. So the second eviction must run whatever the
// delete call returns.
func TestGlobalClient_DeleteEvictsAgainWhenTheDeleteCallFails(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	account := newGlobalUser(accountAliceID, userAliceSubject)
	account.Spec.Sessions = []unikornv1.UserSession{{AccessToken: "access-token"}}

	invalidator := &stubSessionInvalidator{}

	globalClient, _ := newGlobalClient(t, stubBindings{}, invalidator, interceptor.Funcs{
		Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := inner.Delete(ctx, obj, opts...); err != nil {
				return err
			}

			return context.DeadlineExceeded
		},
	}, account)

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	assert.Equal(t, []string{"access-token", "access-token"}, invalidator.invalidated,
		"the token must be evicted before the delete and again after it, even when the delete call fails")
}

// TestGlobalClient_DeleteChecksTheBindingBeforeTheMembership pins the order of
// the two refusals. A subject with a global role binding keeps its authority
// with no membership, so the 422 must win over the 409. With the order
// reversed, a caller would remove the memberships and retry, and then learn
// that the delete can never succeed.
func TestGlobalClient_DeleteChecksTheBindingBeforeTheMembership(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	globalClient, _ := newGlobalClient(t, stubBindings{bound: []string{userAliceSubject}}, &stubSessionInvalidator{}, interceptor.Funcs{},
		newGlobalUser(accountAliceID, userAliceSubject),
		newOrganizationUser(orgUserAliceID, accountAliceID),
	)

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	assert.True(t, errors.IsUnprocessableContent(err), "the binding refusal must come before the membership refusal")
}

// TestGlobalClient_DeleteFindsAMembershipInAnyNamespace pins the search
// scope. Memberships live in organization namespaces, one per organization,
// and the account lives in the identity namespace. A search scoped to the
// account's own namespace finds nothing and deletes a live account.
func TestGlobalClient_DeleteFindsAMembershipInAnyNamespace(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	// newOrganizationUser puts the membership in testOrgNS, which is not
	// testNamespace, so this fixture already exercises the cross-namespace
	// case. Assert the namespaces differ, or a later change to the fixture
	// could make this test pass for the wrong reason.
	membership := newOrganizationUser(orgUserAliceID, accountAliceID)
	require.NotEqual(t, testNamespace, membership.Namespace)

	globalClient, _ := newGlobalClient(t, stubBindings{}, &stubSessionInvalidator{}, interceptor.Funcs{},
		newGlobalUser(accountAliceID, userAliceSubject), membership)

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	require.ErrorIs(t, err, users.ErrMembership)
}

// TestGlobalClient_DeleteFailsClosedWhenMembershipListFails pins the one
// fail-closed branch on this path with no other test. If the List call in
// Delete ever returned nil on an error instead of propagating it, the
// account would be deleted with the membership state unknown, and every
// other test in this file would still pass.
func TestGlobalClient_DeleteFailsClosedWhenMembershipListFails(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	globalClient, c := newGlobalClient(t, stubBindings{}, &stubSessionInvalidator{}, interceptor.Funcs{
		List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*unikornv1.OrganizationUserList); ok {
				return errSimulatedListFailure
			}

			return inner.List(ctx, list, opts...)
		},
	}, newGlobalUser(accountAliceID, userAliceSubject))

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	require.ErrorIs(t, err, errSimulatedListFailure,
		"the caller must see the underlying failure, not a silent success")

	// The account must still be there. A failed membership check must not
	// be read as "no membership found".
	var survivor unikornv1.User

	require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &survivor))
}

// TestGlobalClient_DeleteInvalidatesEverySessionsAccessToken pins the
// eviction of every session's access token from the verification cache. The
// eviction is defense in depth: GetUserinfo refuses the token once the
// informer cache observes the delete. Only access tokens go to the
// invalidator. A refresh token needs no eviction, because the refresh path
// writes the session back to the account, and that write fails once the
// record is gone. Delete evicts every access token twice on a clean run,
// once before the record delete and once after, so each token must appear
// twice.
func TestGlobalClient_DeleteInvalidatesEverySessionsAccessToken(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	account := newGlobalUser(accountAliceID, userAliceSubject)
	account.Spec.Sessions = []unikornv1.UserSession{
		{AccessToken: "access-token-1", RefreshToken: "refresh-token-1"},
		{AccessToken: "access-token-2", RefreshToken: "refresh-token-2"},
	}

	invalidator := &stubSessionInvalidator{}

	globalClient, _ := newGlobalClient(t, stubBindings{}, invalidator, interceptor.Funcs{}, account)

	require.NoError(t, globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID)))

	assert.ElementsMatch(t, []string{"access-token-1", "access-token-2", "access-token-1", "access-token-2"}, invalidator.invalidated,
		"every session's access token must be evicted from the verification cache, twice, once before the delete and once after")
	assert.NotContains(t, invalidator.invalidated, "refresh-token-1")
	assert.NotContains(t, invalidator.invalidated, "refresh-token-2")
}

// TestGlobalClient_DeleteInvalidatesSessionsBeforeDeletingTheRecord pins the
// order the doc comment on Delete depends on. A token evicted after the
// record is gone leaves the window open for as long as the delete call
// takes to reach the client, so eviction must land first.
func TestGlobalClient_DeleteInvalidatesSessionsBeforeDeletingTheRecord(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	account := newGlobalUser(accountAliceID, userAliceSubject)
	account.Spec.Sessions = []unikornv1.UserSession{
		{AccessToken: "access-token-1", RefreshToken: "refresh-token-1"},
	}

	invalidator := &stubSessionInvalidator{}

	var invalidatedBeforeDelete []string

	globalClient, _ := newGlobalClient(t, stubBindings{}, invalidator, interceptor.Funcs{
		Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			// Snapshot what the invalidator holds at the moment the
			// record delete reaches the client. If the invalidation
			// loop ran after this call instead of before it, the
			// snapshot would be empty and the assertion below would
			// fail.
			invalidatedBeforeDelete = slices.Clone(invalidator.invalidated)

			return inner.Delete(ctx, obj, opts...)
		},
	}, account)

	require.NoError(t, globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID)))

	assert.Equal(t, []string{"access-token-1"}, invalidatedBeforeDelete,
		"the token must be evicted from the cache before the record it authorizes against is gone")
}

// TestGlobalClient_DeleteRetriesAResourceVersionRace pins the retry of a
// precondition conflict inside Delete. A login that lands between the read and
// the delete adds a session whose token the first eviction loop never saw.
// The UID and resource version preconditions fail that delete instead of
// deleting a record that changed. Delete then reads the record again, evicts
// the new token too, and deletes. A 409 therefore means only that memberships
// remain, and a caller never has to tell two 409 causes apart.
func TestGlobalClient_DeleteRetriesAResourceVersionRace(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	account := newGlobalUser(accountAliceID, userAliceSubject)
	account.Spec.Sessions = []unikornv1.UserSession{
		{AccessToken: "existing-access-token", RefreshToken: "existing-refresh-token"},
	}

	invalidator := &stubSessionInvalidator{}

	var raced bool

	globalClient, c := newGlobalClient(t, stubBindings{}, invalidator, interceptor.Funcs{
		Delete: func(ctx context.Context, inner client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if raced {
				return inner.Delete(ctx, obj, opts...)
			}

			raced = true

			// The login: it lands between Delete's Get and this call, and
			// moves the resource version that the preconditions name.
			var racer unikornv1.User

			if err := inner.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &racer); err != nil {
				return err
			}

			racer.Spec.Sessions = append(racer.Spec.Sessions, unikornv1.UserSession{ClientID: "racing-client", AccessToken: "racing-access-token"})

			if err := inner.Update(ctx, &racer); err != nil {
				return err
			}

			return inner.Delete(ctx, obj, opts...)
		},
	}, account)

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.NoError(t, err, "Delete must retry the precondition conflict itself, not hand it to the caller as a 409")

	var gone unikornv1.User

	err = c.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &gone)
	assert.True(t, kerrors.IsNotFound(err), "the retry must remove the record")

	assert.Contains(t, invalidator.invalidated, "existing-access-token",
		"the session present at the first read must be evicted")
	assert.Contains(t, invalidator.invalidated, "racing-access-token",
		"the retry must evict the token of the session the race added")
}

// TestGlobalClient_DeleteGivesUpAfterRepeatedConflicts pins the bound on the
// retry. A record that changes on every attempt must not keep the call busy
// for ever, and the answer must not be a 409, which means memberships remain.
// It is a server error, which a caller retries with backoff.
func TestGlobalClient_DeleteGivesUpAfterRepeatedConflicts(t *testing.T) {
	t.Parallel()

	ctx := newContext(t)

	var attempts int

	globalClient, c := newGlobalClient(t, stubBindings{}, &stubSessionInvalidator{}, interceptor.Funcs{
		Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
			attempts++

			return kerrors.NewConflict(unikornv1.SchemeGroupVersion.WithResource("users").GroupResource(), accountAliceID, errSimulatedConflict)
		},
	}, newGlobalUser(accountAliceID, userAliceSubject))

	err := globalClient.Delete(ctx, ids.MustParseGlobalUserID(accountAliceID))

	require.Error(t, err)
	assert.False(t, errors.IsConflict(err), "a 409 means memberships remain, so an exhausted retry must not answer 409")

	var httpErr *errors.Error

	assert.NotErrorAs(t, err, &httpErr, "an exhausted retry is a server error, which the handler renders as 500")

	assert.Equal(t, 3, attempts, "Delete must try a bounded number of times")

	var survivor unikornv1.User

	require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: accountAliceID}, &survivor))
}
