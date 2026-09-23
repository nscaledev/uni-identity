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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// The session writes replace the whole user record.  When another writer
// changes the record between the read and the write, the API server refuses the
// write with a conflict.  The subject migration is one such writer.  These tests
// make the migration win that race and check that the session write still
// succeeds, without undoing the migration.
const (
	conflictUserID   = "user-conflict"
	conflictClientID = "client-conflict"
	conflictSecret   = "secret-conflict"
	conflictCodeID   = "code-conflict"
	conflictStored   = "Carol@Example.com"
	conflictMigrated = "carol@example.com"
	conflictAccess   = "access-conflict"
	conflictRefresh  = "refresh-conflict"
)

// conflictLastAuthentication is when the user of the stored session last signed
// in interactively.
//
//nolint:gochecknoglobals
var conflictLastAuthentication = time.Date(2026, time.September, 1, 9, 0, 0, 0, time.UTC)

// migrateSubject is the change the subject migration makes to a record.
func migrateSubject(user *unikornv1.User) {
	user.Spec.Subject = unikornv1.NormalizeSubject(user.Spec.Subject)
}

// newConflictAuthenticator returns an authenticator whose first user write
// loses a race.  Just before that write reaches the fake API server, the
// concurrent function changes the stored record.  The fake client then refuses
// the stale write with a conflict, as the API server does.
func newConflictAuthenticator(t *testing.T, concurrent func(*unikornv1.User)) (*Authenticator, client.Client) {
	t.Helper()

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: passportTestNamespace,
			Name:      conflictUserID,
		},
		Spec: unikornv1.UserSpec{
			Subject: conflictStored,
			State:   unikornv1.UserStateActive,
			Sessions: []unikornv1.UserSession{
				{
					ClientID:            conflictClientID,
					AuthorizationCodeID: conflictCodeID,
					AccessToken:         conflictAccess,
					RefreshToken:        conflictRefresh,
					LastAuthentication:  &metav1.Time{Time: conflictLastAuthentication},
				},
			},
		},
	}

	oauth2Client := &unikornv1.OAuth2Client{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: passportTestNamespace,
			Name:      conflictClientID,
		},
		Status: unikornv1.OAuth2ClientStatus{
			Secret: conflictSecret,
		},
	}

	raced := false

	funcs := interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, ok := obj.(*unikornv1.User); !ok || raced {
				return c.Update(ctx, obj, opts...)
			}

			raced = true

			stored := &unikornv1.User{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), stored); err != nil {
				return err
			}

			concurrent(stored)

			if err := c.Update(ctx, stored); err != nil {
				return err
			}

			err := c.Update(ctx, obj, opts...)

			// If the fake client took the stale write, the race did not happen
			// and the test proves nothing.
			assert.True(t, kerrors.IsConflict(err), "the stale write must be refused with a conflict, got %v", err)

			return err
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(getPassportInternalScheme(t)).
		WithObjects(user, oauth2Client).
		WithInterceptorFuncs(funcs).
		Build()

	authenticator := &Authenticator{
		client:     cli,
		namespace:  passportTestNamespace,
		userdb:     userdb.NewUserDatabase(cli, passportTestNamespace),
		tokenCache: cache.NewLRUExpireCache(16),
	}

	return authenticator, cli
}

func getConflictUser(t *testing.T, cli client.Client) *unikornv1.User {
	t.Helper()

	user := &unikornv1.User{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: passportTestNamespace, Name: conflictUserID}, user))

	return user
}

func newConflictRefreshRequest(t *testing.T) (*http.Request, *RefreshTokenClaims) {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/v2/token", nil)
	r.SetBasicAuth(conflictClientID, conflictSecret)

	claims := &RefreshTokenClaims{
		Claims: jwt.Claims{
			Subject: conflictStored,
		},
		Federated: &FederatedClaims{
			ClientID: conflictClientID,
			UserID:   conflictUserID,
		},
	}

	return r, claims
}

func TestIssueSurvivesAConcurrentWriteToTheUser(t *testing.T) {
	t.Parallel()

	authenticator, cli := newConflictAuthenticator(t, migrateSubject)

	info := &IssueInfo{
		Federated: &FederatedClaims{
			ClientID: conflictClientID,
			UserID:   conflictUserID,
		},
	}

	tokens := &Tokens{
		AccessToken:  "access-reissued",
		RefreshToken: ptr.To("refresh-reissued"),
	}

	authTime, err := authenticator.updateSession(t.Context(), info, tokens, ptr.To("code-reissued"))
	require.NoError(t, err, "a login must not fail because the migration wrote the record first")

	// The reissue is not interactive, so auth_time must still report the last
	// interactive sign-in.  A max_age check depends on it.
	assert.True(t, conflictLastAuthentication.Equal(authTime), "auth_time must survive the retry, got %v", authTime)

	user := getConflictUser(t, cli)
	assert.Equal(t, conflictMigrated, user.Spec.Subject, "the session write must not undo the migration")

	require.Len(t, user.Spec.Sessions, 1)
	assert.Equal(t, "access-reissued", user.Spec.Sessions[0].AccessToken)
	assert.Equal(t, "refresh-reissued", user.Spec.Sessions[0].RefreshToken)
	assert.Equal(t, "code-reissued", user.Spec.Sessions[0].AuthorizationCodeID)
}

func TestCodeReuseRevokesTheSessionDespiteAConcurrentWrite(t *testing.T) {
	t.Parallel()

	authenticator, cli := newConflictAuthenticator(t, migrateSubject)

	// RFC 6749 4.1.2: a reused code must revoke the tokens issued from it.
	// The caller ignores this error.  If the revocation loses the race, the
	// session stays live and nothing reports it.
	require.NoError(t, authenticator.revokeSession(t.Context(), conflictClientID, conflictCodeID, conflictStored))

	user := getConflictUser(t, cli)
	assert.Equal(t, conflictMigrated, user.Spec.Subject, "the revocation must not undo the migration")
	assert.Empty(t, user.Spec.Sessions, "a reused code must revoke the session")
}

func TestRefreshSurvivesAConcurrentWriteToTheUser(t *testing.T) {
	t.Parallel()

	authenticator, cli := newConflictAuthenticator(t, migrateSubject)

	r, claims := newConflictRefreshRequest(t)

	require.NoError(t, authenticator.validateRefreshToken(t.Context(), r, conflictRefresh, claims),
		"a refresh must not fail because the migration wrote the record first")

	user := getConflictUser(t, cli)
	assert.Equal(t, conflictMigrated, user.Spec.Subject, "the refresh must not undo the migration")

	require.Len(t, user.Spec.Sessions, 1)
	assert.Empty(t, user.Spec.Sessions[0].RefreshToken, "a used refresh token must be cleared")
}

func TestRefreshTokenReuseIsRefusedAfterAConflict(t *testing.T) {
	t.Parallel()

	// Two requests present the same refresh token.  The other request reads,
	// checks and clears the token first, so this request's write conflicts.
	// The retry must check the token again on the latest record.  If the retry
	// only writes again, one refresh token can issue two sessions.
	redeemElsewhere := func(user *unikornv1.User) {
		user.Spec.Sessions[0].RefreshToken = ""
	}

	authenticator, cli := newConflictAuthenticator(t, redeemElsewhere)

	r, claims := newConflictRefreshRequest(t)

	err := authenticator.validateRefreshToken(t.Context(), r, conflictRefresh, claims)
	require.Error(t, err, "a refresh token must be single use")

	var oauthErr *oauth2errors.Error

	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, openapi.InvalidGrant, oauthErr.Code())
	assert.Equal(t, "refresh token reuse", oauthErr.Error())

	user := getConflictUser(t, cli)
	require.Len(t, user.Spec.Sessions, 1)
	assert.Empty(t, user.Spec.Sessions[0].RefreshToken)
}
