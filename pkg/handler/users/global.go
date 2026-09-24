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

package users

import (
	"context"
	goerrors "errors"
	"fmt"
	"net/http"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrMembership reports that an organization still names the account.
	ErrMembership = goerrors.New("account holds organization memberships")

	// ErrGlobalBinding reports that the account's subject holds a global
	// role binding, authority that does not depend on membership.
	ErrGlobalBinding = goerrors.New("account subject holds a global role binding")

	// ErrAccountChanging reports that another change reached the account on
	// every delete attempt.
	ErrAccountChanging = goerrors.New("the account changed on every delete attempt")
)

// GlobalBindingReader reports whether a subject holds authority that survives
// the loss of every membership. pkg/rbac.RBAC implements it. It is declared
// here, and not imported, so the handler clients keep no dependency on the
// authorization package.
type GlobalBindingReader interface {
	HasGlobalSubjectBinding(subject string) bool
}

// SessionInvalidator drops a token from the verification cache.
// pkg/oauth2.Authenticator implements it. It is declared here, and not
// imported, so the handler clients keep no dependency on pkg/oauth2.
type SessionInvalidator interface {
	InvalidateToken(ctx context.Context, token string)
}

// GlobalClient manages the global User record, the account a person holds
// across every organization, as distinct from the OrganizationUser
// memberships that Client manages.
type GlobalClient struct {
	// client must be an uncached reader. A stale cache that reports no
	// membership deletes an account that still has one, and nothing
	// restores it. This is the one unrecoverable mistake available here.
	client client.Client
	// namespace is the namespace the identity service is running in, which
	// is where the account records live.
	namespace string
	// bindings answers whether a subject holds a global role binding.
	bindings GlobalBindingReader
	// sessions evicts a session's access token from the verification
	// cache when its account is deleted.
	sessions SessionInvalidator
}

// NewGlobal creates a client for the unscoped account endpoints. Pass the
// uncached Kubernetes client.
func NewGlobal(client client.Client, namespace string, bindings GlobalBindingReader, sessions SessionInvalidator) *GlobalClient {
	return &GlobalClient{
		client:    client,
		namespace: namespace,
		bindings:  bindings,
		sessions:  sessions,
	}
}

// conflict returns a 409 whose description says what actually conflicted.
// core's errors.HTTPConflict hardcodes "the requested resource already
// exists", which is wrong for a refusal that is not about a duplicate.
// errors.FromOpenAPIError is the exported path that sets a description, so
// this goes through it. It lives here, unexported, and not in the handler
// package's error helpers, because pkg/handler imports pkg/handler/users
// and the reverse import would cycle. The header argument FromOpenAPIError
// takes is unused by its implementation.
func conflict(format string, args ...any) *errors.Error {
	return errors.FromOpenAPIError(http.StatusConflict, nil, &coreopenapi.Error{
		Error:            coreopenapi.Conflict,
		ErrorDescription: fmt.Sprintf(format, args...),
	})
}

// deleteAttempts bounds how often Delete retries a precondition conflict.
const deleteAttempts = 3

// accountNotFound returns the 404 for an account that does not exist. Its
// description is the only one that means the account is gone. core answers a
// request for a route that this server does not have with a 404 too, but with
// core's own text, and a caller must not read that as a completed delete.
func accountNotFound(err error) error {
	return errors.FromOpenAPIError(http.StatusNotFound, nil, &coreopenapi.Error{
		Error:            coreopenapi.NotFound,
		ErrorDescription: "the account does not exist",
	}).WithError(err)
}

// Delete removes an account. It does not cascade: the caller removes the
// memberships first, which is what org-service's signup rollback already
// does. The session records go at once. Identity refuses the account's
// tokens as soon as its informer cache observes the delete, because
// GetUserinfo reads the User through that cache on every request. The
// comment on the deferred eviction describes the one exception. A
// downstream service can still accept a token for up to about 50 seconds
// after its last token exchange, because it caches the passport. It can
// then serve an ACL it already cached for that token, one minute by
// default.
//
// The delete carries the UID and the resource version from its read as
// preconditions. If another change reaches the record first, for example a
// login that adds a session, the delete fails, and Delete reads the record
// again and tries again, up to deleteAttempts times. So a 409 means only that
// memberships remain. If every attempt conflicts, Delete returns a server
// error, which the caller retries with backoff.
//
// It deletes an account and does not erase a person. The subject remains in
// the creator and modifier annotations of resources across compute,
// kubernetes and region.
func (c *GlobalClient) Delete(ctx context.Context, globalUserID ids.GlobalUserID) error {
	// evicted holds every access token that an attempt evicted. They are
	// evicted again when Delete returns, whatever the result. A verification
	// can add a token back to the cache at any time after the first
	// eviction. Verify does not write to the record, so the preconditions
	// cannot see it. Verify reads the session through the informer cache,
	// not through this uncached client, so until that cache observes the
	// delete, a verification can add the token again. That entry gives no
	// access after the informer cache observes the delete, because
	// GetUserinfo then refuses the token. One case differs. GetUserinfo finds
	// the account by subject, so if a new account with the same subject
	// appears while the entry lives, GetUserinfo accepts the token for that
	// new account. The eviction also runs when the delete call fails, because
	// the API server can delete the record and the call can still fail, and a
	// retry then gets 404 before it evicts anything.
	var evicted []string

	defer func() {
		for _, token := range evicted {
			c.sessions.InvalidateToken(ctx, token)
		}
	}()

	for attempt := 1; ; attempt++ {
		tokens, err := c.deleteOnce(ctx, globalUserID)
		evicted = append(evicted, tokens...)

		if !kerrors.IsConflict(err) {
			return err
		}

		if attempt == deleteAttempts {
			return fmt.Errorf("%w: %w", ErrAccountChanging, err)
		}
	}
}

// deleteOnce makes one attempt to delete the account. It returns the access
// tokens that it evicted. A precondition conflict comes back as the API
// server's conflict error, for Delete to retry. Every other error is
// classified for the caller.
func (c *GlobalClient) deleteOnce(ctx context.Context, globalUserID ids.GlobalUserID) ([]string, error) {
	user := &unikornv1.User{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: globalUserID.String()}, user); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, accountNotFound(err)
		}

		return nil, fmt.Errorf("%w: failed to get user", err)
	}

	if err := c.refuse(ctx, globalUserID, user); err != nil {
		return nil, err
	}

	// Evict each session's access token from the verification cache before
	// the record goes. This is defense in depth, not the control that
	// refuses the token. Verify returns early on a cache hit. But its only
	// caller, GetUserinfo, then reads the User through the informer cache,
	// and refuses the token once the User is gone. The eviction keeps the
	// tokens of a deleted account out of the cache, in case a later path
	// trusts Verify alone.
	//
	// This is a cache eviction and not a revocation. The session records
	// are what authorize a token, and they go with the record below. An
	// eviction that lands on an account this function then fails to delete
	// costs one re-verification and nothing else, which is why it is safe
	// to do this first.
	tokens := make([]string, 0, len(user.Spec.Sessions))

	for _, session := range user.Spec.Sessions {
		c.sessions.InvalidateToken(ctx, session.AccessToken)
		tokens = append(tokens, session.AccessToken)
	}

	// A login between the read above and this delete adds a session whose
	// access token is not in that set. The UID and resource version read
	// above make the delete fail instead of deleting the changed record.
	// Delete then tries again, and the next attempt reads the new session
	// too.
	if err := c.client.Delete(ctx, user, client.Preconditions{
		UID:             &user.UID,
		ResourceVersion: &user.ResourceVersion,
	}); err != nil {
		return tokens, deleteUserError(err)
	}

	return tokens, nil
}

// refuse returns the refusal for an account that must not be deleted, or nil.
func (c *GlobalClient) refuse(ctx context.Context, globalUserID ids.GlobalUserID, user *unikornv1.User) error {
	// Cheapest check first, and the graver of the two. A global role
	// binding grants authority with no membership, so a bound subject
	// passes the membership check below whatever its state.
	if c.bindings.HasGlobalSubjectBinding(user.Spec.Subject) {
		// The description must not echo the subject: the caller supplied a
		// UUID, and echoing the subject would disclose the account's email
		// address to someone who only knew its identifier.
		//
		// This refusal is 422, not 409. The platform's configuration blocks
		// the delete, not the resource, so a retry never changes the
		// outcome. The membership refusal below stays 409, because a retry
		// after the caller removes the memberships does change the outcome.
		return errors.HTTPUnprocessableContent("the account subject holds a configured global role binding").WithError(fmt.Errorf("%w: %q", ErrGlobalBinding, user.Spec.Subject))
	}

	memberships := &unikornv1.OrganizationUserList{}

	// No namespace: memberships live in the organization namespaces, one
	// per organization, and the account lives in the identity namespace.
	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{constants.UserLabel: globalUserID.String()}),
	}

	if err := c.client.List(ctx, memberships, options); err != nil {
		return fmt.Errorf("%w: failed to list organization users", err)
	}

	if count := len(memberships.Items); count > 0 {
		// The count is the actionable fact: the caller's job is to remove
		// the memberships first.
		noun := "memberships"
		if count == 1 {
			noun = "membership"
		}

		return conflict("the account holds %d organization %s", count, noun).WithError(fmt.Errorf("%w: %d remaining", ErrMembership, count))
	}

	return nil
}

// deleteUserError classifies the error from the record delete in deleteOnce.
// A precondition conflict stays the API server's conflict error, so that
// Delete can retry it.
func deleteUserError(err error) error {
	if kerrors.IsNotFound(err) {
		return accountNotFound(err)
	}

	if kerrors.IsConflict(err) {
		return err
	}

	return fmt.Errorf("%w: failed to delete user", err)
}
