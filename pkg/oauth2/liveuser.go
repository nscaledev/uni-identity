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
	"fmt"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getLiveUser finds a user by subject for a read that decides a write. The
// canonical record is read live first, by its deterministic name. Only when it
// does not exist is the cache-backed user database asked to name a legacy
// record (its indexes cannot be served live), and that record is then read
// live. The canonical subject is checked again on the live copy, so a stale
// cache entry cannot stand in for the record. It does not check the state: the
// caller does, on the live copy. See the README's "Readers" section.
func (a *Authenticator) getLiveUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	user, err := a.getCanonicalOrLegacyLiveUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	if unikornv1.NormalizeSubject(user.Spec.Subject) != unikornv1.NormalizeSubject(subject) {
		return nil, fmt.Errorf("%w: canonical user subject does not match", userdb.ErrResourceReference)
	}

	return user, nil
}

// getCanonicalOrLegacyLiveUser reads the canonical record live, then falls back
// to a legacy record found through the cache-backed user database.
func (a *Authenticator) getCanonicalOrLegacyLiveUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	user := &unikornv1.User{}

	err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: unikornv1.GlobalUserName(subject)}, user)
	if err == nil {
		return user, nil
	}

	if !kerrors.IsNotFound(err) {
		return nil, err
	}

	found, err := a.userdb.GetUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	user = &unikornv1.User{}

	if err := a.client.Get(ctx, client.ObjectKeyFromObject(found), user); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: user does not exist", userdb.ErrResourceReference)
		}

		return nil, err
	}

	return user, nil
}
