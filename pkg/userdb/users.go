/*
Copyright 2025 the Unikorn Authors.
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

package userdb

import (
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrResourceReference is raised when a resource cannot be looked up.
	ErrResourceReference = fmt.Errorf("resource reference error")

	// ErrUserInactive identifies an inactive global user and wraps
	// ErrResourceReference for compatibility.
	ErrUserInactive = fmt.Errorf("%w: user is not active", ErrResourceReference)

	// ErrAmbiguousSubject identifies a subject that folds onto multiple users.
	ErrAmbiguousSubject = fmt.Errorf("%w: subject matches more than one user", ErrResourceReference)
)

// SubjectIndexField indexes Users by the canonical form of their subject. It
// serves the legacy lookup in GetUser.
const SubjectIndexField = "spec.subject.canonical"

// SubjectIndexValue is the index function for SubjectIndexField.
func SubjectIndexValue(object client.Object) []string {
	user, ok := object.(*unikornv1.User)
	if !ok {
		return nil
	}

	return []string{unikornv1.NormalizeSubject(user.Spec.Subject)}
}

// IndexSubjects registers SubjectIndexField with indexer. A cache MUST have it
// before it starts if it is given to NewUserDatabase as the index reader.
func IndexSubjects(ctx context.Context, indexer client.FieldIndexer) error {
	return indexer.IndexField(ctx, &unikornv1.User{}, SubjectIndexField, SubjectIndexValue)
}

// UserDatabase resolves identities. It never writes.
type UserDatabase struct {
	// client reads the records returned to the caller.
	client client.Reader
	// index finds legacy users by SubjectIndexField. The API server cannot
	// serve that index, so this is the informer cache, even when client is live.
	index     client.Reader
	namespace string
}

// NewUserDatabase returns a user database that reads records with client and
// finds legacy users with index, which MUST serve SubjectIndexField.  See the
// README's "Readers" section.
func NewUserDatabase(client, index client.Reader, namespace string) *UserDatabase {
	return &UserDatabase{
		client:    client,
		index:     index,
		namespace: namespace,
	}
}

func (d *UserDatabase) GetUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	canonical := unikornv1.NormalizeSubject(subject)
	user := &unikornv1.User{}

	if err := d.client.Get(ctx, client.ObjectKey{Namespace: d.namespace, Name: unikornv1.GlobalUserName(subject)}, user); err == nil {
		if unikornv1.NormalizeSubject(user.Spec.Subject) != canonical {
			return nil, fmt.Errorf("%w: canonical user subject does not match", ErrResourceReference)
		}

		return user, nil
	} else if !kerrors.IsNotFound(err) {
		return nil, err
	}

	result := &unikornv1.UserList{}
	selector := labels.SelectorFromSet(map[string]string{unikornv1.UserSubjectIDLabel: unikornv1.GlobalUserName(subject)})

	if err := d.client.List(ctx, result, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	if len(result.Items) == 1 {
		if unikornv1.NormalizeSubject(result.Items[0].Spec.Subject) != canonical {
			return nil, fmt.Errorf("%w: subject label does not match", ErrResourceReference)
		}

		return result.Items[0].DeepCopy(), nil
	}

	if len(result.Items) > 1 {
		return nil, fmt.Errorf("%w: multiple users match subject label", ErrResourceReference)
	}

	return d.getLegacyUser(ctx, subject)
}

// getLegacyUser finds an unlabelled, random-named User. The index holds every
// record whose canonical subject matches, which is the set MatchSubject would
// pick from in a full list, so the result is the same without listing all users.
func (d *UserDatabase) getLegacyUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	result := &unikornv1.UserList{}

	if err := d.index.List(ctx, result, client.MatchingFields{SubjectIndexField: unikornv1.NormalizeSubject(subject)}); err != nil {
		return nil, err
	}

	matches := 0

	for _, user := range result.Items {
		if user.Spec.Subject == subject {
			matches++
		}
	}

	if matches > 1 {
		return nil, fmt.Errorf("%w: duplicate exact subject", ErrAmbiguousSubject)
	}

	index, ambiguous := unikornv1.MatchSubject(result.Items, subject)
	if ambiguous {
		return nil, fmt.Errorf("%w: subject %q", ErrAmbiguousSubject, subject)
	}

	if index < 0 {
		return nil, fmt.Errorf("%w: user does not exist", ErrResourceReference)
	}

	// The index only names the record; read it through client, so a live
	// database returns live content.
	user := &unikornv1.User{}

	if err := d.client.Get(ctx, client.ObjectKeyFromObject(&result.Items[index]), user); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: user does not exist", ErrResourceReference)
		}

		return nil, err
	}

	return user, nil
}

// GetActiveUser returns a user that match the subject and is active.
func (d *UserDatabase) GetActiveUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	user, err := d.GetUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	if user.Spec.State != unikornv1.UserStateActive {
		return nil, ErrUserInactive
	}

	return user, nil
}

// GetActiveOrganizationUser gets an organization user that references the actual user.
func (d *UserDatabase) GetActiveOrganizationUser(ctx context.Context, organizationID string, user *unikornv1.User) (*unikornv1.OrganizationUser, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.OrganizationLabel: organizationID,
		constants.UserLabel:         user.Name,
	})

	result := &unikornv1.OrganizationUserList{}

	if err := d.client.List(ctx, result, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	if len(result.Items) != 1 {
		return nil, fmt.Errorf("%w: user does not exist in organization or exists multiple times", ErrResourceReference)
	}

	organizationUser := &result.Items[0]

	if organizationUser.Spec.State != unikornv1.UserStateActive {
		return nil, fmt.Errorf("%w: user is not active", ErrResourceReference)
	}

	return organizationUser, nil
}

// GetServiceAccount reads a service account by key: its organization's
// namespace and its ID.
func (d *UserDatabase) GetServiceAccount(ctx context.Context, organizationID, id string) (*unikornv1.ServiceAccount, error) {
	organization := &unikornv1.Organization{}

	if err := d.client.Get(ctx, client.ObjectKey{Namespace: d.namespace, Name: organizationID}, organization); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: organization %s does not exist", ErrResourceReference, organizationID)
		}

		return nil, err
	}

	if organization.Status.Namespace == "" {
		return nil, fmt.Errorf("%w: organization %s has no namespace", ErrResourceReference, organizationID)
	}

	serviceAccount := &unikornv1.ServiceAccount{}

	if err := d.client.Get(ctx, client.ObjectKey{Namespace: organization.Status.Namespace, Name: id}, serviceAccount); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: service account %s does not exist", ErrResourceReference, id)
		}

		return nil, err
	}

	return serviceAccount, nil
}

// GetOrganizationIDsForUser returns the active organization IDs for an active user.
func (d *UserDatabase) GetOrganizationIDsForUser(ctx context.Context, user *unikornv1.User) ([]string, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.UserLabel: user.Name,
	})

	organizationUsers := &unikornv1.OrganizationUserList{}
	if err := d.client.List(ctx, organizationUsers, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(organizationUsers.Items))

	for i := range organizationUsers.Items {
		if organizationUsers.Items[i].Spec.State != unikornv1.UserStateActive {
			continue
		}

		result = append(result, organizationUsers.Items[i].Labels[constants.OrganizationLabel])
	}

	return result, nil
}

// GetOrganizationIDs returns the active organization IDs for a user subject.
func (d *UserDatabase) GetOrganizationIDs(ctx context.Context, subject string) ([]string, error) {
	user, err := d.GetActiveUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	return d.GetOrganizationIDsForUser(ctx, user)
}
