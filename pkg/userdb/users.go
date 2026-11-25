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
	"slices"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

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

// Field indexes served by the informer cache. A List with a label selector
// and no namespace walks every cached object of the kind, so each lookup that
// would select by label asks the matching index instead.  See the README's
// "Readers" section.
const (
	// SubjectIndexField indexes Users by the canonical form of their subject.
	// It serves the unlabelled legacy lookup in GetUser.
	SubjectIndexField = "spec.subject.canonical"

	// SubjectLabelIndexField indexes Users by their subject-ID label. It
	// serves the labelled legacy lookup in GetUser.
	SubjectLabelIndexField = "metadata.labels.user-subject-id"

	// MembershipUserIndexField indexes OrganizationUsers by their user label.
	// It serves every membership lookup.
	MembershipUserIndexField = "metadata.labels.user"
)

// Index is a field index that the cache given to NewUserDatabase MUST have
// registered before it starts.
type Index struct {
	Object client.Object
	Field  string
	Func   client.IndexerFunc
}

// Indexes returns every index the user database queries.
func Indexes() []Index {
	return []Index{
		{&unikornv1.User{}, SubjectIndexField, SubjectIndexValue},
		{&unikornv1.User{}, SubjectLabelIndexField, labelIndexValue[*unikornv1.User](unikornv1.UserSubjectIDLabel)},
		{&unikornv1.OrganizationUser{}, MembershipUserIndexField, labelIndexValue[*unikornv1.OrganizationUser](constants.UserLabel)},
	}
}

// IndexUsers registers every index in Indexes with indexer.
func IndexUsers(ctx context.Context, indexer client.FieldIndexer) error {
	for _, index := range Indexes() {
		if err := indexer.IndexField(ctx, index.Object, index.Field, index.Func); err != nil {
			return err
		}
	}

	return nil
}

// SubjectIndexValue is the index function for SubjectIndexField.
func SubjectIndexValue(object client.Object) []string {
	user, ok := object.(*unikornv1.User)
	if !ok {
		return nil
	}

	return []string{unikornv1.NormalizeSubject(user.Spec.Subject)}
}

// labelIndexValue indexes an object of type T by the value of a label, and
// leaves it out of the index if it has none.
func labelIndexValue[T client.Object](label string) client.IndexerFunc {
	return func(object client.Object) []string {
		typed, ok := object.(T)
		if !ok {
			return nil
		}

		if value := typed.GetLabels()[label]; value != "" {
			return []string{value}
		}

		return nil
	}
}

// UserDatabase resolves identities from the informer cache. It never writes
// and never reads live.
type UserDatabase struct {
	reader    client.Reader
	namespace string
}

// NewUserDatabase returns a user database over reader. The reader MUST be the
// informer cache with every index in Indexes registered before it starts: the
// API server cannot serve a field index on a custom resource, so a live client
// fails every lookup. A caller that decides a write on a record MUST read it
// live itself and check it again.  See the README's "Readers" section.
func NewUserDatabase(reader client.Reader, namespace string) *UserDatabase {
	return &UserDatabase{
		reader:    reader,
		namespace: namespace,
	}
}

func (d *UserDatabase) GetUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	canonical := unikornv1.NormalizeSubject(subject)
	user := &unikornv1.User{}

	if err := d.reader.Get(ctx, client.ObjectKey{Namespace: d.namespace, Name: unikornv1.GlobalUserName(subject)}, user); err == nil {
		if unikornv1.NormalizeSubject(user.Spec.Subject) != canonical {
			return nil, fmt.Errorf("%w: canonical user subject does not match", ErrResourceReference)
		}

		return user, nil
	} else if !kerrors.IsNotFound(err) {
		return nil, err
	}

	result := &unikornv1.UserList{}

	if err := d.reader.List(ctx, result, client.MatchingFields{SubjectLabelIndexField: unikornv1.GlobalUserName(subject)}); err != nil {
		return nil, err
	}

	if len(result.Items) == 1 {
		if unikornv1.NormalizeSubject(result.Items[0].Spec.Subject) != canonical {
			return nil, fmt.Errorf("%w: subject label does not match", ErrResourceReference)
		}

		return &result.Items[0], nil
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

	if err := d.reader.List(ctx, result, client.MatchingFields{SubjectIndexField: unikornv1.NormalizeSubject(subject)}); err != nil {
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

	return &result.Items[index], nil
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

// ListOrganizationUsers returns the user's membership records, in every
// organization and in any state. The index finds them by user label, so the
// cost follows the user's memberships, not the number of members in the
// estate.
func (d *UserDatabase) ListOrganizationUsers(ctx context.Context, user *unikornv1.User) ([]unikornv1.OrganizationUser, error) {
	found := &unikornv1.OrganizationUserList{}

	if err := d.reader.List(ctx, found, client.MatchingFields{MembershipUserIndexField: user.Name}); err != nil {
		return nil, err
	}

	return found.Items, nil
}

// GetActiveOrganizationUser gets an organization user that references the actual user.
func (d *UserDatabase) GetActiveOrganizationUser(ctx context.Context, organizationID string, user *unikornv1.User) (*unikornv1.OrganizationUser, error) {
	memberships, err := d.ListOrganizationUsers(ctx, user)
	if err != nil {
		return nil, err
	}

	memberships = slices.DeleteFunc(memberships, func(o unikornv1.OrganizationUser) bool {
		return o.Labels[constants.OrganizationLabel] != organizationID
	})

	if len(memberships) != 1 {
		return nil, fmt.Errorf("%w: user does not exist in organization or exists multiple times", ErrResourceReference)
	}

	organizationUser := &memberships[0]

	if organizationUser.Spec.State != unikornv1.UserStateActive {
		return nil, fmt.Errorf("%w: user is not active", ErrResourceReference)
	}

	return organizationUser, nil
}

// GetServiceAccount reads a service account by key: its organization's
// namespace and its ID.
func (d *UserDatabase) GetServiceAccount(ctx context.Context, organizationID, id string) (*unikornv1.ServiceAccount, error) {
	organization := &unikornv1.Organization{}

	if err := d.reader.Get(ctx, client.ObjectKey{Namespace: d.namespace, Name: organizationID}, organization); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: organization %s does not exist", ErrResourceReference, organizationID)
		}

		return nil, err
	}

	if organization.Status.Namespace == "" {
		return nil, fmt.Errorf("%w: organization %s has no namespace", ErrResourceReference, organizationID)
	}

	serviceAccount := &unikornv1.ServiceAccount{}

	if err := d.reader.Get(ctx, client.ObjectKey{Namespace: organization.Status.Namespace, Name: id}, serviceAccount); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: service account %s does not exist", ErrResourceReference, id)
		}

		return nil, err
	}

	return serviceAccount, nil
}

// GetOrganizationIDsForUser returns the active organization IDs for an active user.
func (d *UserDatabase) GetOrganizationIDsForUser(ctx context.Context, user *unikornv1.User) ([]string, error) {
	memberships, err := d.ListOrganizationUsers(ctx, user)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(memberships))

	for i := range memberships {
		if memberships[i].Spec.State != unikornv1.UserStateActive {
			continue
		}

		result = append(result, memberships[i].Labels[constants.OrganizationLabel])
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
