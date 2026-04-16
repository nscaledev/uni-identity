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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var errSimulated = errors.New("simulated error")

const (
	testNamespaceIdentity          = "unikorn-identity"
	testNamespaceOrganizationOwned = "organization-382d90b6"

	testIssuer = "https://identity.example.com"

	testUserNameAlice             = "user-alice"
	testOrganizationUserNameAlice = "organization-user-alice"
	testSubjectAlice              = "alice@example.com"

	testUserNameBob             = "user-bob"
	testOrganizationUserNameBob = "organization-user-bob"
	testSubjectBob              = "bob@example.com"
)

func newTestManager(t *testing.T, objects ...client.Object) *Manager {
	t.Helper()

	kubeScheme := runtime.NewScheme()
	require.NoError(t, unikorncorev1.AddToScheme(kubeScheme))
	require.NoError(t, identityv1.AddToScheme(kubeScheme))

	kubeClient := fake.NewClientBuilder().
		WithScheme(kubeScheme).
		WithObjects(objects...).
		Build()

	manager, err := NewManager(1, testIssuer, kubeClient)
	require.NoError(t, err)

	return manager
}

func newTestUser(name, subject string) identityv1.User {
	return identityv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespaceIdentity,
		},
		Spec: identityv1.UserSpec{
			Subject: subject,
			State:   identityv1.UserStateActive,
		},
	}
}

func newTestOrganizationUser(organizationUserName, userName string) identityv1.OrganizationUser {
	return identityv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      organizationUserName,
			Namespace: testNamespaceOrganizationOwned,
			Labels: map[string]string{
				coreconstants.UserLabel: userName,
			},
		},
		Spec: identityv1.OrganizationUserSpec{
			State: identityv1.UserStateActive,
		},
	}
}

func newTestGroup(name string, userIDs []string, subjects []identityv1.GroupSubject) identityv1.Group {
	return identityv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       testNamespaceOrganizationOwned,
			ResourceVersion: "1",
		},
		Spec: identityv1.GroupSpec{
			UserIDs:  userIDs,
			Subjects: subjects,
		},
	}
}

func newTestGroupSubject(id, issuer, email string) identityv1.GroupSubject {
	return identityv1.GroupSubject{
		ID:     id,
		Issuer: issuer,
		Email:  email,
	}
}

func writeStateFile(t *testing.T, path string, dryRun bool, results []Result) {
	t.Helper()

	state := State{DryRun: dryRun, Results: results}

	data, err := json.Marshal(state)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func TestMigrationError(t *testing.T) {
	t.Parallel()

	t.Run("formats the error message with failed and total counts", func(t *testing.T) {
		t.Parallel()

		err := NewMigrationError(3, 10)
		assert.EqualError(t, err, "3/10 groups failed during migration, please check the state file for details")
	})
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	t.Run("returns an error when concurrency is zero", func(t *testing.T) {
		t.Parallel()

		_, err := NewManager(0, testIssuer, nil)
		require.ErrorIs(t, err, ErrInvalidConcurrency)
	})

	t.Run("returns an error when concurrency is negative", func(t *testing.T) {
		t.Parallel()

		_, err := NewManager(-1, testIssuer, nil)
		require.ErrorIs(t, err, ErrInvalidConcurrency)
	})

	t.Run("returns an error when identity issuer is empty", func(t *testing.T) {
		t.Parallel()

		_, err := NewManager(1, "", nil)
		require.ErrorIs(t, err, ErrEmptyIdentityIssuer)
	})

	t.Run("returns a manager when inputs are valid", func(t *testing.T) {
		t.Parallel()

		manager, err := NewManager(1, testIssuer, nil)
		require.NoError(t, err)
		require.NotNil(t, manager)
	})
}

//nolint:maintidx
func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("returns an error when the previous state file contains invalid json", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
			data    = []byte("invalid json")
		)

		err := os.WriteFile(path, data, 0600)
		require.NoError(t, err)

		err = manager.Run(t.Context(), path, false)
		require.Error(t, err)
	})

	t.Run("returns an error when a dry run state file is used for an actual migration", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		writeStateFile(t, path, true, nil)

		err := manager.Run(t.Context(), path, false)
		require.ErrorIs(t, err, ErrDryRunStateFile)
	})

	//nolint:dupl
	t.Run("returns an error when listing groups fails", func(t *testing.T) {
		t.Parallel()

		kubeScheme := runtime.NewScheme()
		require.NoError(t, unikorncorev1.AddToScheme(kubeScheme))
		require.NoError(t, identityv1.AddToScheme(kubeScheme))

		kubeClient := fake.NewClientBuilder().
			WithScheme(kubeScheme).
			WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*identityv1.GroupList); ok {
						return errSimulated
					}

					return c.List(ctx, list, opts...)
				},
			}).
			Build()

		manager, err := NewManager(1, testIssuer, kubeClient)
		require.NoError(t, err)

		stateFilePath := filepath.Join(t.TempDir(), "state.json")

		err = manager.Run(t.Context(), stateFilePath, false)
		require.Error(t, err)
	})

	//nolint:dupl
	t.Run("returns an error when listing organization users fails", func(t *testing.T) {
		t.Parallel()

		kubeScheme := runtime.NewScheme()
		require.NoError(t, unikorncorev1.AddToScheme(kubeScheme))
		require.NoError(t, identityv1.AddToScheme(kubeScheme))

		kubeClient := fake.NewClientBuilder().
			WithScheme(kubeScheme).
			WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*identityv1.OrganizationUserList); ok {
						return errSimulated
					}

					return c.List(ctx, list, opts...)
				},
			}).
			Build()

		manager, err := NewManager(1, testIssuer, kubeClient)
		require.NoError(t, err)

		stateFilePath := filepath.Join(t.TempDir(), "state.json")

		err = manager.Run(t.Context(), stateFilePath, false)
		require.Error(t, err)
	})

	//nolint:dupl
	t.Run("returns an error when listing users fails", func(t *testing.T) {
		t.Parallel()

		kubeScheme := runtime.NewScheme()
		require.NoError(t, unikorncorev1.AddToScheme(kubeScheme))
		require.NoError(t, identityv1.AddToScheme(kubeScheme))

		kubeClient := fake.NewClientBuilder().
			WithScheme(kubeScheme).
			WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*identityv1.UserList); ok {
						return errSimulated
					}

					return c.List(ctx, list, opts...)
				},
			}).
			Build()

		manager, err := NewManager(1, testIssuer, kubeClient)
		require.NoError(t, err)

		stateFilePath := filepath.Join(t.TempDir(), "state.json")

		err = manager.Run(t.Context(), stateFilePath, false)
		require.Error(t, err)
	})

	t.Run("returns inconsistent data error when building the in-memory cache fails", func(t *testing.T) {
		t.Parallel()

		organizationUser := newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)

		kubeScheme := runtime.NewScheme()
		require.NoError(t, unikorncorev1.AddToScheme(kubeScheme))
		require.NoError(t, identityv1.AddToScheme(kubeScheme))

		// Inject a duplicate organization user entry so buildInMemoryCache returns an error.
		// The fake client prevents two objects with the same name, so we duplicate via the interceptor.
		kubeClient := fake.NewClientBuilder().
			WithScheme(kubeScheme).
			WithObjects(&organizationUser).
			WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if err := c.List(ctx, list, opts...); err != nil {
						return err
					}

					if organizationUserList, ok := list.(*identityv1.OrganizationUserList); ok {
						organizationUserList.Items = append(organizationUserList.Items, organizationUserList.Items...)
					}

					return nil
				},
			}).
			Build()

		manager, err := NewManager(1, testIssuer, kubeClient)
		require.NoError(t, err)

		stateFilePath := filepath.Join(t.TempDir(), "state.json")

		err = manager.Run(t.Context(), stateFilePath, false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("skips groups that were successfully migrated in a previous run", func(t *testing.T) {
		t.Parallel()

		// group-1 would fail migration (subject has no matching user), but it is marked
		// as successful in the previous results file and should therefore be skipped.
		var (
			subject = newTestGroupSubject("missing@example.com", testIssuer, "missing@example.com")
			group   = newTestGroup("group-1", nil, []identityv1.GroupSubject{subject})
			manager = newTestManager(t, &group)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		results := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true},
		}

		writeStateFile(t, path, false, results)

		err := manager.Run(t.Context(), path, false)
		require.NoError(t, err)
	})

	t.Run("retries groups that failed in a previous run", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			user             = newTestUser(testUserNameAlice, testSubjectAlice)
			group            = newTestGroup("group-1", []string{testOrganizationUserNameAlice}, nil)
			manager          = newTestManager(t, &organizationUser, &user, &group)
			path             = filepath.Join(t.TempDir(), "state.json")
			errorMessage     = "previous error"
		)

		results := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: false, ErrorMessage: &errorMessage},
		}

		writeStateFile(t, path, false, results)

		err := manager.Run(t.Context(), path, false)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		subject := newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
		assert.Equal(t, []identityv1.GroupSubject{subject}, updatedGroup.Spec.Subjects)
	})

	t.Run("does not patch any groups in dry run mode", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser        = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			user                    = newTestUser(testUserNameAlice, testSubjectAlice)
			group                   = newTestGroup("group-1", []string{testOrganizationUserNameAlice}, nil) // needs migration
			originalResourceVersion = group.ResourceVersion
			manager                 = newTestManager(t, &organizationUser, &user, &group)
			path                    = filepath.Join(t.TempDir(), "state.json")
		)

		err := manager.Run(t.Context(), path, true)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		assert.Equal(t, originalResourceVersion, updatedGroup.ResourceVersion, "group should not be patched in dry-run mode")
	})

	t.Run("migrates a group from a user id to a subject entry", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			user             = newTestUser(testUserNameAlice, testSubjectAlice)
			group            = newTestGroup("group-1", []string{testOrganizationUserNameAlice}, nil)
			manager          = newTestManager(t, &organizationUser, &user, &group)
		)

		stateFilePath := filepath.Join(t.TempDir(), "state.json")

		err := manager.Run(t.Context(), stateFilePath, false)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		subject := newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
		assert.Equal(t, []identityv1.GroupSubject{subject}, updatedGroup.Spec.Subjects)
	})

	t.Run("marks pending groups as failed when context is cancelled mid-run", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		// Both groups need migration (missing subjects). With concurrency=1, group-2
		// will not have started when group-1's patch cancels the context.

		var (
			organizationUser = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			user             = newTestUser(testUserNameAlice, testSubjectAlice)
			group1           = newTestGroup("group-1", []string{testOrganizationUserNameAlice}, nil)
			group2           = newTestGroup("group-2", []string{testOrganizationUserNameAlice}, nil)
		)

		kubeScheme := runtime.NewScheme()
		require.NoError(t, unikorncorev1.AddToScheme(kubeScheme))
		require.NoError(t, identityv1.AddToScheme(kubeScheme))

		kubeClient := fake.NewClientBuilder().
			WithScheme(kubeScheme).
			WithObjects(&organizationUser, &user, &group1, &group2).
			WithInterceptorFuncs(interceptor.Funcs{
				Patch: func(pctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					cancel()
					return c.Patch(pctx, obj, patch, opts...)
				},
			}).
			Build()

		manager, err := NewManager(1, testIssuer, kubeClient)
		require.NoError(t, err)

		path := filepath.Join(t.TempDir(), "state.json")

		err = manager.Run(ctx, path, false)
		require.Error(t, err)

		var migrationError *MigrationError
		require.ErrorAs(t, err, &migrationError) //nolint:wsl
		assert.Equal(t, 1, migrationError.Failed)
		assert.Equal(t, 2, migrationError.Total)

		data, err := os.ReadFile(path)
		require.NoError(t, err)

		var state State
		err = json.Unmarshal(data, &state)
		require.NoError(t, err)

		resultsByName := make(map[string]Result, len(state.Results))
		for _, result := range state.Results {
			resultsByName[result.Name] = result
		}

		group1Result := resultsByName["group-1"]
		assert.True(t, group1Result.Success, "group-1 should have been patched before cancellation")

		group2Result := resultsByName["group-2"]
		assert.False(t, group2Result.Success, "group-2 should be marked as failed due to context cancellation")
		require.NotNil(t, group2Result.ErrorMessage)
		assert.Contains(t, *group2Result.ErrorMessage, context.Canceled.Error())
	})

	t.Run("writes migration state to the state file", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			user             = newTestUser(testUserNameAlice, testSubjectAlice)
			group            = newTestGroup("group-1", []string{testOrganizationUserNameAlice}, nil)
			manager          = newTestManager(t, &organizationUser, &user, &group)
			path             = filepath.Join(t.TempDir(), "state.json")
		)

		err := manager.Run(t.Context(), path, false)
		require.NoError(t, err)

		data, err := os.ReadFile(path)
		require.NoError(t, err)

		var state State
		err = json.Unmarshal(data, &state)
		require.NoError(t, err)

		results := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true},
		}

		assert.False(t, state.DryRun)
		assert.Equal(t, results, state.Results)
	})

	t.Run("returns a groups migration error when some groups fail to migrate", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			user             = newTestUser(testUserNameAlice, testSubjectAlice)

			// group1: fully migrated, no-op.
			userIDs1  = []string{testOrganizationUserNameAlice}
			subject1  = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			subjects1 = []identityv1.GroupSubject{subject1}
			group1    = newTestGroup("group-1", userIDs1, subjects1)

			// group2: references a subject with no matching user in the cache → fails.
			subject2  = newTestGroupSubject("missing@example.com", testIssuer, "missing@example.com")
			subjects2 = []identityv1.GroupSubject{subject2}
			group2    = newTestGroup("group-2", nil, subjects2)

			manager = newTestManager(t, &organizationUser, &user, &group1, &group2)
		)

		stateFilePath := filepath.Join(t.TempDir(), "state.json")

		err := manager.Run(t.Context(), stateFilePath, false)
		require.Error(t, err)

		var migrationError *MigrationError
		require.ErrorAs(t, err, &migrationError) //nolint:wsl
		assert.Equal(t, 1, migrationError.Failed)
		assert.Equal(t, 2, migrationError.Total)
	})

	t.Run("succeeds when there are no groups to migrate", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		stateFilePath := filepath.Join(t.TempDir(), "state.json")

		err := manager.Run(t.Context(), stateFilePath, false)
		require.NoError(t, err)
	})
}

func TestReadState(t *testing.T) {
	t.Parallel()

	t.Run("returns an empty slice when the state file does not exist", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		results, err := manager.readState(path, false)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("returns an error when the state file contains invalid json", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
			data    = []byte("invalid json")
		)

		err := os.WriteFile(path, data, 0600)
		require.NoError(t, err)

		_, err = manager.readState(path, false)
		require.Error(t, err)
	})

	t.Run("returns an error when a dry run state file is used for an actual migration", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		writeStateFile(t, path, true, nil)

		_, err := manager.readState(path, false)
		require.ErrorIs(t, err, ErrDryRunStateFile)
	})

	t.Run("succeeds when a dry run state file is used for another dry run", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		writeStateFile(t, path, true, nil)

		results, err := manager.readState(path, true)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("decodes and returns results from an existing state file", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		expected := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true},
			{Namespace: testNamespaceOrganizationOwned, Name: "group-2", Success: false},
		}

		writeStateFile(t, path, false, expected)

		results, err := manager.readState(path, false)
		require.NoError(t, err)
		assert.Equal(t, expected, results)
	})
}

func TestPrepareStateFile(t *testing.T) {
	t.Parallel()

	t.Run("creates the state file when no previous file exists", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		file, err := manager.prepareStateFile(path, false)
		require.NoError(t, err)
		defer file.Close()

		_, err = os.Stat(path)
		require.NoError(t, err, "state file should be created")
	})

	t.Run("backs up the previous state file when dry run is false", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		writeStateFile(t, path, false, nil)

		file, err := manager.prepareStateFile(path, false)
		require.NoError(t, err)
		defer file.Close()

		_, err = os.Stat(fmt.Sprintf("%s.backup", path))
		require.NoError(t, err, "backup file should exist")
	})

	t.Run("does not back up the state file when dry run is true", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
		)

		writeStateFile(t, path, true, nil)

		file, err := manager.prepareStateFile(path, true)
		require.NoError(t, err)
		defer file.Close()

		_, err = os.Stat(fmt.Sprintf("%s.backup", path))
		require.ErrorIs(t, err, os.ErrNotExist, "backup file should not exist for dry-run")
	})
}

func TestBuildInMemoryCache(t *testing.T) {
	t.Parallel()

	t.Run("returns inconsistent data error for a duplicate organization user name", func(t *testing.T) {
		t.Parallel()

		var (
			manager           = newTestManager(t)
			organizationUser  = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers = []identityv1.OrganizationUser{organizationUser, organizationUser}
		)

		_, err := manager.buildInMemoryCache(organizationUsers, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error when an organization user has no user label", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		organizationUser := newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
		delete(organizationUser.Labels, coreconstants.UserLabel)

		organizationUsers := []identityv1.OrganizationUser{organizationUser}

		_, err := manager.buildInMemoryCache(organizationUsers, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error for a duplicate namespaced user id", func(t *testing.T) {
		t.Parallel()

		// Two organization users with different names but the same UserLabel value in the
		// same namespace resolve to the same namespaced user ID, which is inconsistent.
		var (
			manager           = newTestManager(t)
			organizationUser1 = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUser2 = newTestOrganizationUser(testOrganizationUserNameBob, testUserNameAlice) // different name, same UserLabel
			organizationUsers = []identityv1.OrganizationUser{organizationUser1, organizationUser2}
		)

		_, err := manager.buildInMemoryCache(organizationUsers, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error for a duplicate user name", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			user1   = newTestUser(testUserNameAlice, testSubjectAlice)
			user2   = newTestUser(testUserNameAlice, testSubjectBob) // same name as if from a different namespace
			users   = []identityv1.User{user1, user2}
		)

		_, err := manager.buildInMemoryCache(nil, users)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error for a duplicate user subject", func(t *testing.T) {
		t.Parallel()

		var (
			manager          = newTestManager(t)
			userAlice        = newTestUser(testUserNameAlice, testSubjectAlice)
			userNameAliceAlt = fmt.Sprintf("%s-alt", testUserNameAlice)
			userAliceAlt     = newTestUser(userNameAliceAlt, testSubjectAlice) // same subject, different name
			users            = []identityv1.User{userAlice, userAliceAlt}
		)

		_, err := manager.buildInMemoryCache(nil, users)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("populates all four index maps for two valid users", func(t *testing.T) {
		t.Parallel()

		var (
			manager               = newTestManager(t)
			organizationUserAlice = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUserBob   = newTestOrganizationUser(testOrganizationUserNameBob, testUserNameBob)
			organizationUsers     = []identityv1.OrganizationUser{organizationUserAlice, organizationUserBob}
			userAlice             = newTestUser(testUserNameAlice, testSubjectAlice)
			userBob               = newTestUser(testUserNameBob, testSubjectBob)
			users                 = []identityv1.User{userAlice, userBob}
		)

		cc, err := manager.buildInMemoryCache(organizationUsers, users)
		require.NoError(t, err)

		assert.Len(t, cc.OrganizationUserByID, 2)
		assert.Len(t, cc.OrganizationUserByNamespacedUserID, 2)
		assert.Len(t, cc.UserByID, 2)
		assert.Len(t, cc.UserBySubject, 2)

		assert.Equal(t, &organizationUserAlice, cc.OrganizationUserByID[testOrganizationUserNameAlice])

		namespacedUserID := namespacedID(testNamespaceOrganizationOwned, testUserNameAlice)
		assert.Equal(t, &organizationUserAlice, cc.OrganizationUserByNamespacedUserID[namespacedUserID])

		assert.Equal(t, &userAlice, cc.UserBySubject[testSubjectAlice])
		assert.Equal(t, &userAlice, cc.UserByID[testUserNameAlice])
	})

	t.Run("returns an empty cache when given no inputs", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		cc, err := manager.buildInMemoryCache(nil, nil)
		require.NoError(t, err)
		assert.Empty(t, cc.OrganizationUserByID)
		assert.Empty(t, cc.OrganizationUserByNamespacedUserID)
		assert.Empty(t, cc.UserByID)
		assert.Empty(t, cc.UserBySubject)
	})
}

func TestMigrate(t *testing.T) {
	t.Parallel()

	t.Run("backfills the issuer on a subject that has an empty issuer", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser  = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers = []identityv1.OrganizationUser{organizationUser}
			user              = newTestUser(testUserNameAlice, testSubjectAlice)
			users             = []identityv1.User{user}
			userIDs           = []string{testOrganizationUserNameAlice}
			subject           = newTestGroupSubject(testSubjectAlice, "", testSubjectAlice) // empty issuer
			subjects          = []identityv1.GroupSubject{subject}
			group             = newTestGroup("group-1", userIDs, subjects)
			manager           = newTestManager(t, &organizationUser, &user, &group)
		)

		cc, err := manager.buildInMemoryCache(organizationUsers, users)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, false)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		require.Len(t, updatedGroup.Spec.Subjects, 1)
		assert.Equal(t, testIssuer, updatedGroup.Spec.Subjects[0].Issuer)
	})

	t.Run("returns an error when a subject's user is not found in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			subject  = newTestGroupSubject("missing@example.com", testIssuer, "missing@example.com")
			subjects = []identityv1.GroupSubject{subject}
			group    = newTestGroup("group-1", nil, subjects)
			manager  = newTestManager(t)
		)

		cc, err := manager.buildInMemoryCache(nil, nil)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns an error when an organization user is not found in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			userIDs = []string{"organization-user-missing"}
			group   = newTestGroup("group-1", userIDs, nil)
			manager = newTestManager(t)
		)

		cc, err := manager.buildInMemoryCache(nil, nil)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, false)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("does not patch the group when it is already fully migrated", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser        = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers       = []identityv1.OrganizationUser{organizationUser}
			user                    = newTestUser(testUserNameAlice, testSubjectAlice)
			users                   = []identityv1.User{user}
			userIDs                 = []string{testOrganizationUserNameAlice}
			subject                 = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			subjects                = []identityv1.GroupSubject{subject}
			group                   = newTestGroup("group-1", userIDs, subjects)
			originalResourceVersion = group.ResourceVersion
			manager                 = newTestManager(t, &organizationUser, &user, &group)
		)

		cc, err := manager.buildInMemoryCache(organizationUsers, users)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, false)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		assert.Equal(t, originalResourceVersion, updatedGroup.ResourceVersion, "group should not be patched when already fully migrated")
	})

	t.Run("does not patch the group in dry run mode even when changes are needed", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser        = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers       = []identityv1.OrganizationUser{organizationUser}
			user                    = newTestUser(testUserNameAlice, testSubjectAlice)
			users                   = []identityv1.User{user}
			userIDs                 = []string{testOrganizationUserNameAlice}
			group                   = newTestGroup("group-1", userIDs, nil) // needs migration: missing subjects
			originalResourceVersion = group.ResourceVersion
			manager                 = newTestManager(t, &organizationUser, &user, &group)
		)

		cc, err := manager.buildInMemoryCache(organizationUsers, users)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, true)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		assert.Equal(t, originalResourceVersion, updatedGroup.ResourceVersion, "group should not be patched in dry-run mode")
	})

	t.Run("returns an error when the kubernetes patch fails", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser  = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers = []identityv1.OrganizationUser{organizationUser}
			user              = newTestUser(testUserNameAlice, testSubjectAlice)
			users             = []identityv1.User{user}
			userIDs           = []string{testOrganizationUserNameAlice}
			group             = newTestGroup("group-1", userIDs, nil)
		)

		kubeScheme := runtime.NewScheme()
		require.NoError(t, unikorncorev1.AddToScheme(kubeScheme))
		require.NoError(t, identityv1.AddToScheme(kubeScheme))

		kubeClient := fake.NewClientBuilder().
			WithScheme(kubeScheme).
			WithObjects(&group).
			WithInterceptorFuncs(interceptor.Funcs{
				Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
					return errSimulated
				},
			}).
			Build()

		manager, err := NewManager(1, testIssuer, kubeClient)
		require.NoError(t, err)

		cc, err := manager.buildInMemoryCache(organizationUsers, users)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, false)
		require.Error(t, err)
	})

	t.Run("adds the organization user id when only a subject is set", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser  = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers = []identityv1.OrganizationUser{organizationUser}
			user              = newTestUser(testUserNameAlice, testSubjectAlice)
			users             = []identityv1.User{user}
			subject           = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			subjects          = []identityv1.GroupSubject{subject}
			group             = newTestGroup("group-1", nil, subjects)
			manager           = newTestManager(t, &organizationUser, &user, &group)
		)

		cc, err := manager.buildInMemoryCache(organizationUsers, users)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, false)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		assert.Equal(t, []string{testOrganizationUserNameAlice}, updatedGroup.Spec.UserIDs)
		assert.Equal(t, []identityv1.GroupSubject{subject}, updatedGroup.Spec.Subjects)
	})

	t.Run("adds a subject entry when only a user id is set", func(t *testing.T) {
		t.Parallel()

		var (
			organizationUser  = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers = []identityv1.OrganizationUser{organizationUser}
			user              = newTestUser(testUserNameAlice, testSubjectAlice)
			users             = []identityv1.User{user}
			userIDs           = []string{testOrganizationUserNameAlice}
			group             = newTestGroup("group-1", userIDs, nil)
			manager           = newTestManager(t, &organizationUser, &user, &group)
		)

		cc, err := manager.buildInMemoryCache(organizationUsers, users)
		require.NoError(t, err)

		err = manager.migrate(t.Context(), &group, cc, false)
		require.NoError(t, err)

		objectKey := client.ObjectKey{
			Name:      "group-1",
			Namespace: testNamespaceOrganizationOwned,
		}

		var updatedGroup identityv1.Group
		err = manager.kubeClient.Get(t.Context(), objectKey, &updatedGroup)
		require.NoError(t, err)

		assert.Equal(t, []string{testOrganizationUserNameAlice}, updatedGroup.Spec.UserIDs)

		subject := newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
		assert.Equal(t, []identityv1.GroupSubject{subject}, updatedGroup.Spec.Subjects)
	})
}

func TestPatchEmptyIssuerSubjects(t *testing.T) {
	t.Parallel()

	t.Run("fills the issuer field on subjects that have an empty issuer", func(t *testing.T) {
		t.Parallel()

		var (
			manager           = newTestManager(t)
			groupSubjectAlice = newTestGroupSubject(testSubjectAlice, "", testSubjectAlice)
			groupSubjectBob   = newTestGroupSubject(testSubjectBob, testIssuer, testSubjectBob)
			groupSubjects     = []identityv1.GroupSubject{groupSubjectAlice, groupSubjectBob}
			group             = newTestGroup("group-1", nil, groupSubjects)
		)

		hasPatched := manager.patchEmptyIssuerSubjects(&group)
		assert.True(t, hasPatched)
		assert.Len(t, group.Spec.Subjects, 2)
		assert.Equal(t, testIssuer, group.Spec.Subjects[0].Issuer, "empty issuer should be filled")
		assert.Equal(t, testIssuer, group.Spec.Subjects[1].Issuer, "non-empty issuer should be unchanged")
	})

	t.Run("returns false when all subjects already have an issuer", func(t *testing.T) {
		t.Parallel()

		var (
			manager       = newTestManager(t)
			groupSubject  = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			groupSubjects = []identityv1.GroupSubject{groupSubject}
			group         = newTestGroup("group-1", nil, groupSubjects)
		)

		hasPatched := manager.patchEmptyIssuerSubjects(&group)
		assert.False(t, hasPatched)
	})

	t.Run("returns false when the group has no subjects", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			group   = newTestGroup("g1", nil, nil)
		)

		hasPatched := manager.patchEmptyIssuerSubjects(&group)
		assert.False(t, hasPatched)
	})
}

func cacheAlice(t *testing.T, manager *Manager) *Cache {
	t.Helper()

	var (
		organizationUser  = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
		organizationUsers = []identityv1.OrganizationUser{organizationUser}
		user              = newTestUser(testUserNameAlice, testSubjectAlice)
		users             = []identityv1.User{user}
	)

	cc, err := manager.buildInMemoryCache(organizationUsers, users)
	require.NoError(t, err)

	return cc
}

func TestComputeMissingUserIDs(t *testing.T) {
	t.Parallel()

	t.Run("returns inconsistent data error when the subject is not in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			subject  = newTestGroupSubject("missing@example.com", testIssuer, "missing@example.com")
			subjects = []identityv1.GroupSubject{subject}
			original = newTestGroup("group-1", nil, subjects)
			patched  = original.DeepCopy()
		)

		cc, err := manager.buildInMemoryCache(nil, nil)
		require.NoError(t, err)

		err = manager.computeMissingUserIDs(&original, patched, cc)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error when the organization user is not in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			user     = newTestUser(testUserNameAlice, testSubjectAlice)
			users    = []identityv1.User{user}
			subject  = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			subjects = []identityv1.GroupSubject{subject}
			original = newTestGroup("group-1", nil, subjects)
			patched  = original.DeepCopy()
		)

		cc, err := manager.buildInMemoryCache(nil, users)
		require.NoError(t, err)

		err = manager.computeMissingUserIDs(&original, patched, cc)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error when the subject email does not match any user subject", func(t *testing.T) {
		t.Parallel()

		// UserBySubject is keyed by user.Spec.Subject. The lookup uses subject.Email.
		// If the two fields differ, the user cannot be found.
		var (
			manager  = newTestManager(t)
			user     = newTestUser(testUserNameAlice, testSubjectAlice) // Subject = testSubjectAlice
			users    = []identityv1.User{user}
			subject  = newTestGroupSubject(testSubjectAlice, testIssuer, "different-email@example.com") // Email ≠ Subject
			subjects = []identityv1.GroupSubject{subject}
			original = newTestGroup("group-1", nil, subjects)
			patched  = original.DeepCopy()
		)

		cc, err := manager.buildInMemoryCache(nil, users)
		require.NoError(t, err)

		err = manager.computeMissingUserIDs(&original, patched, cc)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("does not duplicate a user id that is already present", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			userIDs  = []string{testOrganizationUserNameAlice}
			subject  = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			subjects = []identityv1.GroupSubject{subject}
			original = newTestGroup("group-1", userIDs, subjects)
			patched  = original.DeepCopy()
			cc       = cacheAlice(t, manager)
		)

		err := manager.computeMissingUserIDs(&original, patched, cc)
		require.NoError(t, err)
		assert.Equal(t, []string{testOrganizationUserNameAlice}, patched.Spec.UserIDs, "existing userID should not be duplicated")
	})

	t.Run("adds the organization user id when a matching subject exists in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			subject  = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			subjects = []identityv1.GroupSubject{subject}
			original = newTestGroup("group-1", nil, subjects)
			patched  = original.DeepCopy()
			cc       = cacheAlice(t, manager)
		)

		err := manager.computeMissingUserIDs(&original, patched, cc)
		require.NoError(t, err)
		assert.Equal(t, []string{testOrganizationUserNameAlice}, patched.Spec.UserIDs)
	})

	t.Run("makes no changes when the group has no subjects", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			original = newTestGroup("group-1", nil, nil)
			patched  = original.DeepCopy()
		)

		cc, err := manager.buildInMemoryCache(nil, nil)
		require.NoError(t, err)

		err = manager.computeMissingUserIDs(&original, patched, cc)
		require.NoError(t, err)
		assert.Empty(t, patched.Spec.UserIDs)
	})
}

func TestComputeMissingSubjects(t *testing.T) {
	t.Parallel()

	t.Run("returns inconsistent data error when the organization user is not in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			userIDs  = []string{"organization-user-missing"}
			original = newTestGroup("group-1", userIDs, nil)
			patched  = original.DeepCopy()
		)

		cc, err := manager.buildInMemoryCache(nil, nil)
		require.NoError(t, err)

		err = manager.computeMissingSubjects(&original, patched, cc)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error when the organization user has no user label", func(t *testing.T) {
		t.Parallel()

		organizationUser := newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
		delete(organizationUser.Labels, coreconstants.UserLabel)

		var (
			manager  = newTestManager(t)
			userIDs  = []string{testOrganizationUserNameAlice}
			original = newTestGroup("group-1", userIDs, nil)
			patched  = original.DeepCopy()
		)

		cc := &Cache{
			OrganizationUserByID: map[string]*identityv1.OrganizationUser{
				organizationUser.Name: &organizationUser,
			},
			OrganizationUserByNamespacedUserID: make(map[string]*identityv1.OrganizationUser),
			UserByID:                           make(map[string]*identityv1.User),
			UserBySubject:                      make(map[string]*identityv1.User),
		}

		err := manager.computeMissingSubjects(&original, patched, cc)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("returns inconsistent data error when the user is not in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			manager           = newTestManager(t)
			userIDs           = []string{testOrganizationUserNameAlice}
			organizationUser  = newTestOrganizationUser(testOrganizationUserNameAlice, testUserNameAlice)
			organizationUsers = []identityv1.OrganizationUser{organizationUser}
			original          = newTestGroup("group-1", userIDs, nil)
			patched           = original.DeepCopy()
		)

		cc, err := manager.buildInMemoryCache(organizationUsers, nil)
		require.NoError(t, err)

		err = manager.computeMissingSubjects(&original, patched, cc)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInconsistentData)
	})

	t.Run("does not duplicate a subject that is already present", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			userIDs  = []string{testOrganizationUserNameAlice}
			subject  = newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
			subjects = []identityv1.GroupSubject{subject}
			original = newTestGroup("group-1", userIDs, subjects)
			patched  = original.DeepCopy()
			cc       = cacheAlice(t, manager)
		)

		err := manager.computeMissingSubjects(&original, patched, cc)
		require.NoError(t, err)
		assert.Equal(t, []identityv1.GroupSubject{subject}, patched.Spec.Subjects, "existing subject should not be duplicated")
	})

	t.Run("adds a subject entry when a matching organization user exists in the cache", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			userIDs  = []string{testOrganizationUserNameAlice}
			original = newTestGroup("group-1", userIDs, nil)
			patched  = original.DeepCopy()
			cc       = cacheAlice(t, manager)
		)

		err := manager.computeMissingSubjects(&original, patched, cc)
		require.NoError(t, err)

		require.Len(t, patched.Spec.Subjects, 1)

		subject := newTestGroupSubject(testSubjectAlice, testIssuer, testSubjectAlice)
		assert.Equal(t, []identityv1.GroupSubject{subject}, patched.Spec.Subjects)
	})

	t.Run("makes no changes when the group has no user ids", func(t *testing.T) {
		t.Parallel()

		var (
			manager  = newTestManager(t)
			original = newTestGroup("group-1", nil, nil)
			patched  = original.DeepCopy()
		)

		cc, err := manager.buildInMemoryCache(nil, nil)
		require.NoError(t, err)

		err = manager.computeMissingSubjects(&original, patched, cc)
		require.NoError(t, err)
		assert.Empty(t, patched.Spec.Subjects)
	})
}

func TestMergeResults(t *testing.T) {
	t.Parallel()

	t.Run("returns an empty slice when both inputs are empty", func(t *testing.T) {
		t.Parallel()

		var (
			manager    = newTestManager(t)
			results    = make([]Result, 0)
			resultMemo = make(map[string]*Result)
		)

		mergedResults := manager.mergeResults(results, resultMemo)
		assert.Empty(t, mergedResults)
	})

	t.Run("adds new results to an empty memo", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		results := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true},
		}

		resultMemo := make(map[string]*Result)

		mergedResults := manager.mergeResults(results, resultMemo)
		require.Len(t, mergedResults, 1)
		assert.Equal(t, mergedResults[0], results[0])
	})

	t.Run("overwrites a previous failed result with a new successful result", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		results := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true},
		}

		resultMemo := map[string]*Result{
			namespacedID(testNamespaceOrganizationOwned, "group-1"): {
				Namespace: testNamespaceOrganizationOwned,
				Name:      "group-1",
				Success:   false,
			},
		}

		mergedResults := manager.mergeResults(results, resultMemo)
		require.Len(t, mergedResults, 1)
		assert.Equal(t, mergedResults[0], results[0])
	})

	t.Run("preserves results from the previous run for groups not in the current results", func(t *testing.T) {
		t.Parallel()

		var (
			manager         = newTestManager(t)
			previousResult  = Result{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true}
			previousResults = []Result{previousResult}
		)

		resultMemo := map[string]*Result{
			namespacedID(testNamespaceOrganizationOwned, "group-1"): &previousResult,
		}

		mergedResults := manager.mergeResults(nil, resultMemo)
		assert.Equal(t, previousResults, mergedResults)
	})
}

func TestWriteState(t *testing.T) {
	t.Parallel()

	t.Run("encodes a state file with dry_run false for an actual migration", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
			results = []Result{{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true}}
		)

		file, err := manager.prepareStateFile(path, false)
		require.NoError(t, err)
		defer file.Close()

		require.NoError(t, manager.writeState(file, false, results))

		data, err := os.ReadFile(path)
		require.NoError(t, err)

		var state State
		err = json.Unmarshal(data, &state)
		require.NoError(t, err)

		assert.False(t, state.DryRun)
		assert.Equal(t, results, state.Results)
	})

	t.Run("encodes a state file with dry_run true for a dry run", func(t *testing.T) {
		t.Parallel()

		var (
			manager = newTestManager(t)
			path    = filepath.Join(t.TempDir(), "state.json")
			results = []Result{{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true}}
		)

		file, err := manager.prepareStateFile(path, true)
		require.NoError(t, err)
		defer file.Close()

		require.NoError(t, manager.writeState(file, true, results))

		data, err := os.ReadFile(path)
		require.NoError(t, err)

		var state State
		err = json.Unmarshal(data, &state)
		require.NoError(t, err)

		assert.True(t, state.DryRun)
		assert.Equal(t, results, state.Results)
	})
}

func TestCheckFailures(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when there are no results", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		err := manager.checkFailures(nil)
		require.NoError(t, err)
	})

	t.Run("returns nil when all results are successful", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		results := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true},
			{Namespace: testNamespaceOrganizationOwned, Name: "group-2", Success: true},
		}

		err := manager.checkFailures(results)
		require.NoError(t, err)
	})

	t.Run("returns a migration error with the correct counts when some results failed", func(t *testing.T) {
		t.Parallel()

		manager := newTestManager(t)

		results := []Result{
			{Namespace: testNamespaceOrganizationOwned, Name: "group-1", Success: true},
			{Namespace: testNamespaceOrganizationOwned, Name: "group-2", Success: false},
		}

		err := manager.checkFailures(results)
		require.Error(t, err)

		var migrationError *MigrationError
		require.ErrorAs(t, err, &migrationError) //nolint:wsl
		assert.Equal(t, 1, migrationError.Failed)
		assert.Equal(t, 2, migrationError.Total)
	})
}
