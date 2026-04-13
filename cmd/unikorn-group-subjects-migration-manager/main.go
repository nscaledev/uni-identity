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
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"

	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var ErrInconsistentData = errors.New("inconsistent data")

type GroupsMigrationError struct {
	Failed int
	Total  int
}

func NewGroupsMigrationError(failed, total int) error {
	return &GroupsMigrationError{
		Failed: failed,
		Total:  total,
	}
}

func (e *GroupsMigrationError) Error() string {
	return fmt.Sprintf("%d/%d groups failed during migration, please check the logs for details", e.Failed, e.Total)
}

type Options struct {
	concurrency    int
	identityIssuer string
	zap            zap.Options
}

func (o *Options) BindFlags(fs *pflag.FlagSet) {
	fs.IntVar(&o.concurrency, "concurrency", 10, "Number of concurrent workers to run for the migration")
	fs.StringVar(&o.identityIssuer, "identity-issuer", "", "OIDC issuer URL of the uni-identity provider")

	gofs := flag.NewFlagSet("", flag.ExitOnError)
	o.zap.BindFlags(gofs)
	fs.AddGoFlagSet(gofs)
}

func (o *Options) SetupLoggers() {
	logger := zap.New(zap.UseFlagOptions(&o.zap))
	log.SetLogger(logger)
	klog.SetLogger(logger)
}

func main() {
	var options Options

	options.BindFlags(pflag.CommandLine)

	pflag.Parse()

	options.SetupLoggers()

	scopedLogger := log.Log.WithName(path.Base(os.Args[0]))

	kubeClient, err := createKubernetesClient(unikorncorev1.AddToScheme, identityv1.AddToScheme)
	if err != nil {
		scopedLogger.Error(err, "failed to create kubernetes client")
		os.Exit(1)
	}

	manager := NewManager(options.concurrency, options.identityIssuer, kubeClient, scopedLogger)

	if err = run(manager); err != nil {
		scopedLogger.Error(err, "migration failed")
		os.Exit(1)
	}
}

func run(manager *Manager) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)

	go func() {
		<-stop
		cancel()
	}()

	if err := manager.Run(ctx); err != nil {
		return err
	}

	return nil
}

func createKubernetesClient(typeRegistries ...func(*runtime.Scheme) error) (client.Client, error) {
	kubeScheme := runtime.NewScheme()
	for _, typeRegistry := range typeRegistries {
		if err := typeRegistry(kubeScheme); err != nil {
			return nil, fmt.Errorf("failed to register types to kubernetes runtime scheme: %w", err)
		}
	}

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster kubernetes config: %w", err)
	}

	kubeClient, err := client.New(kubeConfig, client.Options{Scheme: kubeScheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return kubeClient, nil
}

type Cache struct {
	OrganizationUserByID               map[string]*identityv1.OrganizationUser
	OrganizationUserByNamespacedUserID map[string]*identityv1.OrganizationUser
	UserByID                           map[string]*identityv1.User
	UserBySubject                      map[string]*identityv1.User
}

func namespacedID(namespace, id string) string {
	return fmt.Sprintf("%s/%s", namespace, id)
}

type Manager struct {
	concurrency    int
	identityIssuer string
	kubeClient     client.Client
	scopedLogger   logr.Logger
}

func NewManager(concurrency int, identityIssuer string, kubeClient client.Client, scopedLogger logr.Logger) *Manager {
	return &Manager{
		concurrency:    concurrency,
		identityIssuer: identityIssuer,
		kubeClient:     kubeClient,
		scopedLogger:   scopedLogger,
	}
}

func (m *Manager) Run(ctx context.Context) error {
	var groupList identityv1.GroupList
	if err := m.kubeClient.List(ctx, &groupList); err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}

	var organizationUserList identityv1.OrganizationUserList
	if err := m.kubeClient.List(ctx, &organizationUserList); err != nil {
		return fmt.Errorf("failed to list organization users: %w", err)
	}

	var userList identityv1.UserList
	if err := m.kubeClient.List(ctx, &userList); err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	cc, err := m.buildInMemoryCache(organizationUserList.Items, userList.Items)
	if err != nil {
		return err
	}

	var (
		semaphore = make(chan struct{}, m.concurrency)
		completed = make(chan error)
		failed    = 0
	)

	go m.dispatch(ctx, groupList.Items, cc, semaphore, completed)

	for range groupList.Items {
		if err = <-completed; err != nil {
			failed++
		}

		<-semaphore
	}

	if failed > 0 {
		return NewGroupsMigrationError(failed, len(groupList.Items))
	}

	return nil
}

func (m *Manager) buildInMemoryCache(organizationUsers []identityv1.OrganizationUser, users []identityv1.User) (*Cache, error) {
	cc := Cache{
		OrganizationUserByID:               make(map[string]*identityv1.OrganizationUser, len(organizationUsers)),
		OrganizationUserByNamespacedUserID: make(map[string]*identityv1.OrganizationUser, len(organizationUsers)),
		UserByID:                           make(map[string]*identityv1.User, len(users)),
		UserBySubject:                      make(map[string]*identityv1.User, len(users)),
	}

	for i := range organizationUsers {
		organizationUser := &organizationUsers[i]

		if _, ok := cc.OrganizationUserByID[organizationUser.Name]; ok {
			return nil, fmt.Errorf("multiple organization users found with the same name %q: %w", organizationUser.Name, ErrInconsistentData)
		}

		cc.OrganizationUserByID[organizationUser.Name] = organizationUser

		namespacedUserID := namespacedID(organizationUser.Namespace, organizationUser.Name)

		if _, ok := cc.OrganizationUserByNamespacedUserID[namespacedUserID]; ok {
			return nil, fmt.Errorf("multiple organization users found with the same namespaced user ID %q: %w", namespacedUserID, ErrInconsistentData)
		}

		cc.OrganizationUserByNamespacedUserID[namespacedUserID] = organizationUser
	}

	for i := range users {
		user := &users[i]

		if _, ok := cc.UserByID[user.Name]; ok {
			return nil, fmt.Errorf("multiple users found with the same name %q: %w", user.Name, ErrInconsistentData)
		}

		cc.UserByID[user.Name] = user

		if _, ok := cc.UserBySubject[user.Spec.Subject]; ok {
			return nil, fmt.Errorf("multiple users found with the same subject %q: %w", user.Spec.Subject, ErrInconsistentData)
		}

		cc.UserBySubject[user.Spec.Subject] = user
	}

	return &cc, nil
}

func (m *Manager) dispatch(ctx context.Context, groups []identityv1.Group, cc *Cache, semaphore chan<- struct{}, completed chan<- error) {
	for i := range groups {
		semaphore <- struct{}{}

		go func(group *identityv1.Group) {
			completed <- m.migrate(ctx, group, cc)
		}(&groups[i])
	}
}

func (m *Manager) migrate(ctx context.Context, group *identityv1.Group, cc *Cache) error {
	resourceLogger := m.scopedLogger.WithValues("group", group.Name, "namespace", group.Namespace)

	patched := group.DeepCopy()

	hasPatched := m.patchEmptyIssuerSubjects(patched)

	if err := m.computeMissingUserIDs(group, patched, cc, resourceLogger); err != nil {
		return err
	}

	if err := m.computeMissingSubjects(group, patched, cc, resourceLogger); err != nil {
		return err
	}

	// Skip the patch if nothing changed: no subject issuers were backfilled and
	// neither the UserIDs nor Subjects slices grew. Length comparison is sufficient
	// because the compute functions only append. They never remove or reorder entries.
	if !hasPatched && len(group.Spec.UserIDs) == len(patched.Spec.UserIDs) && len(group.Spec.Subjects) == len(patched.Spec.Subjects) {
		return nil
	}

	if err := m.kubeClient.Patch(ctx, patched, client.MergeFromWithOptions(group, client.MergeFromWithOptimisticLock{})); err != nil {
		resourceLogger.Error(err, "failed to patch group")

		return fmt.Errorf("failed to patch group %q in namespace %q: %w", group.Name, group.Namespace, err)
	}

	return nil
}

func (m *Manager) patchEmptyIssuerSubjects(patched *identityv1.Group) bool {
	var hasPatched bool

	for i := range patched.Spec.Subjects {
		subject := &patched.Spec.Subjects[i]

		if subject.Issuer == "" {
			hasPatched = true
			subject.Issuer = m.identityIssuer
		}
	}

	return hasPatched
}

func (m *Manager) computeMissingUserIDs(original, patched *identityv1.Group, cc *Cache, resourceLogger logr.Logger) error {
	userIDMemo := make(map[string]struct{}, len(original.Spec.UserIDs))
	for _, userID := range original.Spec.UserIDs {
		userIDMemo[userID] = struct{}{}
	}

	for i := range original.Spec.Subjects {
		subject := &original.Spec.Subjects[i]

		user, ok := cc.UserBySubject[subject.Email]
		if !ok {
			resourceLogger.Error(
				ErrInconsistentData,
				"user not found for subject",
				"subject", subject.Email,
			)

			return fmt.Errorf("user not found for subject %q: %w", subject.Email, ErrInconsistentData)
		}

		namespacedUserID := namespacedID(original.Namespace, user.Name)

		organizationUser, ok := cc.OrganizationUserByNamespacedUserID[namespacedUserID]
		if !ok {
			resourceLogger.Error(
				ErrInconsistentData,
				"organization user not found for namespaced user ID",
				"namespaced_user_id", namespacedUserID,
			)

			return fmt.Errorf("organization user not found for namespaced user ID %q: %w", namespacedUserID, ErrInconsistentData)
		}

		if _, exists := userIDMemo[organizationUser.Name]; exists {
			continue
		}

		userIDMemo[organizationUser.Name] = struct{}{}

		patched.Spec.UserIDs = append(patched.Spec.UserIDs, organizationUser.Name)
	}

	return nil
}

func (m *Manager) computeMissingSubjects(original, patched *identityv1.Group, cc *Cache, resourceLogger logr.Logger) error {
	subjectMemo := make(map[string]struct{}, len(original.Spec.Subjects))
	for _, subject := range original.Spec.Subjects {
		subjectMemo[subject.Email] = struct{}{}
	}

	for _, organizationUserID := range original.Spec.UserIDs {
		organizationUser, ok := cc.OrganizationUserByID[organizationUserID]
		if !ok {
			resourceLogger.Error(
				ErrInconsistentData,
				"organization user not found",
				"organization_user", organizationUserID,
			)

			return fmt.Errorf("organization user %q not found: %w", organizationUserID, ErrInconsistentData)
		}

		userID, ok := organizationUser.Labels[coreconstants.UserLabel]
		if !ok {
			resourceLogger.Error(
				ErrInconsistentData,
				"organization user has no user label",
				"organization_user", organizationUserID,
			)

			return fmt.Errorf("organization user %q has no user label: %w", organizationUserID, ErrInconsistentData)
		}

		user, ok := cc.UserByID[userID]
		if !ok {
			resourceLogger.Error(
				ErrInconsistentData,
				"user not found for organization user",
				"user", userID,
				"organization_user", organizationUserID,
			)

			return fmt.Errorf("user %q not found for organization user %q: %w", userID, organizationUserID, ErrInconsistentData)
		}

		if _, exists := subjectMemo[user.Spec.Subject]; exists {
			continue
		}

		subjectMemo[user.Spec.Subject] = struct{}{}

		patched.Spec.Subjects = append(patched.Spec.Subjects, identityv1.GroupSubject{
			ID:     user.Spec.Subject,
			Issuer: m.identityIssuer,
			Email:  user.Spec.Subject,
		})
	}

	return nil
}
