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
	"io"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/spf13/pflag"

	unikorncorev1 "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrInconsistentData    = errors.New("inconsistent data")
	ErrInvalidConcurrency  = errors.New("concurrency must be greater than 0")
	ErrEmptyIdentityIssuer = errors.New("empty identity issuer")
)

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
	return fmt.Sprintf("%d/%d groups failed during migration, please check the output for details", e.Failed, e.Total)
}

type Options struct {
	outputFilePath string
	dryRun         bool

	kubeConfigPath string
	kubeContext    string

	concurrency    int
	identityIssuer string
}

func (o *Options) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.outputFilePath, "file", "group-subject-migration-results.json", "Path to the output file where the migration results will be stored")
	fs.BoolVar(&o.dryRun, "dry-run", false, "If true, the migration will not actually patch any groups")

	fs.StringVar(&o.kubeConfigPath, "kubeconfig", "", "Path to the kubeconfig file to use for connecting to the Kubernetes cluster")
	fs.StringVar(&o.kubeContext, "context", "", "The name of the kubeconfig context to use")

	fs.IntVar(&o.concurrency, "concurrency", 10, "Number of concurrent workers to run for the migration")
	fs.StringVar(&o.identityIssuer, "identity-issuer", "", "The OIDC issuer URL of the uni-identity provider")
}

func main() {
	var options Options

	options.BindFlags(pflag.CommandLine)

	pflag.Parse()

	if err := run(options); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(options Options) error {
	kubeClient, err := createKubernetesClient(options.kubeConfigPath, options.kubeContext, unikorncorev1.AddToScheme, identityv1.AddToScheme)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	manager, err := NewManager(options.concurrency, options.identityIssuer, kubeClient)
	if err != nil {
		return fmt.Errorf("failed to create migration manager: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)

	go func() {
		<-stop
		cancel()
	}()

	if err = manager.Run(ctx, options.outputFilePath, options.dryRun); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

func createKubernetesClient(kubeConfigPath, kubeContext string, typeRegistries ...func(*runtime.Scheme) error) (client.Client, error) {
	kubeScheme := runtime.NewScheme()
	for _, typeRegistry := range typeRegistries {
		if err := typeRegistry(kubeScheme); err != nil {
			return nil, err
		}
	}

	kubeConfigLoader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfigPath},
		&clientcmd.ConfigOverrides{CurrentContext: kubeContext},
	)

	kubeConfig, err := kubeConfigLoader.ClientConfig()
	if err != nil {
		return nil, err
	}

	kubeClient, err := client.New(kubeConfig, client.Options{Scheme: kubeScheme})
	if err != nil {
		return nil, err
	}

	return kubeClient, nil
}

type Result struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Success   bool   `json:"success"`
	//nolint:tagliatelle
	ErrorMessage *string `json:"error_message,omitempty"`
}

type ResultsWriter interface {
	Write(results []Result) error
	Close() error
}

type JSONResultsWriter struct {
	w io.WriteCloser
}

func NewJSONResultsWriter(w io.WriteCloser) *JSONResultsWriter {
	return &JSONResultsWriter{w: w}
}

func (w *JSONResultsWriter) Write(results []Result) error {
	encoder := json.NewEncoder(w.w)
	encoder.SetIndent("", "\t")
	encoder.SetEscapeHTML(false)

	return encoder.Encode(results)
}

func (w *JSONResultsWriter) Close() error {
	return w.w.Close()
}

// DryRunResultsWriter writes migration results to stderr in dry-run mode.
// Only failures are reported. Groups that would be successfully migrated are silently skipped.
type DryRunResultsWriter struct{}

func NewDryRunResultsWriter() DryRunResultsWriter {
	return DryRunResultsWriter{}
}

func (w DryRunResultsWriter) Write(results []Result) error {
	for i := range results {
		result := &results[i]
		if result.Success {
			continue
		}

		message := "unknown error"
		if result.ErrorMessage != nil {
			message = *result.ErrorMessage
		}

		fmt.Fprintf(os.Stderr, "migration failed for group %q in namespace %q: %s\n", result.Name, result.Namespace, message)
	}

	return nil
}

func (w DryRunResultsWriter) Close() error {
	return nil
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
}

func NewManager(concurrency int, identityIssuer string, kubeClient client.Client) (*Manager, error) {
	if concurrency <= 0 {
		return nil, ErrInvalidConcurrency
	}

	if identityIssuer == "" {
		return nil, ErrEmptyIdentityIssuer
	}

	manager := &Manager{
		concurrency:    concurrency,
		identityIssuer: identityIssuer,
		kubeClient:     kubeClient,
	}

	return manager, nil
}

func (m *Manager) Run(ctx context.Context, outputFilePath string, dryRun bool) error {
	previousResults, err := m.readPreviousResults(outputFilePath)
	if err != nil {
		return err
	}

	resultsWriter, err := m.prepareOutput(outputFilePath, dryRun)
	if err != nil {
		return err
	}
	defer resultsWriter.Close()

	resultMemo := make(map[string]*Result)

	for i := range previousResults {
		result := &previousResults[i]
		key := namespacedID(result.Namespace, result.Name)
		resultMemo[key] = result
	}

	groups, cc, err := m.loadResources(ctx)
	if err != nil {
		return err
	}

	groups = slices.DeleteFunc(groups, func(group identityv1.Group) bool {
		key := namespacedID(group.Namespace, group.Name)

		result, ok := resultMemo[key]

		return ok && result.Success
	})

	results := m.dispatch(ctx, groups, cc, dryRun)

	mergedResults := m.mergeResults(results, resultMemo)

	if err = resultsWriter.Write(mergedResults); err != nil {
		return fmt.Errorf("failed to write migration results: %w", err)
	}

	return m.checkFailures(mergedResults)
}

func (m *Manager) readPreviousResults(path string) ([]Result, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Result{}, nil
		}

		return nil, fmt.Errorf("failed to open previous results file: %w", err)
	}
	defer file.Close()

	var results []Result
	if err = json.NewDecoder(file).Decode(&results); err != nil {
		return nil, fmt.Errorf("failed to decode previous results file: %w", err)
	}

	return results, nil
}

func (m *Manager) prepareOutput(path string, dryRun bool) (ResultsWriter, error) {
	if dryRun {
		return NewDryRunResultsWriter(), nil
	}

	if err := os.Rename(path, fmt.Sprintf("%s.backup", path)); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to backup previous results file: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	return NewJSONResultsWriter(file), nil
}

func (m *Manager) loadResources(ctx context.Context) ([]identityv1.Group, *Cache, error) {
	var groupList identityv1.GroupList
	if err := m.kubeClient.List(ctx, &groupList); err != nil {
		return nil, nil, fmt.Errorf("failed to list groups: %w", err)
	}

	var organizationUserList identityv1.OrganizationUserList
	if err := m.kubeClient.List(ctx, &organizationUserList); err != nil {
		return nil, nil, fmt.Errorf("failed to list organization users: %w", err)
	}

	var userList identityv1.UserList
	if err := m.kubeClient.List(ctx, &userList); err != nil {
		return nil, nil, fmt.Errorf("failed to list users: %w", err)
	}

	cc, err := m.buildInMemoryCache(organizationUserList.Items, userList.Items)
	if err != nil {
		return nil, nil, err
	}

	return groupList.Items, cc, nil
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

		userID, ok := organizationUser.Labels[coreconstants.UserLabel]
		if !ok {
			return nil, fmt.Errorf("organization user %q in %q has no user label: %w", organizationUser.Name, organizationUser.Namespace, ErrInconsistentData)
		}

		namespacedUserID := namespacedID(organizationUser.Namespace, userID)

		if _, ok = cc.OrganizationUserByNamespacedUserID[namespacedUserID]; ok {
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

func (m *Manager) dispatch(ctx context.Context, groups []identityv1.Group, cc *Cache, dryRun bool) []Result {
	var (
		semaphore = make(chan struct{}, m.concurrency)
		completed = make(chan Result)
		results   = make([]Result, 0, len(groups))
		total     = len(groups)
	)

	go m.spawnWorkers(ctx, groups, cc, dryRun, semaphore, completed)

	for processed := 1; processed <= total; processed++ {
		results = append(results, <-completed)

		<-semaphore

		fmt.Fprintf(os.Stdout, "progress: %d/%d groups processed\n", processed, total)
	}

	return results
}

func (m *Manager) spawnWorkers(ctx context.Context, groups []identityv1.Group, cc *Cache, dryRun bool, semaphore chan<- struct{}, completed chan<- Result) {
	for i := range groups {
		semaphore <- struct{}{}

		group := &groups[i]

		select {
		case <-ctx.Done():
			errorMessage := ctx.Err().Error()

			completed <- Result{
				Namespace:    group.Namespace,
				Name:         group.Name,
				Success:      false,
				ErrorMessage: &errorMessage,
			}

			continue
		default:
		}

		go func(group *identityv1.Group) {
			result := Result{
				Namespace: group.Namespace,
				Name:      group.Name,
				Success:   true,
			}

			if err := m.migrate(ctx, group, cc, dryRun); err != nil {
				errorMessage := err.Error()

				result.Success = false
				result.ErrorMessage = &errorMessage
			}

			completed <- result
		}(group)
	}
}

func (m *Manager) migrate(ctx context.Context, group *identityv1.Group, cc *Cache, dryRun bool) error {
	patched := group.DeepCopy()

	hasPatched := m.patchEmptyIssuerSubjects(patched)

	if err := m.computeMissingUserIDs(group, patched, cc); err != nil {
		return err
	}

	if err := m.computeMissingSubjects(group, patched, cc); err != nil {
		return err
	}

	// Skip the patch if nothing changed: no subject issuers were backfilled and
	// neither the UserIDs nor Subjects slices grew. Length comparison is sufficient
	// because the compute functions only append. They never remove or reorder entries.
	if !hasPatched && len(group.Spec.UserIDs) == len(patched.Spec.UserIDs) && len(group.Spec.Subjects) == len(patched.Spec.Subjects) {
		return nil
	}

	if !dryRun {
		if err := m.kubeClient.Patch(ctx, patched, client.MergeFromWithOptions(group, client.MergeFromWithOptimisticLock{})); err != nil {
			return fmt.Errorf("failed to patch group %q in namespace %q: %w", group.Name, group.Namespace, err)
		}
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

func (m *Manager) computeMissingUserIDs(original, patched *identityv1.Group, cc *Cache) error {
	userIDMemo := make(map[string]struct{}, len(original.Spec.UserIDs))
	for _, userID := range original.Spec.UserIDs {
		userIDMemo[userID] = struct{}{}
	}

	for i := range original.Spec.Subjects {
		subject := &original.Spec.Subjects[i]

		user, ok := cc.UserBySubject[subject.Email]
		if !ok {
			return fmt.Errorf("user not found for subject %q: %w", subject.Email, ErrInconsistentData)
		}

		namespacedUserID := namespacedID(original.Namespace, user.Name)

		organizationUser, ok := cc.OrganizationUserByNamespacedUserID[namespacedUserID]
		if !ok {
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

func (m *Manager) computeMissingSubjects(original, patched *identityv1.Group, cc *Cache) error {
	subjectMemo := make(map[string]struct{}, len(original.Spec.Subjects))
	for _, subject := range original.Spec.Subjects {
		subjectMemo[subject.Email] = struct{}{}
	}

	for _, organizationUserID := range original.Spec.UserIDs {
		organizationUser, ok := cc.OrganizationUserByID[organizationUserID]
		if !ok {
			return fmt.Errorf("organization user %q not found: %w", organizationUserID, ErrInconsistentData)
		}

		userID, ok := organizationUser.Labels[coreconstants.UserLabel]
		if !ok {
			return fmt.Errorf("organization user %q has no user label: %w", organizationUserID, ErrInconsistentData)
		}

		user, ok := cc.UserByID[userID]
		if !ok {
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

func (m *Manager) mergeResults(results []Result, resultMemo map[string]*Result) []Result {
	for i := range results {
		result := &results[i]
		key := namespacedID(result.Namespace, result.Name)
		resultMemo[key] = result
	}

	mergedResults := make([]Result, 0, len(resultMemo))
	for _, result := range resultMemo {
		mergedResults = append(mergedResults, *result)
	}

	return mergedResults
}

func (m *Manager) checkFailures(results []Result) error {
	var failed int

	for i := range results {
		result := &results[i]
		if !result.Success {
			failed++
		}
	}

	if failed > 0 {
		return NewGroupsMigrationError(failed, len(results))
	}

	return nil
}
