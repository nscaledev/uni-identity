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

package allocations_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/allocations"
	"github.com/unikorn-cloud/identity/pkg/handler/common/fixtures"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace = "test-namespace"
	testOrgID     = "test-org"
	testOrgNS     = "test-org-ns"
	testProjectID = "test-project"
	testProjectNS = "test-project-ns"

	allocationResourceKind = "instance" // arbitrary
	oneGigabyte            = 1024 * 1024 * 1024
)

// allocationTestFixture holds common test setup.
type allocationTestFixture struct {
	client            client.Client
	allocationsClient *allocations.Client
	mutex             *sync.Mutex
}

// syncClient returns a SyncClient instance for testing.
func (f *allocationTestFixture) syncClient() *allocations.SyncClient {
	return allocations.NewSync(f.client, testNamespace, f.mutex)
}

// runConcurrent runs fn concurrently n times and returns all errors.
func runConcurrent(n int, fn func(idx int) error) []error {
	errChan := make(chan error, n)

	var wg sync.WaitGroup

	for i := range n {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()
			errChan <- fn(idx)
		}(i)
	}

	wg.Wait()
	close(errChan)

	errors := make([]error, 0, n)
	for err := range errChan {
		errors = append(errors, err)
	}

	return errors
}

// countErrors categorizes errors into successes, quota errors, and other errors.
func countErrors(errors []error) (int, int, int) {
	var successCount, quotaErrorCount, otherErrorCount int

	for _, err := range errors {
		switch {
		case err == nil:
			successCount++
		case containsAny(err.Error(), "quota", "exceeded"):
			quotaErrorCount++
		default:
			otherErrorCount++
		}
	}

	return successCount, quotaErrorCount, otherErrorCount
}

// setupAllocationTestFixture creates a test fixture with all common setup.
func setupAllocationTestFixture(t *testing.T) *allocationTestFixture {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&unikornv1.Organization{}, &unikornv1.Project{}).
		Build()

	ctx := newContext(t)

	// Create organization namespace
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}
	require.NoError(t, c.Create(ctx, testNs))

	for _, quotaKind := range []string{
		"cpu", "memory",
	} {
		quotaMeta := &unikornv1.QuotaMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Name:      quotaKind,
				Namespace: testNamespace,
			},
			Spec: unikornv1.QuotaMetadataSpec{
				DisplayName: quotaKind,
			},
		}
		require.NoError(t, c.Create(ctx, quotaMeta))
	}

	// Create organization namespace
	orgNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testOrgNS,
			Labels: map[string]string{
				constants.KindLabel: constants.KindLabelValueOrganization,
			},
		},
	}
	require.NoError(t, c.Create(ctx, orgNamespace))

	// Create organization
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testOrgID,
		},
		Spec: unikornv1.OrganizationSpec{},
		Status: unikornv1.OrganizationStatus{
			Namespace: testOrgNS,
		},
	}
	require.NoError(t, c.Create(ctx, organization))
	require.NoError(t, c.Status().Update(ctx, organization))

	// Create project
	project := &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      testProjectID,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.ProjectSpec{},
		Status: unikornv1.ProjectStatus{
			Namespace: testProjectNS,
		},
	}
	require.NoError(t, c.Create(ctx, project))
	require.NoError(t, c.Status().Update(ctx, project))

	// Create project namespace
	projectNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testProjectNS,
			Labels: map[string]string{
				constants.KindLabel:         constants.KindLabelValueProject,
				constants.OrganizationLabel: testOrgID,
				constants.ProjectLabel:      testProjectID,
			},
		},
	}
	require.NoError(t, c.Create(ctx, projectNamespace))

	return &allocationTestFixture{
		client:            c,
		allocationsClient: allocations.New(c, testNamespace),
		mutex:             &sync.Mutex{},
	}
}

// newContext creates a context with required authorization and principal info.
func newContext(t *testing.T) context.Context {
	t.Helper()

	return fixtures.HandlerContextFixture(t.Context(), fixtures.WithProject)
}

// createQuota creates a test quota with the specified limits.
func (f *allocationTestFixture) createQuota(t *testing.T, cpuLimit, memoryLimit int64) {
	t.Helper()

	quota := &unikornv1.Quota{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      testOrgID,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.QuotaSpec{
			Quotas: []unikornv1.ResourceQuota{
				{
					Kind:     "cpu",
					Quantity: resource.NewQuantity(cpuLimit, resource.DecimalSI),
				},
				{
					Kind:     "memory",
					Quantity: resource.NewQuantity(memoryLimit, resource.BinarySI),
				},
			},
		},
	}
	require.NoError(t, f.client.Create(newContext(t), quota))
}

// makeAllocationRequest creates a test allocation request.
func makeAllocationRequest(name, resourceID string, cpuCommitted, memoryCommitted int) *openapi.AllocationWrite {
	return &openapi.AllocationWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: name,
		},
		Spec: openapi.AllocationSpec{
			Kind: allocationResourceKind,
			Id:   resourceID,
			Allocations: openapi.ResourceAllocationList{
				{
					Kind:      "cpu",
					Committed: cpuCommitted,
					Reserved:  0,
				},
				{
					Kind:      "memory",
					Committed: memoryCommitted,
					Reserved:  0,
				},
			},
		},
	}
}

// getTotalAllocations sums up all allocations for a given resource kind.
func (f *allocationTestFixture) getTotalAllocations(t *testing.T, resourceKind string) int64 {
	t.Helper()

	var allocationList unikornv1.AllocationList

	require.NoError(t, f.client.List(newContext(t), &allocationList, client.InNamespace(testProjectNS)))

	var total int64

	for _, allocation := range allocationList.Items {
		for _, res := range allocation.Spec.Allocations {
			if res.Kind == resourceKind {
				total += res.Committed.Value()
			}
		}
	}

	return total
}

// TestConcurrentAllocations_SerializedByMutex tests that concurrent allocations
// are properly serialized by the mutex, preventing race conditions.
func TestConcurrentAllocations_SerializedByMutex(t *testing.T) {
	t.Parallel()

	f := setupAllocationTestFixture(t)
	f.createQuota(t, 10, 10*oneGigabyte)

	// Run 20 concurrent allocations, each requesting 1 CPU
	// Only 10 should succeed due to quota limits
	errors := runConcurrent(20, func(idx int) error {
		request := makeAllocationRequest(
			fmt.Sprintf("allocation-%d", idx),
			fmt.Sprintf("cluster-%d", idx),
			1,           // 1 CPU
			oneGigabyte, // 1GB
		)
		_, err := f.syncClient().Create(newContext(t), testOrgID, testProjectID, request)

		return err
	})

	// Count successes and failures
	successCount, quotaErrorCount, otherErrorCount := countErrors(errors)

	// Log unexpected errors
	for _, err := range errors {
		if err != nil && !containsAny(err.Error(), "quota", "exceeded") {
			t.Logf("Unexpected error type: %v", err)
		}
	}

	// Verify results
	assert.Equal(t, 10, successCount, "Should have exactly 10 successful allocations (quota limit)")
	assert.Equal(t, 10, quotaErrorCount, "Should have 10 quota errors")
	assert.Equal(t, 0, otherErrorCount, "Should have no other types of errors")

	// Verify final state - total allocated should equal quota
	totalCPU := f.getTotalAllocations(t, "cpu")
	assert.Equal(t, int64(10), totalCPU, "Total CPU allocations should equal quota limit")

	totalMemory := f.getTotalAllocations(t, "memory")
	assert.Equal(t, int64(10*oneGigabyte), totalMemory, "Total memory allocations should equal quota limit")
}

// TestConcurrentAllocationUpdates_SerializedByMutex tests that concurrent
// updates to allocations are properly serialized.
func TestConcurrentAllocationUpdates_SerializedByMutex(t *testing.T) {
	t.Parallel()

	f := setupAllocationTestFixture(t)
	f.createQuota(t, 20, 20*oneGigabyte)

	// Create an initial allocation with 1 CPU
	initialRequest := makeAllocationRequest(
		"test-allocation",
		"test-cluster-1",
		1,
		oneGigabyte,
	)

	result, err := f.syncClient().Create(newContext(t), testOrgID, testProjectID, initialRequest)

	require.NoError(t, err)

	allocationID := result.Metadata.Id

	// Run 10 concurrent updates, each trying to increase allocation by 1 CPU
	// All should succeed since we have quota of 20
	errors := runConcurrent(10, func(idx int) error {
		updateRequest := makeAllocationRequest(
			"test-allocation",
			"test-cluster-1",
			2+idx, // Increasing CPU request
			oneGigabyte,
		)
		_, err := f.syncClient().Update(newContext(t), testOrgID, testProjectID, allocationID, updateRequest)

		return err
	})

	// Count results
	successCount, _, _ := countErrors(errors)

	for _, err := range errors {
		if err != nil {
			t.Logf("Update error: %v", err)
		}
	}

	// All updates should succeed (serialized access prevents conflicts)
	assert.Equal(t, 10, successCount, "All updates should succeed when serialized")

	// Verify final state is consistent (should have the last successful update)
	totalCPU := f.getTotalAllocations(t, "cpu")
	assert.GreaterOrEqual(t, totalCPU, int64(1), "Should have at least initial allocation")
	assert.LessOrEqual(t, totalCPU, int64(11), "Should not exceed highest update value")
}

// TestAllocationWithinQuota_Succeeds tests that an allocation within quota succeeds.
func TestAllocationWithinQuota_Succeeds(t *testing.T) {
	t.Parallel()

	f := setupAllocationTestFixture(t)
	f.createQuota(t, 10, 10*oneGigabyte)

	request := makeAllocationRequest(
		"test-allocation",
		"test-cluster-1",
		5, // 5 CPUs - within quota
		5*oneGigabyte,
	)

	result, err := f.syncClient().Create(newContext(t), testOrgID, testProjectID, request)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-allocation", result.Metadata.Name)

	// Verify allocation was created
	totalCPU := f.getTotalAllocations(t, "cpu")
	assert.Equal(t, int64(5), totalCPU)
}

// TestAllocationExceedingQuota_Fails tests that an allocation exceeding quota fails.
func TestAllocationExceedingQuota_Fails(t *testing.T) {
	t.Parallel()

	f := setupAllocationTestFixture(t)
	f.createQuota(t, 10, 10*oneGigabyte)

	request := makeAllocationRequest(
		"test-allocation",
		"test-cluster-1",
		15, // 15 CPUs - exceeds quota of 10
		15*oneGigabyte,
	)

	result, err := f.syncClient().Create(newContext(t), testOrgID, testProjectID, request)
	require.Error(t, err, "Should fail when exceeding quota")
	require.True(t, errors.IsForbidden(err))
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "quota", "Error should mention quota")

	// Verify no allocation was created
	totalCPU := f.getTotalAllocations(t, "cpu")
	assert.Equal(t, int64(0), totalCPU)
}

// containsAny checks if a string contains any of the provided substrings.
func containsAny(s string, substrings ...string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}

	return false
}
