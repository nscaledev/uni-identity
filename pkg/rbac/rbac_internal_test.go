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

package rbac

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	idconstants "github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSrcIssDefaultMatchesMigrationGateSentinel pins the coupling between the
// empty-SrcIss default (srcIssOrUNISentinel) and the sentinel used for bare
// admin entries (idconstants.UNISentinel). Subjects with no propagated srcIss
// must land on the sentinel so they match only bare/sentinel admin entries —
// the legacy semantic deliberately reproduced by expandBareAdminSubjects in
// pkg/server. If either side changes independently, this test fails and calls
// attention to the other side needing the same change.
func TestSrcIssDefaultMatchesMigrationGateSentinel(t *testing.T) {
	t.Parallel()

	if got := srcIssOrUNISentinel(""); got != idconstants.UNISentinel {
		t.Fatalf("srcIssOrUNISentinel(\"\") = %q, want idconstants.UNISentinel (%q)", got, idconstants.UNISentinel)
	}

	if got := srcIssOrUNISentinel("https://staff.auth0.com"); got != "https://staff.auth0.com" {
		t.Fatalf("srcIssOrUNISentinel must not alter a non-empty srcIss, got %q", got)
	}
}

// TestPlatformProjectNames pins the ACL builder's core selection: only projects flagged
// Spec.Platform become the hidden set (D16/D21).
func TestPlatformProjectNames(t *testing.T) {
	t.Parallel()

	projects := &unikornv1.ProjectList{
		Items: []unikornv1.Project{
			{ObjectMeta: metav1.ObjectMeta{Name: "p-normal"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "p-platform"}, Spec: unikornv1.ProjectSpec{Platform: true}},
			{ObjectMeta: metav1.ObjectMeta{Name: "p-normal-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "p-platform-2"}, Spec: unikornv1.ProjectSpec{Platform: true}},
		},
	}

	require.ElementsMatch(t, []string{"p-platform", "p-platform-2"}, platformProjectNames(projects))
	require.Empty(t, platformProjectNames(&unikornv1.ProjectList{}))
}

// TestHasPlatformProjectsCapability pins that only an explicit identity:projects:platform Read
// endpoint counts as holding the capability (so the hidden set is populated for everyone else).
func TestHasPlatformProjectsCapability(t *testing.T) {
	t.Parallel()

	held := &openapi.AclEndpoints{
		{Name: "identity:projects:platform", Operations: openapi.AclOperations{openapi.Read}},
	}
	require.True(t, hasPlatformProjectsCapability(held))

	// The ordinary projects grant does NOT confer the platform capability.
	ordinary := &openapi.AclEndpoints{
		{Name: "identity:projects", Operations: openapi.AclOperations{openapi.Read, openapi.Create}},
	}
	require.False(t, hasPlatformProjectsCapability(ordinary))

	// Holding the endpoint at the wrong operation is not enough.
	wrongOp := &openapi.AclEndpoints{
		{Name: "identity:projects:platform", Operations: openapi.AclOperations{openapi.Create}},
	}
	require.False(t, hasPlatformProjectsCapability(wrongOp))

	require.False(t, hasPlatformProjectsCapability(nil))
}
