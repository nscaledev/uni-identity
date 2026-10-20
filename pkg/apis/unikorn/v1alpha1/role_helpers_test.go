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

package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestChartRoleIDMatchesChart(t *testing.T) {
	t.Parallel()

	for name, id := range map[string]string{
		"administrator":      "f194d170-6ed1-4408-85e0-2d672777019f",
		"administrator-base": "f43fa216-5063-4a27-8033-fc5b59808eb4",
		"reader-base":        "f506352f-1c8a-4c45-82f7-96e59e7f135a",
	} {
		require.Equalf(t, id, unikornv1.ChartRoleID(name), "%s", name)
	}
}

func role(id, name string, protected bool) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: id, Labels: map[string]string{coreconstants.NameLabel: name}},
		Spec:       unikornv1.RoleSpec{Protected: protected},
	}
}

func TestMayRefOwnBase(t *testing.T) {
	t.Parallel()

	admin := role(unikornv1.ChartRoleID("administrator"), "administrator", false)

	require.True(t, admin.MayRef(role(unikornv1.ChartRoleID("administrator-base"), "administrator-base", true)))
	require.True(t, admin.MayRef(role("f0000000-0000-4000-8000-000000000001", "anything", false)))
}

func TestMayRefRefusesSpoofedBase(t *testing.T) {
	t.Parallel()

	admin := role(unikornv1.ChartRoleID("administrator"), "administrator", false)

	require.False(t, admin.MayRef(role(unikornv1.ChartRoleID("system-account"), "administrator-base", true)))
	require.False(t, admin.MayRef(role("f0000000-0000-4000-8000-000000000001", "administrator-base", true)))

	require.False(t, admin.MayRef(role(unikornv1.ChartRoleID("administrator-base"), "system-account", true)))
}

func TestMayRefRenameLocksOut(t *testing.T) {
	t.Parallel()

	renamed := role(unikornv1.ChartRoleID("administrator"), "admin", false)

	require.False(t, renamed.MayRef(role(unikornv1.ChartRoleID("administrator-base"), "administrator-base", true)))
	require.False(t, renamed.MayRef(role(unikornv1.ChartRoleID("administrator-base"), "admin-base", true)))
}
