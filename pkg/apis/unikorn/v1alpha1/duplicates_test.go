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
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDuplicateRecordCheck runs hack/identity-duplicate-records-check.py over
// records shaped like the API server's, and checks it groups Users by folded
// subject, OrganizationUsers by organization and user, and Quotas by
// organization, reporting only the groups with more than one record.
func TestDuplicateRecordCheck(t *testing.T) {
	t.Parallel()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available; skipping duplicate check guard")
	}

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	script := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "hack", "identity-duplicate-records-check.py")

	const driver = `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("check", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
def record(namespace, name, labels=None, subject=None):
    item = {"metadata": {"namespace": namespace, "name": name, "labels": labels or {}}}
    if subject is not None:
        item["spec"] = {"subject": subject}
    return item
users = [
    record("identity", "u-legacy", subject="Bob@Example.com"),
    record("identity", "u-canonical", subject="bob@example.com"),
    record("identity", "u-alice", subject="alice@example.com"),
]
organization_users = [
    record("org-a", "ou-1", {"unikorn-cloud.org/organization": "org-a", "unikorn-cloud.org/user": "u-canonical"}),
    record("org-a", "ou-2", {"unikorn-cloud.org/organization": "org-a", "unikorn-cloud.org/user": "u-canonical"}),
    record("org-a", "ou-3", {"unikorn-cloud.org/organization": "org-a", "unikorn-cloud.org/user": "u-alice"}),
    record("org-b", "ou-4", {}),
]
quotas = [
    record("org-a", "legacy", {"unikorn-cloud.org/organization": "org-a"}),
    record("org-a", "quota", {"unikorn-cloud.org/organization": "org-a"}),
    record("org-b", "quota", {"unikorn-cloud.org/organization": "org-b"}),
]
print(json.dumps(mod.find_duplicates(users, organization_users, quotas, mod.load_normalize())))
`

	raw, err := exec.Command(python, "-c", driver, script).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("python driver failed: %v\n%s", err, exit.Stderr)
		}

		require.NoError(t, err)
	}

	var got map[string]map[string][]string

	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, map[string]map[string][]string{
		"users":             {"bob@example.com": {"identity/u-canonical", "identity/u-legacy"}},
		"organizationusers": {"org-a/u-canonical": {"org-a/ou-1", "org-a/ou-2"}},
		"quotas":            {"org-a": {"org-a/legacy", "org-a/quota"}},
	}, got)
}
