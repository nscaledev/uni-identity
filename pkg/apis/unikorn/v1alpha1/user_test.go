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

	"github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

type backfillOutput struct {
	Namespace string            `json:"namespace"`
	Label     string            `json:"label"`
	IDs       map[string]string `json:"ids"`
}

// TestBackfillScriptMatchesGo guards against drift between the canonical Go
// deterministic-ID algorithm (with its namespace and label constants) and the
// Python re-implementation in hack/identity-user-subject-id-backfill.py. The Go
// side owns the algorithm; the script must reproduce it exactly or the backfill
// would write labels that the server never looks up.
func TestBackfillScriptMatchesGo(t *testing.T) {
	t.Parallel()

	subjects := []string{
		"https://accounts.google.com#1234567890",
		"alice@example.com",
		"bob@example.org",
		"github|42",
		"okta:00u1a2b3c4d5e6f7g8h9",
		"keycloak-realm:service-account-robot",
	}

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available; skipping backfill drift guard")
	}

	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	script := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "hack", "identity-user-subject-id-backfill.py")

	// Load the script as a module (its __main__ guard keeps kubectl out of the
	// way) and emit its constants and identifier() outputs as JSON.
	const driver = `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("backfill", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(json.dumps({
    "namespace": str(mod.NAMESPACE),
    "label": mod.LABEL,
    "ids": {s: mod.identifier(s) for s in sys.argv[2:]},
}))
`

	args := append([]string{"-c", driver, script}, subjects...)

	raw, err := exec.Command(python, args...).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("python driver failed: %v\n%s", err, exit.Stderr)
		}

		require.NoError(t, err)
	}

	var got backfillOutput

	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, v1alpha1.GlobalUserNamespace().String(), got.Namespace, "backfill NAMESPACE drifted from GlobalUserNamespace")
	require.Equal(t, v1alpha1.UserSubjectIDLabel, got.Label, "backfill LABEL drifted from UserSubjectIDLabel")

	for _, subject := range subjects {
		require.Equal(t, v1alpha1.GlobalUserName(subject), got.IDs[subject], "backfill identifier drifted for subject %q", subject)
	}
}
