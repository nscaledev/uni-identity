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

	idconstants "github.com/unikorn-cloud/identity/pkg/constants"
)

// TestSrcIssDefaultMatchesMigrationGateSentinel pins the coupling between the
// empty-SrcIss default (srcIssOrUNISentinel) and the sentinel that
// Options.Validate's migration gate checks against (idconstants.UNISentinel).
// If either side changes independently, this test fails and calls attention
// to the other side needing the same change.
func TestSrcIssDefaultMatchesMigrationGateSentinel(t *testing.T) {
	t.Parallel()

	if got := srcIssOrUNISentinel(""); got != idconstants.UNISentinel {
		t.Fatalf("srcIssOrUNISentinel(\"\") = %q, want idconstants.UNISentinel (%q)", got, idconstants.UNISentinel)
	}

	if got := srcIssOrUNISentinel("https://staff.auth0.com"); got != "https://staff.auth0.com" {
		t.Fatalf("srcIssOrUNISentinel must not alter a non-empty srcIss, got %q", got)
	}
}
