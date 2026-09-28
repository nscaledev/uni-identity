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

package userdb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/userdb"
)

// TestErrUserInactiveWrapsErrResourceReference pins the compatibility contract:
// existing errors.Is(err, ErrResourceReference) callers must keep matching.
func TestErrUserInactiveWrapsErrResourceReference(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, userdb.ErrUserInactive, userdb.ErrResourceReference)
}
