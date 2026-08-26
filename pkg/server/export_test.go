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

// This file exists so the test-only export below never ships: the "_test.go"
// suffix compiles it only under `go test`, keeping the seam visible to the
// external server_test package while it stays out of the production binary.
package server

import "github.com/go-chi/chi/v5"

// MountAPIForTest mounts the profile's routes over a nil handler so a test
// can inspect the served route set.  Exported for tests only: the route set
// is a security boundary, so it is pinned by a test that inspects the mux
// rather than by an integration probe, which cannot distinguish an absent
// route from a refused one. It must never reach production: it mounts real
// routes over a nil ServerInterface with no middlewares, so a real caller
// would get a router whose first request panics on a nil dereference,
// unlogged by the audit middleware.
func MountAPIForTest(profile *APIProfile, router chi.Router) {
	mountAPI(*profile, nil, router, nil, nil)
}
