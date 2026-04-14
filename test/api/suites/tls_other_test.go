//go:build integration && !darwin

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

package suites

// patchTLSTransport is a no-op on non-darwin platforms.
// Linux respects SSL_CERT_FILE via the system cert pool, so no explicit
// patching of http.DefaultTransport is needed.
func patchTLSTransport() {}
