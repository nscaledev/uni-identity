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

package cerbos

import (
	"time"

	"github.com/spf13/pflag"
)

// Options configure the Cerbos PDP client.
type Options struct {
	// Endpoint is the address of the PDP gRPC listener.  The default
	// matches the sidecar in charts/identity: plaintext gRPC on localhost
	// within the pod's network namespace.
	Endpoint string

	// CheckTimeout bounds every call to the PDP with a per-call context
	// deadline.
	CheckTimeout time.Duration

	// PoliciesConfigMap names the controller-owned policy store ConfigMap
	// (the same expression the policy controller publishes to and the sidecar
	// mounts), read by the PolicyStoreHasher to fingerprint the store for the
	// coarse-decision cache.  Empty disables the hasher, so the cache stays
	// inert (safe default); the chart sets it.
	PoliciesConfigMap string
}

// AddFlags registers the client flags with the flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.Endpoint, "cerbos-endpoint", "localhost:3593", "Address of the Cerbos PDP gRPC listener.")
	f.DurationVar(&o.CheckTimeout, "cerbos-check-timeout", 2*time.Second, "Per-call deadline for Cerbos PDP requests.")
	f.StringVar(&o.PoliciesConfigMap, "cerbos-policies-configmap", "", "Name of the Cerbos policy store ConfigMap, read to key the coarse-decision cache on the policy-store hash (empty disables caching).")
}
