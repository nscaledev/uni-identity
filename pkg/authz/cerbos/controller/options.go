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

package controller

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"
)

// ErrOptions is returned for invalid static configuration.
var ErrOptions = errors.New("options error")

// Options configure the policy controller.
type Options struct {
	// ConfigMapName is the name of the policy store ConfigMap the
	// controller owns, in the controller's --namespace.  Required: the
	// chart passes the same expression the cerbos sidecar's policy volume
	// references, and publishing to a default name that drifted from the
	// volume would be a silent authorization outage.
	ConfigMapName string

	// CerbosBinary is the path of the cerbos binary exec'd as the compile
	// gate.  The default matches where the controller image vendors the
	// pinned binary (docker/unikorn-policy-controller/Dockerfile).
	CerbosBinary string
}

// AddFlags registers the controller flags with the flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.ConfigMapName, "cerbos-policies-configmap", "", "Name of the Cerbos policy store ConfigMap to publish (required).")
	f.StringVar(&o.CerbosBinary, "cerbos-binary", "/usr/local/bin/cerbos", "Path of the cerbos binary used as the compile gate.")
}

// Validate rejects unusable static configuration; the manager fails fast on
// error rather than reconciling into the void.
func (o *Options) Validate() error {
	if o.ConfigMapName == "" {
		return fmt.Errorf("%w: --cerbos-policies-configmap is required", ErrOptions)
	}

	if o.CerbosBinary == "" {
		return fmt.Errorf("%w: --cerbos-binary must not be empty", ErrOptions)
	}

	return nil
}
