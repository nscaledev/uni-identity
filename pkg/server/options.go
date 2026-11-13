/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

package server

import (
	"time"

	"github.com/spf13/pflag"
)

// Options are server options that core's ServerOptions does not cover.
type Options struct {
	// IdleTimeout is how long a keep-alive connection may wait for its next
	// request. It must exceed the upstream keep-alive timeout of any proxy in
	// front (ingress-nginx's is 60s), so the proxy closes idle connections
	// first. Otherwise the proxy can send a request on a connection just as
	// the server closes it, and the request is reset.
	IdleTimeout time.Duration
}

// AddFlags registers the options' flags.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.IdleTimeout, "server-idle-timeout", 120*time.Second, "How long to keep an idle keep-alive connection open. Must exceed the upstream keep-alive timeout of any proxy in front.")
}
