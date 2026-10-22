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

package audit

import (
	"time"

	"github.com/spf13/pflag"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
)

const (
	// SigningKeySecretID is the key in the signing secret holding the key id
	// the collector knows this key by.  It MUST live in the same secret as the
	// key: rotation is then one atomic write, and the two cannot drift.  See
	// the README's rotation section.
	SigningKeySecretID = "id"

	// SigningKeySecretKey is the key in the signing secret holding the PEM
	// encoded PKCS#8 Ed25519 private key.
	SigningKeySecretKey = "key"

	// defaultTimeout bounds one delivery.  The response has already been written
	// when a sink runs, so this does not delay the client; it bounds how long a
	// handler goroutine is held by an unresponsive collector.
	defaultTimeout = 5 * time.Second
)

// Options configures delivery of audit records to an external collector.
type Options struct {
	// server is the collector endpoint and its CA.
	server *coreclient.HTTPOptions

	// client is the certificate we present to the collector.  It is prefixed,
	// and so distinct from the mTLS identity used between unikorn services,
	// because the collector issues it from its own authority.
	client *coreclient.HTTPClientOptions

	// signingKeyNamespace and signingKeyName locate the Ed25519 signing key.
	signingKeyNamespace string
	signingKeyName      string

	// timeout bounds a single delivery.
	timeout time.Duration
}

func NewOptions() *Options {
	return &Options{
		server: coreclient.NewHTTPOptions("audit"),
		client: coreclient.NewHTTPClientOptions("audit"),
	}
}

// AddFlags adds the options to the CLI flags.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	o.server.AddFlags(f)
	o.client.AddFlags(f)

	f.StringVar(&o.signingKeyNamespace, "audit-signing-key-secret-namespace", "", "Audit signing key secret namespace.")
	f.StringVar(&o.signingKeyName, "audit-signing-key-secret-name", "", "Audit signing key secret name, holding the Ed25519 private key and its key id.")
	f.DurationVar(&o.timeout, "audit-timeout", defaultTimeout, "How long to allow for a single audit record delivery.")
}

// Enabled reports whether a collector is configured.  The host is the single
// switch: without it no sink is built and no secrets are read, so an unset
// audit configuration costs nothing at startup.
func (o *Options) Enabled() bool {
	return o.server.Host() != ""
}
