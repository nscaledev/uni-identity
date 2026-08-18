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

package server

import (
	"crypto/tls"
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
)

// ErrSPIFFESourcesRequired is returned when the mutual TLS listener is asked for but
// there is no Workload API connection to serve it from.
var ErrSPIFFESourcesRequired = errors.New("SPIFFE sources are required by --spiffe-tls-listen-address")

// SPIFFEServerTLSConfig returns the TLS configuration for the mutual TLS listener:
// our own X509-SVID as the server certificate, and any peer in the trust domain
// accepted at the handshake.
//
// Authorization is deliberately not narrowed here.  Which SPIFFE IDs may act as
// which system account is decided by --system-account-roles-ids, and keeping the
// handshake to "authenticated member of the trust domain" leaves that the single
// place authority is granted.
//
// Note what HookMTLSServerConfig sets: ClientAuth is RequireAnyClientCert, not
// RequireAndVerifyClientCert, because SPIFFE verification runs against a rotating
// bundle in VerifyPeerCertificate rather than against ClientCAs.  A certificate is
// still required and the callback still runs on every handshake, but Go does not
// build the chain, so r.TLS.VerifiedChains is EMPTY on a fully verified peer.
// Anything downstream must key off r.TLS.PeerCertificates.  See go-spiffe
// spiffetls/tlsconfig/config.go:123-127.
func SPIFFEServerTLSConfig(sources coreclient.Sources) *tls.Config {
	return tlsconfig.MTLSServerConfig(sources, sources, tlsconfig.AuthorizeAny())
}
