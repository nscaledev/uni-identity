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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/unikorn-cloud/identity/pkg/readiness"
	"github.com/unikorn-cloud/identity/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

var errRelayerID = errors.New("invalid SPIFFE relayer ID")

// spiffeSource gives the SVID of identity and the trust bundles of the SPIFFE
// Workload API.  A test can give static sources.
type spiffeSource interface {
	x509svid.Source
	x509bundle.Source
	Close() error
}

// SPIFFEOptions configure a second listener on the API server.  It terminates TLS
// with the X.509-SVID of identity and verifies the X.509-SVID of each client.
type SPIFFEOptions struct {
	// ListenAddress turns the listener on when it is not empty.
	ListenAddress string

	relayerIDs   []string
	startTimeout time.Duration

	// SetupSPIFFE sets these when the listener is on.
	source      spiffeSource
	trustDomain spiffeid.TrustDomain
	relayers    []string
}

func (o *SPIFFEOptions) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.ListenAddress, "spiffe-tls-listen-address", "", "Address of the TLS listener that verifies the X.509-SVID of each client, for example :6082. An empty value turns the listener off.")
	f.StringSliceVar(&o.relayerIDs, "spiffe-relayer-ids", nil, "SPIFFE IDs of the verified peers that can propagate the client certificate of another caller. Each ID must be in the trust domain of identity and in --system-account-roles-ids.")
	f.DurationVar(&o.startTimeout, "spiffe-start-timeout", 30*time.Second, "Maximum time to wait at start for the first X.509-SVID from the SPIFFE Workload API.")
}

// SetupSPIFFE opens the SPIFFE Workload API source when the listener is on.  It
// waits at most the start timeout for the first SVID.  Then it checks the relayer
// IDs against the trust domain of that SVID and the system accounts.  The socket
// address comes from SPIFFE_ENDPOINT_SOCKET.
func (s *Server) SetupSPIFFE(ctx context.Context) error {
	o := &s.SPIFFEOptions

	if o.ListenAddress == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, o.startTimeout)
	defer cancel()

	logger := log.Log.WithName("spiffe")

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithLogger(spiffeLogger{logger: logger})))
	if err != nil {
		return err
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		return errors.Join(err, source.Close())
	}

	logger.Info("SVID source open", "spiffeID", svid.ID.String(), "notAfter", svid.Certificates[0].NotAfter)

	trustDomain := svid.ID.TrustDomain()

	relayers, err := validateRelayerIDs(o.relayerIDs, trustDomain, s.RBACOptions.SystemAccountRoleIDs)
	if err != nil {
		return errors.Join(err, source.Close())
	}

	o.source = source
	o.trustDomain = trustDomain
	o.relayers = relayers

	return nil
}

// Close closes the SVID source, if one is open.
func (o *SPIFFEOptions) Close() error {
	if o.source == nil {
		return nil
	}

	return o.source.Close()
}

// validateRelayerIDs checks that each relayer ID is a SPIFFE ID in the trust
// domain of identity, and a registered system account.
func validateRelayerIDs(ids []string, trustDomain spiffeid.TrustDomain, registered map[string]string) ([]string, error) {
	for _, raw := range ids {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w %q: %w", errRelayerID, raw, err)
		}

		if !id.MemberOf(trustDomain) {
			return nil, fmt.Errorf("%w %q: not in the trust domain %q", errRelayerID, raw, trustDomain)
		}

		if _, ok := registered[raw]; !ok {
			return nil, fmt.Errorf("%w %q: not a registered system account", errRelayerID, raw)
		}
	}

	return ids, nil
}

// serverTLSConfig presents the SVID of identity, and verifies the SVID of each
// client against the trust bundle.  Any SVID of the trust domain completes the
// handshake, and the system accounts then decide what each subject can do.  Go
// does not verify the peer again when it resumes a session, so session tickets
// are off.
func serverTLSConfig(svid x509svid.Source, bundle x509bundle.Source, trustDomain spiffeid.TrustDomain) *tls.Config {
	config := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}

	tlsconfig.HookMTLSServerConfig(config, svid, bundle, tlsconfig.AuthorizeMemberOf(trustDomain))

	return config
}

// configureServer prepares the server to serve the listener with ServeTLS.  It
// does nothing when the listener is off.
func (o *SPIFFEOptions) configureServer(server *http.Server, ready *readiness.Checker) {
	if o.ListenAddress == "" {
		return
	}

	// NextProtos alone does not turn HTTP/2 off.  With HTTP/1 only, the
	// Connection: close of verifiedPeerHeaders ends the connection.
	var protocols http.Protocols

	protocols.SetHTTP1(true)

	server.TLSConfig = serverTLSConfig(o.source, o.source, o.trustDomain)
	server.Protocols = &protocols
	server.ErrorLog = stdlog.New(serverLogWriter{logger: log.Log.WithName("http-server")}, "", 0)

	ready.Require(readiness.SVIDAvailable(o.source))
}

// verifiedPeerHeaders acts on a request with a verified TLS peer.  It deletes the
// client certificate headers that the ingress sets, so that no later step reads
// them or writes them to the log.  When the peer certificate is past half of its
// lifetime, it adds Connection: close to the response, so that the client opens a
// new connection with its renewed SVID.  A verified SPIFFE peer has no
// VerifiedChains, so each check of a peer uses util.HasVerifiedPeer.
func verifiedPeerHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if util.HasVerifiedPeer(r) {
			r.Header.Del("Ssl-Client-Cert")
			r.Header.Del("Ssl-Client-Verify")

			leaf := r.TLS.PeerCertificates[0]

			if time.Now().After(leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)) {
				w.Header().Set("Connection", "close")
			}
		}

		next.ServeHTTP(w, r)
	})
}

// serverLogWriter sends each line of the error log of the server, for example a
// TLS handshake error, to the structured log.
type serverLogWriter struct {
	logger logr.Logger
}

func (w serverLogWriter) Write(p []byte) (int, error) {
	w.logger.Info("http server error", "message", strings.TrimSuffix(string(p), "\n"))

	return len(p), nil
}

// spiffeLogger sends the log of go-spiffe to the structured log.  Debug and
// warning lines become info lines, so the log shows when the Workload API watch
// starts.
type spiffeLogger struct {
	logger logr.Logger
}

func (l spiffeLogger) Debugf(format string, args ...any) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l spiffeLogger) Infof(format string, args ...any) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l spiffeLogger) Warnf(format string, args ...any) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l spiffeLogger) Errorf(format string, args ...any) {
	l.logger.Error(nil, fmt.Sprintf(format, args...))
}
