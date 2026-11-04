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
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/go-logr/logr/funcr"
	"github.com/spf13/pflag"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/constants"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/readiness"
	"github.com/unikorn-cloud/identity/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TestExpandBareAdminSubjects covers the legacy-compatibility mirroring of
// bare (UNI-sentinel) platform-admin entries onto the deprecated
// auth0-exchange issuer. The runtime match compares issuers exactly, so the
// mirror copies the flag issuer verbatim.
func TestExpandBareAdminSubjects(t *testing.T) {
	t.Parallel()

	const legacyIssuer = "https://legacy.auth0.com/"

	bare := rbac.PlatformAdministratorSubject{Issuer: constants.UNISentinel, Subject: "admin@nscale.com"}
	mirrored := rbac.PlatformAdministratorSubject{Issuer: legacyIssuer, Subject: "admin@nscale.com"}
	qualified := rbac.PlatformAdministratorSubject{Issuer: "https://staff.auth0.com/", Subject: "staff@nscale.com"}

	cases := []struct {
		name         string
		subjects     []rbac.PlatformAdministratorSubject
		legacyIssuer string
		want         []rbac.PlatformAdministratorSubject
	}{
		{
			// The bare entry is retained (UNI-login admins keep matching the
			// sentinel) and mirrored onto the legacy issuer (Auth0-exchange
			// admins keep matching), reproducing main's issuer-blind match.
			name:         "bare entry mirrored and sentinel retained",
			subjects:     []rbac.PlatformAdministratorSubject{bare},
			legacyIssuer: legacyIssuer,
			want:         []rbac.PlatformAdministratorSubject{bare, mirrored},
		},
		{
			name:         "issuer-qualified entries are not duplicated",
			subjects:     []rbac.PlatformAdministratorSubject{qualified},
			legacyIssuer: legacyIssuer,
			want:         []rbac.PlatformAdministratorSubject{qualified},
		},
		{
			// The dominant real deployment: no auth0-exchange flags at all.
			// Expansion no-ops and the admin is preserved via the sentinel
			// entry — behaviour identical to main.
			name:         "no auth0-exchange flags set",
			subjects:     []rbac.PlatformAdministratorSubject{bare},
			legacyIssuer: "",
			want:         []rbac.PlatformAdministratorSubject{bare},
		},
		{
			name:         "sentinel-valued legacy issuer is a no-op",
			subjects:     []rbac.PlatformAdministratorSubject{bare},
			legacyIssuer: constants.UNISentinel,
			want:         []rbac.PlatformAdministratorSubject{bare},
		},
		{
			// An operator who already supplied both forms gets a duplicate
			// mirrored entry. That is deliberate: duplicates are harmless
			// (the runtime match short-circuits on first hit) and the
			// expansion does not dedupe.
			name:         "pre-existing qualified duplicate is not deduped",
			subjects:     []rbac.PlatformAdministratorSubject{bare, mirrored},
			legacyIssuer: legacyIssuer,
			want:         []rbac.PlatformAdministratorSubject{bare, mirrored, mirrored},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := expandBareAdminSubjects(tc.subjects, tc.legacyIssuer); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expandBareAdminSubjects(%v, %q) = %v, want %v", tc.subjects, tc.legacyIssuer, got, tc.want)
			}
		})
	}
}

// TestDefaultRequestTimeoutFitsOrganizationLease fails if the default server
// timeouts and the organization Lease timings stop fitting together: a
// takeover and critical section must end before the request deadline, and
// Lease cleanup and the response must fit before the write deadline.
func TestDefaultRequestTimeoutFitsOrganizationLease(t *testing.T) {
	t.Parallel()

	var serverOptions options.ServerOptions

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	serverOptions.AddFlags(flags)
	require.NoError(t, flags.Parse(nil))
	require.Positive(t, serverOptions.WriteTimeout)

	deadline, err := requestTimeout(&serverOptions)
	require.NoError(t, err)
	require.GreaterOrEqual(t, deadline, handlercommon.OrganizationLeaseTakeoverBudget)
	require.LessOrEqual(t, deadline+handlercommon.OrganizationLeaseReleaseTimeout+responseWriteReserve, serverOptions.WriteTimeout)
}

func TestRequestTimeout(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		requestTimeout time.Duration
		writeTimeout   time.Duration
		want           time.Duration
		wantErr        bool
	}{
		{name: "no timeouts installs no deadline"},
		{name: "write timeout leaves room for release and response", requestTimeout: 30 * time.Second, writeTimeout: 10 * time.Second, want: 8 * time.Second},
		{name: "shorter request timeout wins", requestTimeout: 6 * time.Second, writeTimeout: 10 * time.Second, want: 6 * time.Second},
		{name: "write timeout alone", writeTimeout: 10 * time.Second, want: 8 * time.Second},
		{name: "request timeout alone", requestTimeout: 30 * time.Second, want: 30 * time.Second},
		{name: "write timeout too short for takeover", requestTimeout: 30 * time.Second, writeTimeout: 5 * time.Second, wantErr: true},
		{name: "request timeout too short for takeover", requestTimeout: time.Second, writeTimeout: 10 * time.Second, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := requestTimeout(&options.ServerOptions{RequestTimeout: tc.requestTimeout, WriteTimeout: tc.writeTimeout})
			if tc.wantErr {
				require.ErrorIs(t, err, errRequestTimeout)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestRequestDeadlineMiddlewareCancelsRequestContext checks that the deadline
// reaches the handler's context, which the write timeout alone does not cancel.
func TestRequestDeadlineMiddlewareCancelsRequestContext(t *testing.T) {
	t.Parallel()

	middleware, err := requestDeadlineMiddleware(&options.ServerOptions{RequestTimeout: 30 * time.Second, WriteTimeout: 10 * time.Second})
	require.NoError(t, err)

	start := time.Now()

	var (
		deadline time.Time
		ok       bool
	)

	middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		deadline, ok = r.Context().Deadline()
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	require.True(t, ok)
	require.WithinDuration(t, start.Add(8*time.Second), deadline, time.Second)
}

const (
	identityID = "spiffe://example.org/identity"
	regionID   = "spiffe://example.org/region"
)

// staticSource is a SPIFFE source with a fixed SVID and fixed bundles.
type staticSource struct {
	*x509svid.SVID
	x509bundle.Source
}

func (staticSource) Close() error {
	return nil
}

// spiffeTestPKI holds a CA for the trust domain of identity, and a CA for a
// second trust domain.  The bundle set holds both, so a peer of the second
// trust domain passes chain verification and only the authorizer refuses it.
type spiffeTestPKI struct {
	trustDomain        spiffeid.TrustDomain
	caCertificate      *x509.Certificate
	caKey              *ecdsa.PrivateKey
	otherCACertificate *x509.Certificate
	otherCAKey         *ecdsa.PrivateKey
	bundles            *x509bundle.Set
}

func newSPIFFETestPKI(t *testing.T) *spiffeTestPKI {
	t.Helper()

	caCertificate, caKey, _, _, err := mtlstest.GenerateCACerts()
	require.NoError(t, err)

	otherCACertificate, otherCAKey, _, _, err := mtlstest.GenerateCACerts()
	require.NoError(t, err)

	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")

	return &spiffeTestPKI{
		trustDomain:        trustDomain,
		caCertificate:      caCertificate,
		caKey:              caKey,
		otherCACertificate: otherCACertificate,
		otherCAKey:         otherCAKey,
		bundles: x509bundle.NewSet(
			x509bundle.FromX509Authorities(trustDomain, []*x509.Certificate{caCertificate}),
			x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("other.org"), []*x509.Certificate{otherCACertificate}),
		),
	}
}

func (p *spiffeTestPKI) svid(t *testing.T, id string) *x509svid.SVID {
	t.Helper()

	svid, err := mtlstest.NewSVID(p.caCertificate, p.caKey, id, "")
	require.NoError(t, err)

	return svid
}

// clientConfig is the TLS configuration of a client with the SVID that checks
// the SPIFFE ID of identity.
func (p *spiffeTestPKI) clientConfig(svid *x509svid.SVID) *tls.Config {
	return tlsconfig.MTLSClientConfig(svid, p.bundles, tlsconfig.AuthorizeID(spiffeid.RequireFromString(identityID)))
}

// serveSPIFFETest serves the listener as the command does: configureServer, then
// ServeTLS.  The handler sends the TLS state of each request.  configure, when
// set, changes the server before it serves.
func serveSPIFFETest(t *testing.T, pki *spiffeTestPKI, configure func(*http.Server)) (string, <-chan *tls.ConnectionState) {
	t.Helper()

	states := make(chan *tls.ConnectionState, 10)

	server := &http.Server{
		Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			states <- r.TLS
		}),
		ReadHeaderTimeout: time.Second,
	}

	o := &SPIFFEOptions{
		ListenAddress: "127.0.0.1:0",
		source:        staticSource{SVID: pki.svid(t, identityID), Source: pki.bundles},
		trustDomain:   pki.trustDomain,
	}

	o.configureServer(server, readiness.New())

	if configure != nil {
		configure(server)
	}

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		_ = server.ServeTLS(listener, "", "")
	}()

	t.Cleanup(func() {
		require.NoError(t, server.Close())
	})

	return listener.Addr().String(), states
}

// get sends one request on a new connection, reads the response and expects a
// 200.  It returns the TLS state of the connection.
func get(t *testing.T, config *tls.Config, address string) (*tls.ConnectionState, error) {
	t.Helper()

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: config, DisableKeepAlives: true},
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/", nil)
	require.NoError(t, err)

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)

	return response.TLS, nil
}

func TestSPIFFEListenerAcceptsAnSVIDOfTheTrustDomain(t *testing.T) {
	t.Parallel()

	pki := newSPIFFETestPKI(t)
	address, states := serveSPIFFETest(t, pki, nil)

	_, err := get(t, pki.clientConfig(pki.svid(t, regionID)), address)
	require.NoError(t, err)

	state := <-states
	require.Len(t, state.PeerCertificates, 1)
	require.Equal(t, regionID, state.PeerCertificates[0].URIs[0].String())
	require.Empty(t, state.VerifiedChains, "a verified SPIFFE peer has no verified chains, so no check can use them")
}

func TestSPIFFEListenerRefusesAClientWithNoCertificate(t *testing.T) {
	t.Parallel()

	pki := newSPIFFETestPKI(t)
	address, _ := serveSPIFFETest(t, pki, nil)

	_, err := get(t, tlsconfig.TLSClientConfig(pki.bundles, tlsconfig.AuthorizeID(spiffeid.RequireFromString(identityID))), address)
	require.Error(t, err)
}

func TestSPIFFEListenerRefusesAnotherTrustDomain(t *testing.T) {
	t.Parallel()

	pki := newSPIFFETestPKI(t)
	address, _ := serveSPIFFETest(t, pki, nil)

	other, err := mtlstest.NewSVID(pki.otherCACertificate, pki.otherCAKey, "spiffe://other.org/region", "")
	require.NoError(t, err)

	_, err = get(t, pki.clientConfig(other), address)
	require.Error(t, err)
}

func TestSPIFFEListenerRefusesTLS12(t *testing.T) {
	t.Parallel()

	pki := newSPIFFETestPKI(t)
	address, _ := serveSPIFFETest(t, pki, nil)

	config := pki.clientConfig(pki.svid(t, regionID))
	config.MaxVersion = tls.VersionTLS12

	_, err := get(t, config, address)
	require.ErrorContains(t, err, "protocol version")
}

func TestSPIFFEListenerNegotiatesHTTP1(t *testing.T) {
	t.Parallel()

	pki := newSPIFFETestPKI(t)
	address, _ := serveSPIFFETest(t, pki, nil)

	config := pki.clientConfig(pki.svid(t, regionID))
	config.NextProtos = []string{"h2", "http/1.1"}

	conn, err := (&tls.Dialer{Config: config}).DialContext(t.Context(), "tcp", address)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	tlsConn, ok := conn.(*tls.Conn)
	require.True(t, ok)
	require.Equal(t, "http/1.1", tlsConn.ConnectionState().NegotiatedProtocol)
}

// TestSPIFFEListenerDoesNotResumeSessions checks that each connection verifies
// the peer again.  The control run turns session tickets on and expects a
// resumed session, so the test can see a resumption.  A TLS 1.3 client reads
// the ticket after the handshake, so each connection reads a response.
func TestSPIFFEListenerDoesNotResumeSessions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		configure  func(*http.Server)
		wantResume bool
	}{
		{
			name: "session tickets off",
		},
		{
			name: "control with session tickets on",
			configure: func(server *http.Server) {
				server.TLSConfig.SessionTicketsDisabled = false
			},
			wantResume: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pki := newSPIFFETestPKI(t)
			address, _ := serveSPIFFETest(t, pki, tc.configure)

			config := pki.clientConfig(pki.svid(t, regionID))
			config.ClientSessionCache = tls.NewLRUClientSessionCache(1)

			first, err := get(t, config, address)
			require.NoError(t, err)
			require.False(t, first.DidResume)

			second, err := get(t, config, address)
			require.NoError(t, err)
			require.Equal(t, tc.wantResume, second.DidResume)
		})
	}
}

// TestSPIFFEListenerReadinessFollowsTheSVID checks that the listener takes the
// replica out of service when the SVID of identity expires.
func TestSPIFFEListenerReadinessFollowsTheSVID(t *testing.T) {
	t.Parallel()

	pki := newSPIFFETestPKI(t)
	svid := pki.svid(t, identityID)

	ready := readiness.New()
	o := &SPIFFEOptions{
		ListenAddress: ":6082",
		source:        staticSource{SVID: svid, Source: pki.bundles},
		trustDomain:   pki.trustDomain,
	}

	o.configureServer(&http.Server{ReadHeaderTimeout: time.Second}, ready)
	require.NoError(t, ready.Check(t.Context()))

	svid.Certificates[0].NotAfter = time.Now().Add(-time.Minute)

	require.ErrorIs(t, ready.Check(t.Context()), readiness.ErrSVIDExpired)
}

func TestSPIFFEListenerOffLeavesTheServerUnchanged(t *testing.T) {
	t.Parallel()

	s := &Server{SPIFFEOptions: SPIFFEOptions{relayerIDs: []string{"not a SPIFFE ID"}}}
	require.NoError(t, s.SetupSPIFFE(t.Context()), "the relayer IDs are not read when the listener is off")

	server := &http.Server{ReadHeaderTimeout: time.Second}
	ready := readiness.New()

	s.SPIFFEOptions.configureServer(server, ready)

	require.Nil(t, server.TLSConfig)
	require.Nil(t, server.Protocols)
	require.Nil(t, server.ErrorLog)
	require.NoError(t, ready.Check(t.Context()))
	require.NoError(t, s.SPIFFEOptions.Close())
}

func TestValidateRelayerIDs(t *testing.T) {
	t.Parallel()

	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	registered := map[string]string{
		regionID:                    "region-service",
		"unikorn-region":            "region-service",
		"spiffe://other.org/region": "region-service",
	}

	refused := []struct {
		name string
		id   string
	}{
		{name: "not a SPIFFE ID", id: "unikorn-region"},
		{name: "another trust domain", id: "spiffe://other.org/region"},
		{name: "not registered", id: "spiffe://example.org/compute"},
	}

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := validateRelayerIDs([]string{regionID, tc.id}, trustDomain, registered)
			require.ErrorIs(t, err, errRelayerID)
		})
	}

	t.Run("a duplicate passes", func(t *testing.T) {
		t.Parallel()

		relayers, err := validateRelayerIDs([]string{regionID, regionID}, trustDomain, registered)
		require.NoError(t, err)
		require.Equal(t, []string{regionID, regionID}, relayers)
	})

	t.Run("an empty list passes", func(t *testing.T) {
		t.Parallel()

		relayers, err := validateRelayerIDs(nil, trustDomain, registered)
		require.NoError(t, err)
		require.Empty(t, relayers)
	})
}

// TestSetupSPIFFEWaitIsBounded checks that the process does not wait forever
// for a Workload API that is not there.  It sets an environment variable, so it
// does not run in parallel.
func TestSetupSPIFFEWaitIsBounded(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix://"+t.TempDir()+"/missing.sock")

	s := &Server{SPIFFEOptions: SPIFFEOptions{ListenAddress: ":6082", startTimeout: 100 * time.Millisecond}}

	start := time.Now()

	err := s.SetupSPIFFE(t.Context())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second, "the start timeout bounds the wait")
	require.NoError(t, s.SPIFFEOptions.Close())
}

// peerRequest returns a request with a verified TLS peer whose certificate is
// valid from notBefore to notAfter.
func peerRequest(t *testing.T, path string, notBefore, notAfter time.Time) *http.Request {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{NotBefore: notBefore, NotAfter: notAfter}},
	}

	return r
}

func TestVerifiedPeerHeadersDeletesClientCertificateHeaders(t *testing.T) {
	t.Parallel()

	now := time.Now()

	cases := []struct {
		name        string
		request     func(t *testing.T) *http.Request
		wantDeleted bool
	}{
		{
			name: "verified peer",
			request: func(t *testing.T) *http.Request {
				t.Helper()

				return peerRequest(t, "/", now.Add(-time.Hour), now.Add(time.Hour))
			},
			wantDeleted: true,
		},
		{
			name: "no TLS state",
			request: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			},
		},
		{
			name: "TLS state with no peer certificate",
			request: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://identity.example.com/", nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := tc.request(t)
			r.Header.Set("Ssl-Client-Cert", "certificate")
			r.Header.Set("Ssl-Client-Verify", "SUCCESS")

			var seen http.Header

			verifiedPeerHeaders(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = r.Header.Clone()
			})).ServeHTTP(httptest.NewRecorder(), r)

			if tc.wantDeleted {
				require.Empty(t, seen.Get("Ssl-Client-Cert"))
				require.Empty(t, seen.Get("Ssl-Client-Verify"))

				return
			}

			require.Equal(t, "certificate", seen.Get("Ssl-Client-Cert"))
			require.Equal(t, "SUCCESS", seen.Get("Ssl-Client-Verify"))
		})
	}
}

// TestVerifiedPeerHeadersClosesAgingConnections checks that a client reconnects
// with its renewed SVID once its SVID is past half of its lifetime.  An expired
// SVID also gets Connection: close, whatever the status of the response.
func TestVerifiedPeerHeadersClosesAgingConnections(t *testing.T) {
	t.Parallel()

	now := time.Now()

	cases := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		status    int
		wantClose bool
	}{
		{name: "before half of the lifetime", notBefore: now.Add(-time.Hour), notAfter: now.Add(3 * time.Hour), status: http.StatusOK},
		{name: "past half of the lifetime", notBefore: now.Add(-3 * time.Hour), notAfter: now.Add(time.Hour), status: http.StatusOK, wantClose: true},
		{name: "expired", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Minute), status: http.StatusUnauthorized, wantClose: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()

			verifiedPeerHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})).ServeHTTP(w, peerRequest(t, "/", tc.notBefore, tc.notAfter))

			require.Equal(t, tc.status, w.Code)

			if tc.wantClose {
				require.Equal(t, "close", w.Header().Get("Connection"))

				return
			}

			require.Empty(t, w.Header().Get("Connection"))
		})
	}
}

// logLines collects the lines of the global logger.  The router middleware
// takes its logger from the global one, so a test cannot give it a logger in
// the request context.
//
//nolint:gochecknoglobals // The global logger can be set only once.
var logLines struct {
	once  sync.Once
	lock  sync.Mutex
	lines []string
}

func captureGlobalLog() {
	logLines.once.Do(func() {
		log.SetLogger(funcr.New(func(prefix, args string) {
			logLines.lock.Lock()
			defer logLines.lock.Unlock()

			logLines.lines = append(logLines.lines, prefix+" "+args)
		}, funcr.Options{Verbosity: 1}))
	})
}

func logLinesContaining(text string) []string {
	logLines.lock.Lock()
	defer logLines.lock.Unlock()

	var result []string

	for _, line := range logLines.lines {
		if strings.Contains(line, text) {
			result = append(result, line)
		}
	}

	return result
}

// TestRouterDeletesClientCertificateHeadersBeforeTheRequestLog checks the
// order of the router middleware: a request with a verified peer and a 4xx
// result must not write Ssl-Client-Cert to the request log.
func TestRouterDeletesClientCertificateHeadersBeforeTheRequestLog(t *testing.T) {
	t.Parallel()

	captureGlobalLog()

	schema, err := helpers.NewSchema(openapi.GetSwagger)
	require.NoError(t, err)

	router, err := (&Server{}).newRouter(schema)
	require.NoError(t, err)

	const path = "/test-router-deletes-client-certificate-headers"

	// chi applies the middleware only once the router has a route.
	router.Get(path, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	r := peerRequest(t, path, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	r.Header.Set("Ssl-Client-Cert", "client-certificate-of-another-account")
	r.Header.Set("Ssl-Client-Verify", "SUCCESS")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	require.GreaterOrEqual(t, w.Code, http.StatusBadRequest)

	lines := logLinesContaining(path)
	require.NotEmpty(t, lines, "the request log has a line for the request")

	for _, line := range lines {
		require.NotContains(t, line, "client-certificate-of-another-account")
		require.NotContains(t, line, "Ssl-Client-Verify")
	}
}

// TestValidatorChecksTheSystemAccountRegistry checks that the API server gives
// the registry to the validator: an unregistered certificate subject that sends
// X-Principal gets the generic 401, and no ACL lookup runs.
func TestValidatorChecksTheSystemAccountRegistry(t *testing.T) {
	t.Parallel()

	s := &Server{}
	s.OpenAPIOptions.ACLCacheSize = 1
	s.RBACOptions.SystemAccountRoleIDs = map[string]string{"registered-service": "role"}

	schema, err := helpers.NewSchema(openapi.GetSwagger)
	require.NoError(t, err)

	// The mock expects no call, so an ACL lookup fails the test.
	validator := s.newValidator(mock.NewMockAuthorizer(gomock.NewController(t)), nil)

	router := chi.NewRouter()
	router.Use(routeresolver.New(schema).Middleware)
	router.Use(validator.Middleware)
	router.Get("/api/v1/organizations", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// The subject of the certificate is its common name, which is not registered.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newSPIFFETestPKI(t).caCertificate.Raw})

	principalJSON, err := json.Marshal(&principal.Principal{Actor: "jane@acme.com"})
	require.NoError(t, err)

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/organizations", nil)
	r.Header.Set("Ssl-Client-Cert", url.QueryEscape(string(certPEM)))
	r.Header.Set("Ssl-Client-Verify", "SUCCESS")
	r.Header.Set(principal.Header, base64.RawURLEncoding.EncodeToString(principalJSON))

	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)

	response := &coreapi.Error{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), response))
	require.Equal(t, coreapi.AccessDenied, response.Error)
	require.Equal(t, util.AccessDeniedDescription, response.ErrorDescription)
}

// TestSPIFFEListenerLogsAHandlerPanicAsAnError checks the levels of the server
// error log: a handler panic is an error line, and a TLS handshake error stays
// an info line.
func TestSPIFFEListenerLogsAHandlerPanicAsAnError(t *testing.T) {
	t.Parallel()

	captureGlobalLog()

	pki := newSPIFFETestPKI(t)

	const panicValue = "test-spiffe-listener-handler-panic"

	address, _ := serveSPIFFETest(t, pki, func(server *http.Server) {
		server.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(panicValue)
		})
	})

	_, err := get(t, pki.clientConfig(pki.svid(t, regionID)), address)
	require.Error(t, err)

	connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", address)
	require.NoError(t, err)

	handshakeError := "TLS handshake error from " + connection.LocalAddr().String()

	require.NoError(t, connection.Close())

	require.Eventually(t, func() bool {
		return len(logLinesContaining(panicValue)) > 0 && len(logLinesContaining(handshakeError)) > 0
	}, 5*time.Second, 10*time.Millisecond)

	for _, line := range logLinesContaining(panicValue) {
		require.Contains(t, line, `"error"=`)
	}

	for _, line := range logLinesContaining(handshakeError) {
		require.NotContains(t, line, `"error"=`)
	}
}
