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
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/identity/pkg/constants"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/rbac"
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
