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

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"

	coreoptions "github.com/unikorn-cloud/core/pkg/options"
	"github.com/unikorn-cloud/identity/pkg/constants"
)

const metricsScrapeTestProcess = "IDENTITY_METRICS_SCRAPE_TEST_PROCESS"

func TestSetupTelemetryServesLabeledCounters(t *testing.T) {
	t.Parallel()

	if os.Getenv(metricsScrapeTestProcess) != "1" {
		command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSetupTelemetryServesLabeledCounters$") //nolint:gosec // re-runs this test binary.
		command.Env = append(os.Environ(), metricsScrapeTestProcess+"=1")
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))

		return
	}

	options := &coreoptions.CoreOptions{}
	require.NoError(t, setupTelemetry(t.Context(), options))

	counter, err := otel.Meter(constants.Application).Int64Counter("identity_test_scrape")
	require.NoError(t, err)
	counter.Add(t.Context(), 1)

	assert.Regexp(t, `\nidentity_test_scrape_total\{[^}]*service="unikorn-identity"[^}]*\} 1\n`, scrapeMetrics(t, options))
}

func scrapeMetrics(t *testing.T, options *coreoptions.CoreOptions) string {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errs := make(chan error, 1)
	go func() { errs <- options.ServeMetrics(ctx, address) }()

	var body string

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
		require.NoError(c, err)

		response, err := http.DefaultClient.Do(request)
		require.NoError(c, err)

		defer response.Body.Close()

		data, err := io.ReadAll(response.Body)
		require.NoError(c, err)
		require.Equal(c, http.StatusOK, response.StatusCode)

		body = string(data)
	}, 5*time.Second, 50*time.Millisecond)

	cancel()
	require.NoError(t, <-errs)

	return body
}
