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

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// Static errors for the mTLS client — keeps lint happy and lets callers use
// errors.Is for branch assertions if they ever need to.
var (
	errMTLSMissingBaseURL   = errors.New("mtls client: BaseURL is required")
	errMTLSMissingKeyPair   = errors.New("mtls client: CertPath and KeyPath are required")
	errMTLSInvalidCABundle  = errors.New("mtls client: parsing CA bundle")
	errMTLSUnexpectedStatus = errors.New("mtls client: exchange returned unexpected status")
)

// MTLSClient performs impersonated passport exchanges against /oauth2/v2/exchange
// using mutual TLS. The core APIClient is tightly coupled to bearer-token auth
// and doesn't expose a hook for custom HTTP transports, so this is a small,
// self-contained client purpose-built for the impersonation flow.
type MTLSClient struct {
	baseURL    string
	httpClient *http.Client
	endpoints  *Endpoints
}

// MTLSClientOptions configures a new MTLSClient.
type MTLSClientOptions struct {
	BaseURL  string
	CertPath string
	KeyPath  string
	// CACertPath is the CA bundle used to verify the identity server cert.
	// When empty, the system cert pool is used.
	CACertPath string
	Timeout    time.Duration
}

// NewMTLSClient builds a new client from file paths. It reads the cert, key
// and CA bundle from disk, constructs a dedicated TLS transport, and returns
// a client ready to POST /oauth2/v2/exchange.
func NewMTLSClient(opts MTLSClientOptions) (*MTLSClient, error) {
	if opts.BaseURL == "" {
		return nil, errMTLSMissingBaseURL
	}

	if opts.CertPath == "" || opts.KeyPath == "" {
		return nil, errMTLSMissingKeyPair
	}

	cert, err := tls.LoadX509KeyPair(opts.CertPath, opts.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("mtls client: loading key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	if opts.CACertPath != "" {
		caBytes, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("mtls client: reading CA bundle: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, errMTLSInvalidCABundle
		}

		tlsConfig.RootCAs = pool
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   timeout,
	}

	return &MTLSClient{
		baseURL:    opts.BaseURL,
		httpClient: httpClient,
		endpoints:  NewEndpoints(),
	}, nil
}

// ImpersonatedExchangeOptions controls a single impersonated exchange call.
// Principal is the identity being impersonated; when nil, no X-Principal header
// is sent (useful for fail-closed negative tests). Impersonate controls the
// X-Unikorn-Impersonate header; send "true" to opt into the impersonation path.
type ImpersonatedExchangeOptions struct {
	Principal    *principal.Principal
	Impersonate  bool
	Organization *string
	Project      *string
	// PrincipalHeaderOverride, when non-nil, replaces the base64 principal
	// header value. Use the empty string to send "X-Principal:" with an empty
	// value, or a bogus string to exercise malformed-header handling.
	PrincipalHeaderOverride *string
	// OmitImpersonateHeader suppresses the header entirely (regardless of
	// Impersonate). Distinguishes "absent" from "false".
	OmitImpersonateHeader bool
	// ImpersonateHeaderValue, when non-empty, sends that literal value
	// instead of "true"/"false" derived from Impersonate. Supports tests
	// like ImpersonateHeaderFalse and casing variants.
	ImpersonateHeaderValue string
}

// exchangeURL renders the full exchange URL including organization/project
// query parameters.
func (c *MTLSClient) exchangeURL(opts ImpersonatedExchangeOptions) string {
	path := c.endpoints.Exchange()

	params := url.Values{}
	if opts.Organization != nil {
		params.Set("organizationId", *opts.Organization)
	}

	if opts.Project != nil {
		params.Set("projectId", *opts.Project)
	}

	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	return c.baseURL + path
}

// applyPrincipalHeader sets X-Principal based on the options. PrincipalHeaderOverride
// takes precedence so tests can send malformed values; otherwise the principal is
// marshalled and base64url-encoded.
func applyPrincipalHeader(h http.Header, opts ImpersonatedExchangeOptions) error {
	if opts.PrincipalHeaderOverride != nil {
		h.Set(principal.Header, *opts.PrincipalHeaderOverride)

		return nil
	}

	if opts.Principal == nil {
		return nil
	}

	value, err := encodePrincipal(opts.Principal)
	if err != nil {
		return err
	}

	h.Set(principal.Header, value)

	return nil
}

// impersonateHeaderValue resolves the literal value for X-Impersonate. Returns
// an empty string when the header should be omitted.
func impersonateHeaderValue(opts ImpersonatedExchangeOptions) string {
	if opts.OmitImpersonateHeader {
		return ""
	}

	if opts.ImpersonateHeaderValue != "" {
		return opts.ImpersonateHeaderValue
	}

	if opts.Impersonate {
		return "true"
	}

	return "false"
}

// ExchangePassportRaw posts to /oauth2/v2/exchange and returns the response plus
// body bytes so tests can assert on both ExchangeResult and error shapes like
// oauth2error{error, error_description}.
func (c *MTLSClient) ExchangePassportRaw(ctx context.Context, opts ImpersonatedExchangeOptions) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.exchangeURL(opts), http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("building request: %w", err)
	}

	if err := applyPrincipalHeader(req.Header, opts); err != nil {
		return nil, nil, err
	}

	if value := impersonateHeaderValue(opts); value != "" {
		req.Header.Set(principal.ImpersonateHeader, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("exchange POST: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("reading response body: %w", err)
	}

	return resp, body, nil
}

// ExchangePassport is the happy-path helper that decodes a 200 response into
// ExchangeResult. Negative tests should use ExchangePassportRaw.
func (c *MTLSClient) ExchangePassport(ctx context.Context, opts ImpersonatedExchangeOptions) (*identityopenapi.ExchangeResult, error) {
	//nolint:bodyclose // ExchangePassportRaw closes the body before returning.
	resp, body, err := c.ExchangePassportRaw(ctx, opts)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d: %s", errMTLSUnexpectedStatus, resp.StatusCode, string(body))
	}

	var result identityopenapi.ExchangeResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshaling exchange result: %w", err)
	}

	return &result, nil
}

func encodePrincipal(p *principal.Principal) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshaling principal: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(data), nil
}
