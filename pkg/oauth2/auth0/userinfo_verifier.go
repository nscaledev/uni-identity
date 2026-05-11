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

package auth0

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type userinfoResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
}

type userinfoCircuitBreaker struct {
	failures         int
	openUntil        time.Time
	failureThreshold int
	openDuration     time.Duration
	now              func() time.Time
	mutex            sync.Mutex
}

func newUserinfoCircuitBreaker(failureThreshold int, openDuration time.Duration) *userinfoCircuitBreaker {
	return &userinfoCircuitBreaker{
		failureThreshold: failureThreshold,
		openDuration:     openDuration,
		now:              time.Now,
	}
}

func (b *userinfoCircuitBreaker) before() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.now().Before(b.openUntil) {
		return ErrUserinfoCircuitOpen
	}

	return nil
}

func (b *userinfoCircuitBreaker) success() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.failures = 0
	b.openUntil = time.Time{}
}

func (b *userinfoCircuitBreaker) failure() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.failures++

	if b.failures >= b.failureThreshold {
		b.openUntil = b.now().Add(b.openDuration)
		b.failures = 0
	}
}

// UserinfoVerifier validates opaque Auth0 access tokens via /userinfo.
type UserinfoVerifier struct {
	httpClient   *http.Client
	userinfoURL  string
	timeout      time.Duration
	maxRetries   int
	retryBackoff time.Duration
	circuit      *userinfoCircuitBreaker
	sleep        func(context.Context, time.Duration) error
}

// NewUserinfoVerifier configures migration-only opaque-token fallback.
func NewUserinfoVerifier(httpClient *http.Client, options *Options) (*UserinfoVerifier, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("%w: http client is required", ErrNotConfigured)
	}

	if options == nil {
		return nil, fmt.Errorf("%w: options are required", ErrNotConfigured)
	}

	url := strings.TrimSpace(options.EffectiveUserinfoURL())
	if url == "" {
		return nil, fmt.Errorf("%w: userinfo URL is required", ErrNotConfigured)
	}

	verifier := &UserinfoVerifier{
		httpClient:   httpClient,
		userinfoURL:  url,
		timeout:      options.EffectiveUserinfoHTTPTimeout(),
		maxRetries:   options.EffectiveUserinfoMaxRetries(),
		retryBackoff: options.EffectiveUserinfoRetryBackoff(),
		circuit:      newUserinfoCircuitBreaker(options.EffectiveUserinfoCircuitFailures(), options.EffectiveUserinfoCircuitOpenDuration()),
		sleep:        sleepWithContext,
	}

	return verifier, nil
}

// Verify validates opaque token against Auth0 /userinfo and returns claims.
func (v *UserinfoVerifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	if err := v.circuit.before(); err != nil {
		return nil, err
	}

	var lastErr error

	for attempt := 0; attempt <= v.maxRetries; attempt++ {
		claims, err := v.verifyOnce(ctx, rawToken)
		if err == nil {
			v.circuit.success()
			return claims, nil
		}

		if errors.Is(err, ErrInvalidToken) {
			v.circuit.failure()
			return nil, err
		}

		lastErr = err

		if attempt == v.maxRetries {
			break
		}

		if sleepErr := v.sleep(ctx, v.retryBackoff); sleepErr != nil {
			v.circuit.failure()
			return nil, fmt.Errorf("%w: retry canceled", ErrUserinfoUnavailable)
		}
	}

	v.circuit.failure()

	if lastErr == nil {
		return nil, ErrUserinfoUnavailable
	}

	return nil, lastErr
}

func (v *UserinfoVerifier) verifyOnce(ctx context.Context, rawToken string) (*Claims, error) {
	requestCtx, cancel := withFallbackTimeout(ctx, v.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, v.userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build userinfo request", ErrUserinfoUnavailable)
	}

	request.Header.Set("Authorization", "Bearer "+rawToken)

	response, err := v.httpClient.Do(request)
	if err != nil {
		return nil, classifyUserinfoRequestError(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read userinfo response", ErrUserinfoUnavailable)
	}

	return parseUserinfoResponse(response.StatusCode, body)
}

func classifyUserinfoRequestError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: timeout", ErrUserinfoUnavailable)
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: timeout", ErrUserinfoUnavailable)
	}

	return fmt.Errorf("%w: request failed", ErrUserinfoUnavailable)
}

func parseUserinfoResponse(statusCode int, body []byte) (*Claims, error) {
	switch statusCode {
	case http.StatusOK:
		var payload userinfoResponse
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("%w: invalid userinfo response", ErrUserinfoUnavailable)
		}

		subject := strings.TrimSpace(payload.Subject)
		if subject == "" {
			return nil, ErrInvalidToken
		}

		claims := &Claims{}
		claims.Subject = subject
		claims.Email = strings.TrimSpace(payload.Email)

		return claims, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrInvalidToken

	default:
		return nil, fmt.Errorf("%w: status %d", ErrUserinfoUnavailable, statusCode)
	}
}

func withFallbackTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= time.Millisecond {
			return context.WithTimeout(ctx, time.Millisecond)
		}

		if timeout >= remaining {
			return context.WithTimeout(ctx, remaining-time.Millisecond)
		}
	}

	return context.WithTimeout(ctx, timeout)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
