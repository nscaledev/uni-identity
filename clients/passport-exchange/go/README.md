# Go Passport Exchange Client

This package provides a Go client for `POST /oauth2/v2/exchange`.

## Features

- Bearer token exchange with optional `organizationId` and `projectId` context.
- Typed unauthorized, HTTP status, and transport errors.
- Configurable retry policy for transient failures.
- Context cancellation/deadline support (caller-managed timeouts).
- Optional in-process response caching.
- Optional metrics hooks.

## Timeout Model (Go)

- The Go client does not expose a separate timeout option.
- Callers set request timeout/deadline via `context.WithTimeout` / `context.WithDeadline`.
- Callers may also set transport-level limits on their own `http.Client` as needed.

## Metrics Hooks

`Options.Metrics` provides lightweight integration points without forcing a metrics backend:

- `IncTotal(result string)`
- `ObserveDuration(duration time.Duration)`

Recommended mapping:

- `IncTotal` -> `passport_exchange_total{result=success|cached|error|unauthorized}`
- `ObserveDuration` -> `passport_exchange_duration_seconds`

Hook behavior in this client:

- Cache hits emit `result=cached` and do not emit duration.
- Non-cached attempts emit duration once per call outcome.

## Retry Defaults

- Max attempts: `2` (initial call + one retry)
- Retryable statuses: `502`, `503`, `504`
- `500` is not retried by default
- Network errors retried once unless context cancellation/deadline has fired

Why `500` is excluded by default:
- `500` is ambiguous for this endpoint and is not always a transient condition.
- Retrying all `500`s can amplify traffic on the identity hot path during outages.
- If your environment treats some `500` classes as transient, include `500` in `RetryableStatusCodes` explicitly.
