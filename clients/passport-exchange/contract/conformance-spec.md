# Passport Exchange Conformance Specification

This document defines behavior that each language client must satisfy for `POST /oauth2/v2/exchange`.

## Request Contract

- Method: `POST`
- Path: `/oauth2/v2/exchange`
- Authorization: `Authorization: Bearer <source token>`
- Body encoding: `application/x-www-form-urlencoded`
- Optional form fields:
  - `organizationId`
  - `projectId`

## Response Contract

- `200` returns JSON body with:
  - `passport` (string)
  - `expires_in` (integer seconds)
- `401` returns OAuth2 error JSON and is surfaced as unauthorized to callers.
- Non-2xx responses are surfaced as typed HTTP errors.

## Retry Contract

- 4xx responses are never retried.
- Default retry policy:
  - max attempts: `2` total calls
  - retryable HTTP statuses: `502`, `503`, `504`
  - `500` is not retried by default
  - network errors are retried once (unless context deadline/cancel fired)
- Retry behavior is configurable per client.

Rationale for excluding `500` by default:
- `500` is not a reliable transient signal in current exchange endpoint behavior.
- Some `500` responses may represent permanent/auth-related failures that will not succeed on immediate retry.
- Avoiding default `500` retries limits retry amplification on the identity hot path.
- Clients may opt in to retry `500` for specific environments via configuration.

## Timeout and Cancellation

- Each exchange call must honor caller context cancellation.
- Each exchange call must honor caller-provided deadline/timeout semantics.
- Retries must not outlive request context deadline.

## Caching Contract

- In-process cache behavior is optional and configurable.
- Cache key includes source token plus optional org/project context.
- Cached entries expire using `expires_in` when present.
- If `expires_in` is absent/non-positive, client default cache TTL is used.

## Security and Logging

- Clients must not log:
  - source tokens
  - passport tokens
  - raw authorization headers
  - PII claims
- Safe telemetry fields include result class, status code class, retry count, and duration.

## Metrics Hook Contract

- Clients should expose host-wired metrics hooks/callbacks rather than enforcing a concrete metrics backend.
- Hook outputs should map to:
  - `passport_exchange_total{result=success|cached|error|unauthorized}`
  - `passport_exchange_duration_seconds`
- Duration metric excludes cache hits.
