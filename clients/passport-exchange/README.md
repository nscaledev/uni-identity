# Passport Exchange Clients

This directory contains the shared contract artifacts and language-specific client implementations for `POST /oauth2/v2/exchange`.

## Layout

```text
clients/passport-exchange/
  contract/
  go/
  rust/
  typescript/
  python/
```

## Shared Contract Goals

- Accept source bearer token and return passport JWT.
- Support optional `organizationId` and `projectId` request options.
- Surface unauthorized responses clearly.
- Apply explicit retry policy for transient failures.
- Honor timeout and cancellation/deadline semantics.
- Avoid logging secrets or PII.

## Observability Integration

Language clients expose metrics hooks/callbacks for host applications to wire into their telemetry stack.

Recommended standard metrics:

- `passport_exchange_total{result=success|cached|error|unauthorized}`
- `passport_exchange_duration_seconds` (exclude cache hits)

Timeout behavior is language-specific. The Go client follows idiomatic context-driven timeouts (caller-managed deadlines).

## Default Retry Rationale

- `500` is not retried by default because it is ambiguous in current server behavior and may represent permanent/auth-related failures.
- On the identity auth path, broad `500` retries can amplify load and increase latency during incidents.
- Defaults therefore retry clearly transient classes (`502`, `503`, `504`) and network failures.
- Clients can still opt in to retry `500` explicitly when deployment-specific evidence supports it.

Language-specific packaging and release metadata lives in each implementation folder.
