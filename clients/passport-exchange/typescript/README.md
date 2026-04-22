# TypeScript Passport Exchange Client

This package provides a TypeScript client for `POST /oauth2/v2/exchange`.

## Features

- Builder-style exchange API.
- Source token exchange with optional `organizationId` and `projectId` context.
- Per-request timeout and signal support on the call builder.
- Typed unauthorized, HTTP status, and transport errors.
- Configurable retry policy and safe defaults.
- Optional in-memory cache and metrics hooks.

## Retry Defaults

- Max attempts: `2` total calls.
- Retryable statuses: `502`, `503`, `504`.
- `500` is not retried by default.
- Network/transport errors retried once by default.

## Usage

```ts
const response = await client
  .exchange('source-token')
  .organizationId('org-1')
  .projectId('project-1')
  .timeout(2000)
  .send()
```
