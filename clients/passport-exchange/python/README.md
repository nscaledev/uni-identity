# Python Passport Exchange Client

This package provides a Python client for `POST /oauth2/v2/exchange`.

## Features

- Builder-style exchange call API.
- Source bearer token exchange with optional `organizationId` and `projectId` context.
- Per-request timeout on the call builder.
- Typed unauthorized, HTTP status, transport, and payload errors.
- Configurable retry policy.
- Optional in-process cache keyed by token and scope context.
- Optional request editor hooks and metrics callbacks.

## Retry Defaults

- Max attempts: `2` total calls.
- Retryable statuses: `502`, `503`, `504`.
- `500` is not retried by default.
- Network/transport errors are retried once by default.

## Usage

```python
from passport_exchange_client import Options, PassportExchangeClient

client = PassportExchangeClient(Options(base_url="https://identity.example.com"))

response = (
    client.exchange("source-token")
    .organization_id("org-1")
    .project_id("project-1")
    .timeout(2.0)
    .send()
)

print(response.passport)
```
