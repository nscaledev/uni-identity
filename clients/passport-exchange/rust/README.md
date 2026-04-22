# Rust Passport Exchange Client

This crate provides a Rust client for `POST /oauth2/v2/exchange`.

## Features

- Builder-style exchange call API.
- Source bearer token exchange with optional `organizationId` and `projectId` context.
- Typed errors for unauthorized, HTTP status, transport, and payload failures.
- Configurable retry policy.
- Optional in-process cache keyed by token + context.
- Optional request editor hooks for caller-provided request mutation.
- Pluggable metrics sink trait for total-result and duration reporting.

## Usage

```rust
let response = client
    .exchange("source-token")
    .organization_id("org-1")
    .project_id("project-1")
    .timeout(std::time::Duration::from_secs(2))
    .send()
    .await?;
```

## Retry Defaults

- Max attempts: `2` total calls.
- Retryable statuses: `502`, `503`, `504`.
- `500` is not retried by default.
- Network/transport errors are retried once by default.

## Metrics Sink

Provide your own metrics backend by implementing `MetricsSink` and wiring it through `Options.metrics`.

```rust
use std::sync::Arc;
use std::time::Duration;

use passport_exchange_client::{MetricsSink, Options};

struct MyMetrics;

impl MetricsSink for MyMetrics {
    fn inc_total(&self, result: &'static str) {
        let _ = result;
    }

    fn observe_duration(&self, duration: Duration) {
        let _ = duration;
    }
}

let mut options = Options::new("https://identity.example.com");
options.metrics = Arc::new(MyMetrics);
```
