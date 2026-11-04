# `pkg/server/metrics`

This package publishes API-server build and readiness gauges through the
configured OpenTelemetry meter.

`unikorn_identity_server_build_info{version,revision}` is `1` for the process
lifetime. `unikorn_server_ready{version,revision}` is `1` only while the server
owns its bound HTTP listener. The command creates the listener before starting
`Serve`, so a server that cannot bind never reports ready.

The readiness gauge name is platform-generic so one query can aggregate it
across services; the emitting service is identified by the OTLP resource
(`service.name`), which the deployment sets via `OTEL_SERVICE_NAME`.

`unikorn_identity_system_account_authentications` is a counter with the unit
`{authentication}`. `NewAuthentications` creates it, and the API server passes
its `Record` method to the OpenAPI validator as the authentication recorder
(see [`pkg/middleware/openapi`](../../middleware/openapi/README.md)). The
validator records each refused client certificate, and each success of a
request that has a client certificate and no `Authorization` header. A label
is present only when its field has a value:

- `listener`: `spiffe` for a request with a verified TLS peer, `legacy`
  otherwise.
- `result`: `ok` or `refused`.
- `reason`: the reason code, on a refusal only.
- `peer`: the subject of the verified TLS peer, on the `spiffe` listener only.
- `subject`: the authenticated system account, on a success only.

Only the identity command imports this package, so other services that import
the validator do not emit the counter.
