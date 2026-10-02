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
