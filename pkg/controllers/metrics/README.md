# Controller metrics

## Purpose

This package publishes the build identity and leader-ready state of each Identity
controller manager through the configured OpenTelemetry meter.

`unikorn_identity_controller_build_info` is `1` for the lifetime of a controller
process. `unikorn_controller_ready` becomes `1` only after its cache has synced
and it has acquired the manager leader lease. Both metrics carry the controller
name, version, and revision.

The readiness gauge name is platform-generic so one query can aggregate it
across services; the emitting service is identified by the OTLP resource
(`service.name`), which the deployment sets via `OTEL_SERVICE_NAME`.
