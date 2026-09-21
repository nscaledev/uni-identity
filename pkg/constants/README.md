# `pkg/constants`

This package defines the canonical runtime identity for identity service binaries.

## Intent

The package is the single source of truth for process-level build metadata:

- application name
- version
- revision

That metadata is operationally important, not decorative.

It also defines `UNISentinel` — the non-URL issuer sentinel (`"uni"`) marking
UNI-locally-authenticated tokens. It lives here (a dependency-free leaf) so `oauth2` and `rbac` can
both reference it without an import cycle, letting issuer trust decisions distinguish UNI-local
tokens from external-IdP tokens.

It is used to:

- identify the running binary in logging and service descriptors
- tie a live deployment back to the exact code revision it was built from
- carry client identity across HTTP calls so cross-service mismatches can be debugged against
  the code actually running

The package is small, but it forms part of a wider operational contract that other repositories
can and do inherit.

## Invariants

- There should be one canonical source of application, version, and revision metadata inside
  the service.
- `Version` and `Revision` are expected to be injected by the build system.
- `ServiceDescriptor()` must remain aligned with the shared `core` service descriptor shape so
  other packages can consume it generically.
- `VersionString()` must remain suitable for use in HTTP client identity headers.
- The metadata emitted by this package must be stable enough to support debugging across logs,
  telemetry, and network calls.

## Caveats

- If the build does not inject `Version` or `Revision`, the package still compiles, but a large
  part of the deployment-debugging value is lost.
- `Application` is derived from `os.Args[0]`, so reported process identity depends in part on how
  the binary is invoked or packaged.
- This package links a deployment to a binary name and source revision, but it is not a complete
  software supply-chain provenance system.
- Changing `VersionString()` carelessly can damage downstream observability or make cross-service
  request attribution harder, even if local logging still appears acceptable.

## Cross-Repo Context

This style of package is not just a local helper. It is part of a broader cross-repository pattern
for runtime identity, service descriptors, and wire-visible debugging context. When evolving it,
prefer consistency with related services over repository-local convenience.
