# ids

Nominal UUID types for organization and project identifiers.

## Purpose

Provides `OrganizationID` and `ProjectID` as distinct named types over
`uuid.UUID`. The two types are not interchangeable: the compiler rejects
any attempt to pass a `ProjectID` where an `OrganizationID` is expected,
preventing a whole class of silent parameter-swap bugs.

Both types implement `encoding.TextUnmarshaler` by delegating to
`uuid.UUID`. This means the oapi-codegen parameter binder validates UUID
format at path-parameter binding time — before any handler is reached —
so non-UUID path values produce a 400 at the routing layer rather than
propagating into business logic.

## Conversion

**Inward (string → typed ID):** Use `ParseOrganizationID` / `ParseProjectID`
when the source is untrusted (e.g. Kubernetes labels, token claims). Use
`MustParseOrganizationID` / `MustParseProjectID` only where the value is
guaranteed valid by a prior validation step (e.g. a path parameter that has
already passed the binding layer).

**Outward (typed ID → string):** Call `.String()` to produce the canonical
hyphenated UUID string for Kubernetes object names, label values, or log
messages.
