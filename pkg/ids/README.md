# ids

Nominal UUID types for all resource identifiers in the identity API.

## Purpose

Provides distinct named types over `uuid.UUID` for every resource category:

| Type | Identifies |
|---|---|
| `OrganizationID` | organizations |
| `ProjectID` | projects |
| `ServiceAccountID` | service accounts |
| `UserID` | users |
| `GroupID` | groups |
| `OAuth2ProviderID` | OAuth2 providers |
| `AllocationID` | resource allocations |

Each type is a distinct named type — not an alias — so the compiler prevents
a `ProjectID` from being passed where an `OrganizationID` is expected, and
so on across all seven types.

Each type implements `encoding.TextUnmarshaler` by delegating to `uuid.UUID`,
so the oapi-codegen parameter binder validates UUID format at path-parameter
binding time before any handler is reached. Non-UUID path values produce a
400 at the routing layer rather than propagating into business logic.

## Conversion

**Inward (string → typed ID):** Use `Parse*` for untrusted input (Kubernetes
labels, token claims, request body fields). Use `MustParse*` only where the
value is guaranteed valid by a prior validation step (e.g. a path parameter
that has already passed the binding layer).

**Outward (typed ID → string):** Call `.String()` to produce the canonical
hyphenated UUID string for Kubernetes object names, label values, or log
messages.
