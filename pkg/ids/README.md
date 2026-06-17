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

## Scope readers

Two interfaces let scope-aware code accept a resource directly instead of bare
IDs, performing the "read labels, parse to typed ID" step in one place:

| Interface | Method(s) |
|---|---|
| `OrganizationScopeReader` | `OrganizationID() (OrganizationID, error)` |
| `ProjectScopeReader` | embeds `OrganizationScopeReader` plus `OrganizationAndProjectID() (OrganizationID, ProjectID, error)` |

`ProjectScopeReader` **embeds** `OrganizationScopeReader` because a project
always belongs to an organization — anything that knows its project also knows
its organization. A consumer can therefore accept the narrower
`OrganizationScopeReader` and still be passed a project-scoped resource.

These are implemented by CRDs in other services (e.g. `region`'s `Server`,
`Network`, `SecurityGroup`, …), whose accessor methods recover the IDs from the
standard organization/project labels. Consumers in this repo include the RBAC
`*Reader` helpers (`pkg/rbac`), the principal-enrichment helpers
(`pkg/principal`), and the `References` SDK client (`pkg/client`).

Three comparison helpers operate over these interfaces. All are
referential-integrity (ownership-equality) checks, **not** RBAC checks: they ask
whether resources belong to a given tenancy, not whether a caller may act in it.
Routing these through an RBAC scope check would let a caller authorized for
several projects relate resources across tenancy boundaries. All return an error
only when a resource's scope cannot be read, and a `bool` otherwise — callers map
a `false` result to their own transport error (the convention is `404`, so
resource existence is not leaked); this package stays free of transport concerns.

| Helper | Question |
|---|---|
| `SameProject(a, b ProjectScopeReader)` | do two resources share an org+project? |
| `OwnedByProject(scope ProjectScopeReader, organizationID, projectID)` | does a resource live in this org+project? |
| `OwnedByOrganization(scope OrganizationScopeReader, organizationID)` | does a resource live in this organization? |

`SameProject` guards relationships between two resources (e.g. a server and the
SSH certificate authority it references). `OwnedByProject` / `OwnedByOrganization`
are the typed equivalents of core's `AssertProjectOwnership` /
`AssertOrganizationOwnership`, for verifying a resource fetched by ID actually
belongs to the org/project from the request path.
