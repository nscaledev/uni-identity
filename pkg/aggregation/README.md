# `pkg/aggregation`

Computes the effective scopes of aggregating roles.

`Compute` takes a snapshot of every role in the namespace and returns, for
each aggregating role: effective scopes, the sources used (with a scopes hash
each), the `Available` condition, and the labelled roles the controller's
`Grantable` check needs. It is pure: it reads, never writes, and never reads
status.

`Resolve` runs `Compute` on a map of roles and sets each aggregating role's
`Computed` field in place. `ResolveRole` does the same for one loaded role, by
listing its namespace; a role that does not aggregate is left alone, with no
list. `Computed` is never stored or sent.

Callers:

- the ACL build in [`pkg/rbac`](../rbac/README.md), which resolves every role
  it lists
- the group and membership handlers, which resolve a role before
  `rbac.AllowRole`
- the [role controller](../controllers/role/README.md), which writes the
  result to status as a record for people
- tests that check the chart's role catalogue

Enforcement uses only the live result: `Role.EffectiveScopes()` reads
`Computed`, and an aggregating role that was not resolved holds nothing and is
not grantable.

The scope rules, source rules and failure behaviour are documented in the
[role controller README](../controllers/role/README.md).
