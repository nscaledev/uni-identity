# `pkg/aggregation`

Computes the effective scopes of aggregating roles.

`Compute` takes a snapshot of every role in the namespace and returns, for
each aggregating role: effective scopes, the sources used (with a scopes hash
each), the `Available` condition, and the labelled roles the controller's
`Grantable` check needs. It is pure: it reads, never writes, and never reads
status.

`Resolve` runs `Compute` on a map of roles and sets each aggregating role's
`Computed` field in place. A `Resolver` does the same for roles loaded one
at a time in one request: it lists the namespace once, the first time an
aggregating role needs it, and resolves each role's own copy against that
list. A role that does not aggregate is left alone, with no list. On a list
error the role holds nothing and is not ready, and the error is returned.
`ResolveRole` is a one-role `Resolver`. `Computed` is never stored or sent.

Each aggregating role's sources are gathered into one scope set and sorted
once, so `Compute` is linear in the number of sources (`BenchmarkResolve`:
300 roles, 5 aggregating).

Callers:

- the ACL build in [`pkg/rbac`](../rbac/README.md), which resolves every role
  it lists
- the group and membership handlers, which resolve the roles being granted
  through one `Resolver` per request before `rbac.AllowRole`
- the [role controller](../controllers/role/README.md), which writes the
  result to status as a record for people
- tests that check the chart's role catalogue

Enforcement uses only the live result: `Role.EffectiveScopes()` reads
`Computed`, and an aggregating role that was not resolved holds nothing and is
not grantable.

The scope rules, source rules and failure behaviour are documented in the
[role controller README](../controllers/role/README.md).
