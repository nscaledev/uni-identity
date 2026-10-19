# `pkg/aggregation`

Computes the effective scopes of aggregating roles.

`Compute` takes a snapshot of every role in the namespace and returns the
desired status of each aggregating role: effective scopes, the sources used
(with a scopes hash each), and the `Available` and `Grantable` conditions. It
is pure: it reads, never writes.

It has two callers:

- the [role controller](../controllers/role/README.md), which writes the
  result to each role's status
- tests that check the chart's role catalogue, which compute effective scopes
  the same way the controller will

The scope rules, source rules and failure behaviour are documented in the
[role controller README](../controllers/role/README.md).
