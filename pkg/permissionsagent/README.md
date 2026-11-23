# Permissions Agent Client

## Purpose

This package holds the public API contract for the nscale permissions agent and
a small Go client for it.

The agent runs in each region and answers authorization questions from a local
copy of the platform's permissions.  The agent itself lives in a separate
service; this package is the contract it implements and the client that uni
services use to call it.

Nothing in uni-identity calls the client yet.

## What Lives Here

- [`openapi/agent.spec.yaml`](./openapi/agent.spec.yaml): the API contract, and
  the source of truth
- `openapi/types.go`, `openapi/client.go`, `openapi/schema.go`: generated from
  the spec by `go generate` (`make generate`); do not edit
- `client.go`: the `Agent` interface, the HTTP `Client`, typed errors and the
  `UntrimmedPermissions` helper
- `mock/agent.go`: a generated gomock of `Agent`

## API

| Operation | Path | Use |
|---|---|---|
| Check | `POST /v1/check` | one item |
| BatchCheck | `POST /v1/check/batch` | many items in one call, answers in request order |
| Permissions | `GET /v1/permissions` | what the caller holds in one organization |
| Status | `GET /v1/status` | agent version, copy and policy versions, copy age, own region |

An item is `kind` + `action`, with an optional `organization_id` and
`project_id`.  No organization means a global question; an organization and no
project means org-wide.

Paths carry the version.  Within `v1`, fields are only ever added.

### Region trimming

- `/v1/check` does not use region: the answer is the same in every region.
- `/v1/permissions` is trimmed to one region by default: services the region does
  not run are left out.  `region_id` names the region; without it the agent's
  own region is used.
- `untrimmed=true` lists every service.  It cannot be combined with `region_id`.
- The response field `form` is `trimmed` or `untrimmed`.
- An unknown `region_id`, or `untrimmed=true` with `region_id`, returns 400.

## Client Behaviour

- **Caller**: `Caller.Token` is the user's access token, sent as a bearer
  token; the agent answers for its subject.  `Caller.Actor`, when set, is sent
  as `X-Actor` on checks; an item is then allowed only when both the user and
  the actor are allowed.  The actor can only narrow the answer.
- **Timeout**: each call is bounded by `Options.Timeout` (default 250ms).
- **Errors**: every failure matches one sentinel with `errors.Is`.
  `ErrUnavailable` covers transport errors, timeouts and 502/503/504; the agent
  returns 503 when it has no fresh copy.  Callers that enforce must treat any
  error as a denial.  A denied item is not an error: it is `allowed: false`.
- **Batch**: `BatchCheck` refuses a reply whose answer count does not match the
  items (`ErrResponse`), since answers are matched by position.
- **Untrimmed lists**: `UntrimmedPermissions` asks for `untrimmed=true` and
  returns `ErrTrimmed` for any other form.  Role grants and comparisons with uni
  RBAC must use it, because a trimmed list hides what the caller holds where
  other services run.

## Caveats

- The agent's own authentication of callers (bearer token, mTLS or both) is set
  by the agent deployment.  The client sends no `Authorization` header when
  `Caller.Token` is empty, so an mTLS-only `HTTPClient` works.
- The spec sets no maximum batch size yet.
