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
- `openapi/types.go`, `openapi/client.go`: generated from the spec by
  `make generate`; do not edit
- `client.go`: the `Agent` interface, the HTTP `Client` and typed errors
- `mock/agent.go`: a generated gomock of `Agent`

## API

| Operation | Path | Use |
|---|---|---|
| Check | `POST /v1/check` | one item |
| BatchCheck | `POST /v1/check/batch` | up to 100 items in one call, `results` in request order |
| Permissions | `GET /v1/permissions` | what a subject holds in one organization |
| Status | `GET /v1/status` | agent version, copy and policy versions, copy age, own region |

- Every check and list request names the `subject` (required) and may name an
  `actor`: in the body for checks, as query parameters for the list.  With an
  actor, an item is allowed only when both are allowed.  The actor can only
  narrow an answer.
- An item is `kind` + `action`, with an optional `organizationId` and
  `projectId`.  No organization means a global question; an organization and
  no project means org-wide.
- A batch holds 1 to 100 items.  One invalid item fails the whole batch with
  400.
- Each list entry has `scope`: `global`, `organization` or `project`.
  `projectId` is set only for `project`.
- A denied item is `allowed: false` with 200.  A subject with no access in the
  organization gets 200 and an empty list.  Checks and the list never return
  403.
- JSON fields and query parameters are camelCase, like uni-identity's own API.
  Error bodies use the core error schema.
- Paths carry the version.  Within `v1`, fields are only ever added.

### Region trimming

- `/v1/check` does not use region: the answer is the same in every region.
- `/v1/permissions` is trimmed to one region by default: services the region does
  not run are left out.  `regionId` names the region; without it the agent's
  own region is used.
- `untrimmed=true` lists every service.  It cannot be combined with `regionId`.
- The response field `form` is `trimmed` or `untrimmed`.
- An unknown `regionId`, or `untrimmed=true` with `regionId`, returns 400.

## Caller Authentication

- The caller authenticates to the agent as itself, never with the subject's
  access token.
- `Options.Token` is the calling service's own bearer token, sent on every call.
  Leave it empty to send no `Authorization` header.
- For mTLS, pass an `Options.HTTPClient` set up with the client certificate.
  The agent deployment decides which of the two it requires.
- 401 (`ErrUnauthorized`) means the caller's own credentials were rejected.

## Client Behaviour

- **Timeout**: each call is bounded by `Options.Timeout` (default 250ms).
- **Errors**: every failure matches one sentinel with `errors.Is`.  Callers that
  enforce must treat any error as a denial.

  | Error | Meaning |
  |---|---|
  | `ErrInvalidInput` | refused locally, agent not called: no subject, empty batch, more than 100 items |
  | `ErrBadRequest` | 400 from the agent |
  | `ErrUnauthorized` | 401: caller credentials rejected |
  | `ErrForbidden` | 403, from status only |
  | `ErrUnavailable` | agent unreachable, `Options.Timeout` hit, or 502/503/504; 503 means no fresh copy |
  | `ErrServer` | any other error status |
  | `ErrResponse` | reply does not match the contract: not JSON, or wrong batch result count |
  | `ErrTrimmed` | untrimmed list asked for, trimmed list returned |

- **Caller context**: if the caller's own context is cancelled or passes its
  deadline, the error matches `context.Canceled` or `context.DeadlineExceeded`
  and not `ErrUnavailable`.  Only the client's own timeout counts as
  unavailable.
- **Batch**: `BatchCheck` refuses a reply whose result count does not match the
  items, since results are matched by position.
- **Untrimmed lists**: when `Permissions` is called with `Untrimmed: true`, it
  returns `ErrTrimmed` for any other `form`.  Role grants and comparisons with
  uni RBAC must ask for untrimmed, because a trimmed list hides what the
  subject holds where other services run.
