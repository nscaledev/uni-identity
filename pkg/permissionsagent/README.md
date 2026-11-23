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
| Permissions | `POST /v1/permissions` | what a subject holds in one organization (reads only) |
| Status | `GET /v1/status` | agent version, copy and policy versions, copy age, own region |

- Every check and list request names the `subject` (required) and may name an
  `actor`, the principal (for example a service account) acting on the
  subject's behalf, always in the JSON body.  A subject can be an email
  address, so it never goes in a URL, an access log or error text.
- With an actor, a check is allowed only when both the subject and the actor
  are allowed, and the list is the intersection of what each holds.  The actor
  can only narrow an answer.
- Subject and actor format:
  - a user is the identity provider's subject identifier for that user, that
    is the `sub` claim the caller verified
  - a service account is `serviceaccount:<id>`
- `subject` and `actor` must not be empty; an empty value is 400.  The client
  also refuses, before calling: whitespace only, control characters, over 512
  bytes, or `serviceaccount:` with no ID.
- An item is `kind` + `action` (both required), with an optional
  `organizationId` and `projectId`.  No organization means a global question;
  an organization and no project means org-wide.  `projectId` requires
  `organizationId`.
- A batch holds 1 to 100 items.  `results[i]` answers `checks[i]`.  One
  invalid item fails the whole batch with 400.
- Each list entry has `scope`: `global`, `organization` or `project`.
  `projectId` is set only for `project`.
- A denied item is `allowed: false` with 200.  A subject with no access in the
  organization gets 200 and an empty list.  401 and 403 are about the caller,
  never the subject.
- JSON fields are camelCase, like uni-identity's own API.
  Error bodies use the core error schema.
- Paths carry the version.  Within `v1`, fields are only ever added, so the
  client ignores fields it does not know.

### Region trimming

- `/v1/check` does not use region: the answer is the same in every region.
- `/v1/permissions` is trimmed to one region by default: services the region does
  not run are left out.  `regionId` names the region; without it the agent's
  own region is used.
- `untrimmed: true` lists every service.  It cannot be combined with `regionId`.
- The response field `form` is `trimmed` or `untrimmed`.
- An unknown `regionId`, or `untrimmed: true` with `regionId`, returns 400.

## Caller Authentication

- The caller authenticates to the agent as itself, never with the subject's
  access token.
- The agent rejects a request with no caller credentials, or bad ones, with 401
  (`ErrUnauthorized`).
- The agent accepts only callers it is configured to trust.  Valid credentials
  for any other principal, including a user's own access token from the same
  issuer, get 403 (`ErrForbidden`).
- The agent takes `subject` and `actor` as given.  Callers must take them from
  an identity they have already verified, never from request input.
- `Options.TokenSource` gives the calling service's own bearer token.  It is
  called on every request, so it can refresh the token.  `StaticToken` wraps a
  fixed one.
  - A source error is `ErrUnavailable`, with none of the source's error text.
  - An empty token is `ErrUnauthorized`, and nothing is sent.
- `New` refuses a token source with an `http://` URL unless
  `Options.AllowInsecureHTTP` is set.
- For mTLS, pass an `Options.HTTPClient` set up with the client certificate.
  The agent deployment decides whether it needs the token, the certificate or
  both.  Leave `Options.TokenSource` nil only when the certificate alone is
  enough.

## Client Behaviour

- **Timeout**: each call is bounded by `Options.Timeout` (default 250ms).
- **HTTP client**: with no `Options.HTTPClient`, the client uses its own
  transport (cloned from `http.DefaultTransport`, 32 idle connections per
  host) and does not follow redirects; a 3xx is `ErrServer`.
- **Reply size**: bodies over 8 MiB are `ErrResponse`.
- **Errors**: every failure matches one sentinel with `errors.Is`.  Callers that
  enforce must treat any error as a denial.

  | Error | Meaning |
  |---|---|
  | `ErrInvalidOptions` | `New` refused the options: bad URL, or a token over `http://` without `AllowInsecureHTTP` |
  | `ErrInvalidInput` | refused locally, agent not called: bad subject or actor, bad item, no organization for a list, empty batch, more than 100 items |
  | `ErrBadRequest` | 400 from the agent |
  | `ErrUnauthorized` | 401: no caller credentials, or bad ones; or the token source gave an empty token |
  | `ErrForbidden` | 403: caller authenticated but not trusted by this agent |
  | `ErrUnavailable` | agent unreachable, `Options.Timeout` hit, token source failed, or 502/503/504; 503 means no fresh copy |
  | `ErrServer` | any other error status |
  | `ErrResponse` | reply does not match the contract or the request (see below) |
  | `ErrTrimmed` | untrimmed list asked for, trimmed list returned |

- **Caller context**: if the caller's own context is cancelled or passes its
  deadline, the error matches `context.Canceled` or `context.DeadlineExceeded`
  and not `ErrUnavailable`.  Only the client's own timeout counts as
  unavailable.  A client timeout matches both `ErrUnavailable` and
  `context.DeadlineExceeded`, so check `ErrUnavailable` first.
- **Error text**: errors never hold the subject, actor or token.
  `Error.Description` has them replaced if the agent echoes them.
  `Error.Error()` drops control characters and caps the description at 256
  characters.  Transport errors drop the URL's query and user info.
- **Reply checks** (`ErrResponse`):
  - any reply: over 8 MiB, not JSON, or JSON `null`
  - check and batch: a result with no `allowed`
  - batch: a result count that does not match the items, since results are
    matched by position
  - list: `organizationId` is not the one asked for; a `project` entry with no
    `projectId`; a `global` or `organization` entry with a `projectId`; an
    unknown `scope`
- **Untrimmed lists**: when `Permissions` is asked for `Untrimmed: true`, it
  returns `ErrTrimmed` for any other `form`.  Role grants and comparisons with
  uni RBAC must ask for untrimmed, because a trimmed list hides what the
  subject holds where other services run.
