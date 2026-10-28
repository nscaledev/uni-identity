# `pkg/middleware/audit`

This package emits request-level audit records for state-changing API operations.

## Intent

`pkg/middleware/audit` is the accountability layer that turns normalized request context into audit
 log events.

It is intentionally selective rather than exhaustive. The goal is to record who changed what, in
 which scope, and with what result, rather than logging every routine read.

That selectivity is deliberate for two reasons:

- reduce signal-to-noise for the end user or auditor consuming the logs
- avoid paying unnecessary logging cost on hot API paths at high request volumes

Its main responsibilities are:

- log write-like API activity
- attach actor, component, scope, resource, operation, result, and client information
- rely on the normalized authorization context built earlier in the middleware stack
- optionally deliver the same record to an external collector

### Actor and client

`actor` is who made the call. `client` is what they made it with, taken from the request's
`User-Agent`. They are kept apart because they answer different questions, and a consumer needs the
second to attribute an event to a channel: the same person acting through the UI, the CLI or a
direct API call produces the same actor and three different clients.

`client` is a structure rather than a bare string so that a derived client type can be added beside
the raw agent later without changing the field's shape on the wire. It is omitted entirely, from
both the log line and the JSON body, when the request carried no `User-Agent`, so an absent client
is never reported as an empty one.

The [platform specification][spec-audit] fixes the fields an audit entry must carry; that is a
minimum, not a maximum, and `client` is additional to it.

[spec-audit]: https://github.com/nscaledev/uni-specifications/blob/main/SPECIFICATION.md#92-audit-logging

## What a record has to answer

A reader should not need another system to make sense of a record.

- **The time it happened.** The signature carries a creation time, but that is a property of the
  delivery: it moves on a retry, covers a batch rather than one event, and is gone once the record
  is stored. A party holding only the record must still be able to say when.
- **What was touched**, by name as well as identifier. Resolving an identifier means another
  lookup, and after a deletion there is nothing left to look up. The name comes from the response
  body, so operations that return none, notably deletes, do not carry one.
- **Where the request came from.** Behind a proxy the connection address is the proxy, so the
  forwarding headers are preferred where present.
- **Why it was allowed.** The checks a request passed before the operation itself are not separate
  events, they are the grounds for this one. Updating a group while adding roles records that a
  role grant was checked, which is the difference between a rename and an escalation.

## Delivery

Each audited request produces one `Record`, which is handed to every configured `Sink`.

The log sink is always present and is not optional: the stdout audit line is mandated by the
[platform specification][spec-audit], and it is also what remains if a remote sink cannot deliver. An
HTTPS sink is added when a collector is configured, and is an addition to that line, never a
replacement for it.

`Sink.Emit` returns no error. That is the mechanism by which "audit delivery never fails an API
request" holds at the call site, rather than being a rule every future caller has to remember. A
sink reports its own failures, logging the record alongside them so the event stays recoverable from
stdout. Panics are recovered per sink, so one misbehaving sink neither fails the request nor stops
the others.

### Why delivery is synchronous, and why there is no queue

`middleware.Capture` writes through to the real `ResponseWriter`, so by the time this middleware
runs the response bytes have already reached the client. A synchronous POST therefore costs the
caller nothing. Its only cost is holding the handler goroutine open, which is what the per-delivery
timeout bounds; without that timeout an unresponsive collector becomes an unbounded goroutine
pile-up.

That is the whole reason no queue is needed here. Durability, batching and retry are deliberately
absent, and each of them retrofits as a decorator over the HTTPS sink satisfying the same
one-method interface, with no change to the middleware.

If retry is ever added it MUST re-sign: a fresh nonce, a fresh timestamp and a new signature. A
byte-for-byte resend is recorded by the collector as a replay.

### What the HTTPS sink sends

The body is the bare `Record` as JSON, one record per request. Three independent mechanisms protect
it, because each covers something the others cannot:

- **Mutual TLS** proves who connected. The certificate is issued by the collector's authority from a
  CSR we generate, so it is deliberately not the mTLS identity used between unikorn services.
- **An RFC 9421 signature** over the body's digest proves who produced it, to a third party, later.
  Signing is [`github.com/yaronf/httpsign`](https://github.com/yaronf/httpsign) rather than our own
  code: the signature is evidence, and a conforming implementation others can check it with is
  worth more than one we maintain. The tests verify with that library's verifier rather than with
  our own arithmetic, so a mistake cannot agree with itself.
- **A nonce and timestamp** in the signature parameters let the collector reject replays.
- **A bearer token**, when the collector requires one, gates admission at its edge.

The token is not redundant with the signature, and neither substitutes for the other. The
collector's edge can compute an HMAC but cannot verify an asymmetric signature, so the token is the
only thing that can refuse a request at the door; without it anyone reaching the endpoint could post
arbitrary volume and it would all be stored until a downstream pass noticed. The signature is
checked later, away from the request path, and is the only thing that attests to who produced a
body, which a shared secret cannot do because the collector holds a copy of it.

The token is covered by the signature. It is a credential rather than a description of the record,
which is an argument for leaving it out, but not a good one: the collector looks the token up per
path, so an unsigned credential lets a captured body and signature be re-posted under a different
token, into a different stream, still verifying as ours. Covering it binds the two. RFC 9421 section
7.2.1 asks for as much of the message as possible to be signed and names only components that
intermediaries rewrite — `Via`, `Forwarded` — as the exceptions; section 3.2.1 uses `Authorization`
itself as its example of a field an application requires to be signed.

The consequence is an ordering constraint: the header is attached before signing, not after. A test
tampers with the credential on a captured request and asserts verification fails.

It is sent as `Authorization: Bearer`, which the collector accepts interchangeably with its own
`X-Streams-Token`; RFC 6648 deprecates `X-` prefixes and RFC 6750 standardises this one.

The covered set therefore differs between a deployment with a token and one without, which is
exactly what `Signature-Input` exists to declare.

The digest and signature are applied in a `http.RoundTripper` rather than in `Emit`, so the digest
covers exactly the bytes that go on the wire. Re-serialising JSON to compute a digest is how a
signature that should match stops matching, because key order and whitespace are not stable across
encoders.

### Credential rotation

The key id lives inside the signing secret alongside the key, never in configuration, and the sink
re-reads that secret on every delivery rather than caching it.

Together those two facts make rotation a single atomic write of one secret: no chart change, no
restart, and no window in which the key and the id disagree. That drift is worth preventing rather
than documenting, because signing under a stale id is not refused at the time; the collector
verifies asynchronously, so it surfaces later as a failed verification against records already sent.

For the same reason the signing key is not a cert-manager `Certificate`. There is no X.509 involved,
and an in-place renewal would replace the key while leaving the id untouched.

The token is re-read per delivery on the same basis, so rotating it is also a write to one secret.

## Where a record comes from

Everything in a record comes from the authorization decision the handler made, not from the
request's URL.

The URL was never a dependable source. v1 APIs happened to carry the organisation and project in
the path and v2 APIs do not, so scope was already unrecoverable there. Worse, the resource was
derived by matching a path ending in an identifier, and anything that did not match that shape was
dropped in silence: changing an organisation's quotas produced no record at all, and rotating a
service account credential was recorded against a resource type of `rotate`.

A missing entry in an audit log is not a gap, it is evidence that something did not happen. Guessing
from the request's shape produced both missing and wrong entries, which is why it is gone.

The decision supplies the scope, the resource type, the resource identifier and the action. One
exception remains: a create is authorised before the resource exists, so its identifier is still
read from the response body.

Every authenticated mutation produces exactly one record, whatever the outcome, and the status
says whether it happened. The record is built from the request decision, the one decision that
describes the request (see [`pkg/authz`](../../authz/README.md)); the checks it had to pass first,
such as proving the caller may grant each role they are adding to a group, are not separate events,
and appear as grants only when the request succeeded.

| Outcome | Verb, resource | Scope | Status |
|---|---|---|---|
| allowed | from the decision | from the check | 2xx |
| allowed, failed later | from the decision | from the check | the error |
| refused by its own check | from the decision | from the check | 403 |
| failed before its check (not found, dependency refused) | from the declaration | absent | the error |
| rejected before any handler (validation, ACL lookup) | absent | absent | the error |

A request nothing described still gets a record, with the caller, the outcome and what the server
matched it to, and no operation: the HTTP method is the obvious thing to reach for and it would be
a lie, since a POST to an action sub-resource reads as a creation, so a failed rotation would be
reported as a create. Unknown parts are absent rather than empty, so unknown never reads as blank.

Every record carries `request`: the method, the route template the server matched from its own
schema, and the trace ID that joins the record to the error the caller was given and to the
server's logs. The route is never the path the caller sent; that is the caller's text, can be any
length, and can carry another tenant's identifiers.

A request that succeeded without its own check ever running is a handler that failed to describe
itself, and is reported as an `audit defect`, as is a check naming something other than what the
handler declared.

### Running outermost

The validator authenticates before it validates parameters and body, and stores the caller in a
holder this middleware puts in the context, so audit learns who made a request even when it runs
outside the validator and the validator rejects it. Run inside the validator, audit never sees
those rejections. The holder is optional: audit falls back to the caller in the request context, so
a service changes nothing until it moves audit outermost. An unauthenticated request has nobody to
hold to account and is not recorded.

A service moves audit outermost by listing it after the validator in its generated router's
middleware list, which wraps in list order. Identity itself has not moved yet, so in identity a
request the validator rejects is still not recorded.

## Invariants

- Nothing in a record is derived from the request path.
- The stdout audit line is mandatory and its field set is fixed by the [platform specification][spec-audit].
  Configuring a collector adds a destination; it never removes or alters that line.
- `Sink.Emit` MUST NOT report failure and MUST NOT block indefinitely.
- Delivery MUST NOT inherit the request's cancellation. `net/http` cancels a request's context when
  the client closes the connection, and the response has already been written by the time a sink
  runs, so a caller that reads its response and exits would cancel the POST in flight. The record
  would survive on stdout and nowhere else, which is the failure the collector exists to prevent.
  `context.WithoutCancel` keeps the values and the per-delivery timeout.
- The signed `@path` MUST equal what goes on the wire. A host configured without a path leaves
  `URL.Path` empty while Go sends `POST / HTTP/1.1`, so a conforming collector derives `/`, the
  signature does not verify, and every record is rejected for the life of the process. The
  transport normalises it, so the guarantee does not depend on how an operator writes the host.
- A verification test MUST rebuild the request from what the collector received, never from the URL
  the client was given. Rebuilding from the sender makes the derived components agree with the
  signature by construction, and the test then passes whatever they were — which is how the empty
  `@path` reached a release.
- The bearer token MUST be attached before the request is signed, and MUST be covered by the
  signature. Attaching it afterwards still sends a valid request, so only a test that tampers with
  the credential and expects verification to fail catches the mistake.
- The sink MUST NOT follow redirects. Credentials are attached per hop by the `RoundTripper`, so
  `net/http`'s own rule of stripping `Authorization` across hosts does not apply: each hop would be
  freshly signed and freshly credentialed, handing the token to wherever the collector pointed us.
- Either half of a credential's namespace/name pair MUST be treated as a credential the operator
  intended. The chart emits each flag independently, so a half-configured one is reachable from
  values, and ignoring it starts a service that is refused every record for the life of the pod.
- A credential MUST be trimmed before it is checked for emptiness, not after. A secret holding only
  a newline otherwise passes, and is then sent as an empty token or an empty `keyid`.
- A configured token that cannot be read MUST fail startup. A collector that requires one refuses
  every record without it, so continuing would produce a service that delivers nothing.
- The signing key and its key id MUST be read together from one secret, and MUST NOT be cached, or
  rotation needs a restart and the two can drift.
- Audit logging depends on trusted authorization context already being present.
- The package is focused on mutating operations rather than routine reads.
- A resource is identified from the authorization decision, not from the route. The decision names
  the resource type, the object and the action; the response body supplies an identifier only for a
  create, which is the one fact a decision cannot carry because the resource does not exist when it
  is authorised. An earlier version read the route instead, which recorded nothing for a path not
  ending in an identifier and named a sub-resource rather than the thing being changed.
- An authenticated mutation MUST produce exactly one record, whether or not anything was checked or
  allowed. A denial is the event an auditor most wants, and a retried check is still one request.
- Reads get no recorder, so a list filtering out what the caller may not see costs nothing.
- The log record shape is intended to be stable enough for downstream audit processing.

## Caveats

- Unauthenticated calls are skipped: there is no caller to hold to account.
- A refused create records the scope the caller named, which nothing confirmed. Organisation-scoped
  tokens will make a cross-organisation request fail authentication instead.
- A path parameter that fails to parse is rejected by the generated router before any middleware
  runs, and is not recorded.
- A service still using the older gates for its own operations, which record only preconditions,
  gets records with no verb or scope, and an `audit defect` on every success, until it migrates to
  the explicit form.
- The package depends on route shape and response structure matching the expected API patterns.
- If upstream middleware fails to populate authorization or route context correctly, audit quality
  degrades silently.

## Related Documentation

- [`pkg/middleware/openapi`](../openapi/README.md), which assembles the request context this package
  depends on
- [`pkg/middleware/authorization`](../authorization/README.md), which carries the actor facts used
  for audit attribution
- [`pkg/principal`](../../principal/README.md), which explains how delegated identity and attribution
  concepts relate to downstream accountability
