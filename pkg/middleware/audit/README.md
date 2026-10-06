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

The digest and signature are applied in a `http.RoundTripper` rather than in `Emit`, so the digest
covers exactly the bytes that go on the wire. Re-serialising JSON to compute a digest is how a
signature that should match stops matching, because key order and whitespace are not stable across
encoders.

### Signing key rotation

The key id lives inside the signing secret alongside the key, never in configuration, and the sink
re-reads that secret on every delivery rather than caching it.

Together those two facts make rotation a single atomic write of one secret: no chart change, no
restart, and no window in which the key and the id disagree. That drift is worth preventing rather
than documenting, because signing under a stale id is not refused at the time; the collector
verifies asynchronously, so it surfaces later as a failed verification against records already sent.

For the same reason the signing key is not a cert-manager `Certificate`. There is no X.509 involved,
and an in-place renewal would replace the key while leaving the id untouched.

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

A request may make several decisions. Only those the handler marked as describing the request
itself become records; the checks it had to pass first, such as proving the caller may grant each
role they are adding to a group, are not separate events. A request acting on several resources
produces one record each.

A mutation that authorised something but never said what it was doing cannot be described. That is
reported as an `audit gap`, because silence is the failure this exists to prevent. The gap names the
endpoints that were checked and deliberately claims no operation: the HTTP method is the obvious
thing to reach for and it would be a lie, since a POST to an action sub-resource reads as a
creation, so a failed rotation would be reported as a create.

## Invariants

- Nothing in a record is derived from the request path.
- The stdout audit line is mandatory and its field set is fixed by the [platform specification][spec-audit].
  Configuring a collector adds a destination; it never removes or alters that line.
- `Sink.Emit` MUST NOT report failure and MUST NOT block indefinitely.
- The signing key and its key id MUST be read together from one secret, and MUST NOT be cached, or
  rotation needs a restart and the two can drift.
- Audit logging depends on trusted authorization context already being present.
- The package is focused on mutating operations rather than routine reads.
- Resource identification is derived from route structure and response metadata rather than custom
  per-handler audit code.
- The log record shape is intended to be stable enough for downstream audit processing.

## Caveats

- Global or unscoped calls may be intentionally skipped when the package cannot derive meaningful
  accountability context.
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
