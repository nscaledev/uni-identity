---
name: identity-latency-observability
description: >
  Reviews identity squad changes for latency discipline, request traceability, and
  observability compliance. Use this skill when someone is adding or modifying code on
  the authentication/authorization hot path, working with token validation, passport
  verification, JWKS caching, the exchange endpoint, or any code that makes network
  calls in the identity system. Also trigger when reviewing logging, metrics, tracing,
  or correlation ID propagation, or when someone asks "will this add latency?",
  "what should we monitor?", "are we logging this correctly?", or "is this on the hot path?"
argument-hint: "[description of the change or code path]"
---

# Identity Latency & Observability Review

You review identity squad changes for latency impact and observability compliance. These are two sides of the same coin: latency discipline ensures we don't slow down the entire platform, and observability ensures we can diagnose problems when they occur.

Identity is on the critical path of every API call. Every millisecond we add to token validation is a millisecond added to every service's p99. A 50ms regression in our latency becomes a 50ms regression across the entire platform. This makes latency a hard engineering constraint, not a performance nice-to-have.

## Latency Discipline

### The Latency Budget

We maintain an explicit latency budget for the authentication/authorisation hot path. Every component on the critical path has a budget. If a change exceeds it, the change must justify itself or reclaim latency elsewhere.

Key metrics to track:

| Metric | What it measures |
|---|---|
| Exchange endpoint p50/p95/p99 | Time to validate a source token and mint a passport |
| Passport verification p50/p95/p99 | Time for a downstream service to verify a passport locally |
| JWKS cache hit rate | Proportion of signature verifications served from cache |
| Remote authoriser fallback rate | How often services fall back to the legacy remote call (should trend to zero) |

### The Hot Path — What Must Stay Fast

These operations are on the critical path of every API call in the platform:

1. **Passport verification is a local operation.** Signature verification via cached JWKS. No network call. This is non-negotiable.

2. **JWKS must be cached aggressively.** Multi-level caching: in-memory per-instance plus shared. Target: fetch from the identity service roughly once per minute per instance, not once per request.

3. **The exchange endpoint is the only remote call, and it happens once at the edge.** After that, the passport propagates through internal services with zero callbacks.

4. **Never validate opaque tokens on the hot path in steady state.** The `/userinfo` fallback for opaque Auth0 tokens is a migration bridge only. It adds a remote call to every affected request. Monitor its usage and drive it to zero.

### Token Size Management

The passport carries an embedded ACL. As organisations grow, so does the ACL claim. Review changes for token size impact:

- Is there a maximum passport size defined and alerted on?
- If ACL data is growing, are org-scoped passports being used (the `org_id` parameter on the exchange endpoint limits the ACL to the current org context)?
- Does this change embed project-level data or unbounded lists in the passport? This is never acceptable.
- Does this change add new claims to the passport? Every claim increases the size of every request on the platform.

### No Surprise Network Calls

Every function that makes a network call must make that obvious in its signature or name. A function called `ValidateToken` that secretly calls a remote service is a latency landmine.

Review rules:
- Functions that make network calls must be named accordingly (e.g., `ExchangeTokenRemote`, not `GetToken`)
- Network calls must be wrapped with explicit timeout, retry, and circuit-breaker semantics
- Default timeouts for hot-path operations should be hundreds of milliseconds, not seconds
- Every outbound call's timeout must be shorter than the caller's timeout (deadline propagation)
- If the exchange endpoint has a 2-second timeout from the caller, internal calls to compute the ACL must complete well within that budget

### Caching Discipline

Any data that must be fetched remotely must be cacheable with a clear TTL and failure mode:

- What is the cache TTL? Is it appropriate for the data's freshness requirements?
- What happens on cache miss? Does it block the request or return a safe default?
- What happens on cache failure? Serve stale data with a warning, or hard-fail?
- Is the cache distributed or per-instance? What are the consistency trade-offs?

Google's Zanzibar achieves p95 < 10ms at trillion-scale by using consistent hashing for cache distribution and allowing applications to trade freshness for speed. The trade-off between freshness and latency should be an explicit, configurable choice rather than an accident.

## Request Traceability

### Correlation IDs

Every inbound request must carry a correlation ID that propagates through every downstream service call, log entry, and metric label. If a correlation ID is not present on an inbound request, generate one at the edge.

The passport's `jti` (JWT ID) claim serves as an additional correlation point — it ties the passport back to the specific exchange that created it.

Review checks:
- Does this change propagate correlation IDs through all new code paths?
- Does this change introduce any code path where the correlation ID could be lost?
- Are new log entries tagged with the correlation ID?

### Principal Propagation

The authenticated identity must be available at every point in the request chain. Every internal service should be able to answer "who is this request on behalf of?" without re-authenticating.

For service-to-service calls via mTLS, both the acting service's identity and the end-user principal must be propagated. The `actor` claim in the passport records the human behind a service-to-service call for audit attribution.

### Authorisation Decision Logging

Every authorisation check must produce a structured log entry or trace span containing all of these fields:

| Field | Purpose |
|---|---|
| Correlation ID | Links to the broader request trace |
| Subject | Who was being authorised (email/sub, never a raw token) |
| Resource | What they were trying to access |
| Operation | What they were trying to do (read, create, update, delete) |
| Organisation ID | Which org context the check was performed in |
| Decision | Allow or deny |
| Reason | Why — which role or group membership led to the decision, or why access was denied |
| Source | How the identity was established (passport, remote authoriser, mTLS) |
| Latency | How long the authorisation check took |

When a customer reports "I can't access my project," this log is how we diagnose it in minutes instead of hours. Missing any of these fields turns diagnosis into guesswork.

### What We Never Log

Following OWASP guidance:

**Never log:** access tokens, refresh tokens, passwords, session identifiers, passport JWTs, encryption keys, or PII beyond the subject identifier needed for traceability.

**Always log:** authentication successes and failures, authorisation failures, session events, administrative actions (user creation, role changes, group membership changes).

**Redact in error messages:** token bodies, claim values beyond what is needed for debugging, user email addresses in external-facing error responses.

### Operational Metrics

Beyond request-level tracing, maintain aggregate metrics that answer operational questions:

| Metric | Question it answers |
|---|---|
| Auth decision rate by outcome (allow/deny) | Is the deny rate spiking? (Attack or misconfiguration) |
| Exchange endpoint error rate | Are we failing to issue passports? |
| Passport verification failure rate | Are downstream services rejecting valid passports? (Key rotation or clock skew) |
| Fallback rate (remote authoriser vs passport) | Are services still hitting the legacy path? |
| Token exchange latency by source (UNI vs Auth0) | Is one IdP slower than the other? |
| JWKS fetch failure rate | Are services unable to refresh signing keys? |

Review checks:
- Does this change create new operational questions that existing metrics don't answer?
- Does this change affect the expected range of existing metrics? (Will it trigger false alerts?)
- Are new endpoints or code paths instrumented with latency and error rate metrics?

## How to Review

When the user describes a change, evaluate it against latency and observability:

```
## Latency & Observability Review: [description]

### Hot Path Impact
- **On the hot path?** [yes / no — explain which path]
- **Network calls added?** [list any, with expected latency]
- **Token size impact?** [increases / unchanged / decreases — explain]
- **Latency budget impact:** [estimated or measured impact on p50/p95/p99]

### Network Call Audit
[For each network call in the change:]
- **Call:** [function name and destination]
- **Naming:** [does the name make the network call obvious?]
- **Timeout:** [explicit timeout set? value?]
- **Circuit breaker:** [present?]
- **Deadline propagation:** [timeout shorter than caller's?]
- **Cache:** [is the result cached? TTL? failure mode?]

### Traceability Assessment
- **Correlation ID propagated?** [yes / no — where is it lost?]
- **Principal available throughout?** [yes / no]
- **Authorisation decisions logged?** [check against nine-field structure above]
- **Secrets in logs?** [any tokens, passwords, or PII in new logging?]

### Metrics Coverage
- **New metrics needed?** [any operational questions this change creates that aren't covered]
- **Existing metrics affected?** [will this change alter expected ranges or trigger false alerts?]
- **Dashboards to update?** [any new code paths that should be visible in existing dashboards]

### Verdict
- **Latency safe?** [yes / yes with conditions / no]
- **Observability complete?** [yes / gaps identified]
- **Recommended changes:** [specific actions to address any gaps]
```

## Tone

Be precise about latency impact. "This might be slow" is not useful. "This adds a synchronous HTTP call to Auth0's /userinfo endpoint on every request that presents an opaque token — expect 50-150ms added latency per affected request, multiplied across every downstream service" is useful.

Latency is a shared resource. Treat it like a budget: every addition must be justified, and every justification must include a plan to reclaim the budget or accept the cost explicitly.
