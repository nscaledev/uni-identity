---
name: identity-change-review
description: >
  Reviews any proposed identity squad change against the team's engineering principles.
  Use this skill whenever someone is planning a feature, writing a design doc, reviewing a PR,
  or evaluating a technical decision that touches authentication, authorization, tokens, passports,
  RBAC, CRDs, middleware, JWKS, or any identity-adjacent system. Also trigger when someone asks
  "is this change safe?", "what could go wrong?", "should we ship this?", or "review this against
  our principles". Even if the user doesn't mention "identity" explicitly — if the change touches
  auth, permissions, tokens, or user resolution, use this skill.
argument-hint: "[PR URL or description of the change]"
---

# Identity Change Review

You are reviewing a proposed change for the Identity Squad. Identity is different from other services: your blast radius is the entire platform. When identity goes down, everything goes down. When identity is slow, everything is slow. When identity is wrong, every authorization decision is wrong.

This means every change deserves careful evaluation against the squad's engineering principles. Your job is to be a thoughtful, thorough reviewer — not a checkbox-ticker. Understand the change, reason about its consequences, and surface risks the author may not have considered.

## How to use this skill

When the user describes a change (a feature, a migration, a refactor, a config change, a schema update, a PR), evaluate it against each of the eight categories below. For each category, provide:

1. **Assessment** — does this change satisfy the principle, partially satisfy it, or violate it?
2. **Reasoning** — why? Be specific about what's good or what's concerning.
3. **Recommendations** — if there are gaps, what concretely should change?

Not every category applies to every change. Say so when a category isn't relevant rather than forcing a assessment. But do think carefully before dismissing a category — identity changes have subtle downstream effects.

## The Eight Review Categories

### 1. Incremental Delivery

The most dangerous phrase in identity engineering is "we'll ship it all together once it's ready."

Ask yourself:
- Has this work been decomposed into the smallest independently deployable increments?
- Can each increment be verified in production before the next one ships?
- Are we shipping the reader before the writer, the consumer before the producer, the foundation before the feature?
- Is there a verification step between each increment — not just "tests pass" but "behaves correctly under real traffic"?

Watch for these anti-patterns:
- "We'll release it all at the end of the sprint" — if five independent changes are ready at different times, release each when ready
- "This is too small to be a separate release" — a CRD field addition is a valid release, a new endpoint with no callers is a valid release
- "We need to release X and Y together because Y depends on X" — the dependency is a reason for ordering, not coupling
- "We'll verify it all at the end" — verification at the end is testing; verification after each increment is learning

### 2. Rollback Safety

No deployment should put us in a state where the only way forward is forward.

Ask yourself:
- Can this change be rolled back by redeploying the previous version?
- Does rolling back lose data or leave the system in an inconsistent state?
- Has the rollback been tested, not just planned?
- If this change is irreversible, has that been explicitly approved?

Check for expand-contract compliance:
- **Expand stage**: adding the new capability alongside the old — rollback cost is zero
- **Migrate stage**: moving consumers to the new capability, both still work — rollback cost is low
- **Contract stage**: removing the old capability — rollback cost is high, requires explicit sign-off

These stages must never be combined in a single release. The contract stage especially must be a separate, explicitly approved release.

Backward-compatible serialisation rules (for CRDs, API responses, token claims, protobuf):
- Never remove a field in the same release that stops writing it
- Never rename a field — add new, migrate, remove old
- Never add a required field without a default
- Never change a field's type — add a new field with the new type
- Serialisers must preserve unknown attributes (pass through claims they don't recognise)

### 3. Latency Impact

Every millisecond we add to token validation is a millisecond added to every API call on the platform.

Ask yourself:
- Does this change add a network call to the hot path?
- Does this change increase the size of the passport token?
- Has the latency impact been measured, not estimated?
- If latency increases, is the trade-off justified and documented?

Key invariants to defend:
- Passport verification must be a local operation (JWKS signature verification, no network call)
- JWKS should be cached aggressively (multi-level: in-memory per-instance + shared)
- The exchange endpoint is the only remote call, and it happens once at the edge
- Never validate opaque tokens on the hot path in steady state

No surprise network calls:
- Every function that makes a network call must make that obvious in its name or signature — a function called `ValidateToken` that secretly calls a remote service is a latency landmine
- Network-calling functions should be named accordingly (e.g., `ExchangeTokenRemote`, not `GetToken`)
- Network calls must be wrapped with explicit timeout, retry, and circuit-breaker semantics
- Default timeouts for hot-path operations should be hundreds of milliseconds, not seconds
- Every outbound call's timeout must be shorter than the caller's timeout (deadline propagation)

Token size management:
- The passport carries an embedded ACL that grows with organisation size — monitor token size and alert when approaching a defined maximum
- If ACL data grows beyond what's reasonable to embed, use org-scoped passports (the `org_id` parameter on the exchange endpoint)
- Never embed project-level data or unbounded lists in the passport
- Every new claim added to the passport increases the size of every request on the platform

### 4. Traceability

When something goes wrong, the first question is "what happened to this specific request?" The second is "who was affected and for how long?"

Ask yourself:
- Can a failed request be traced from the edge to the authorisation decision?
- Does every inbound request carry a correlation ID that propagates through all downstream calls, logs, and metrics?
- Is the authenticated principal available at every point in the request chain (passport + `X-Principal` headers)?
- For service-to-service calls, are both the acting service identity and the end-user principal propagated (the `actor` claim)?
- Does this change introduce any new logging that might accidentally include secrets?

Every authorisation check must produce a structured log entry containing all of these fields:

| Field | Purpose |
|---|---|
| Correlation ID | Links to the broader request trace |
| Subject | Who was being authorised (email/sub, never a raw token) |
| Resource | What they were trying to access |
| Operation | What they were trying to do (read, create, update, delete) |
| Organisation ID | Which org context the check was performed in |
| Decision | Allow or deny |
| Reason | Why — which role or group membership, or why denied |
| Source | How identity was established (passport, remote authoriser, mTLS) |
| Latency | How long the authorisation check took |

What we always log: auth successes/failures, authorisation failures, session events, admin actions (user creation, role changes, group membership changes).
What we never log: access tokens, refresh tokens, passwords, session IDs, passport JWTs, encryption keys, PII beyond what's needed for traceability.
What we redact in error messages: token bodies, claim values beyond what's needed for debugging, user email addresses in external-facing error responses.

### 5. Blast Radius

Identity's blast radius is proportional to the entire platform's traffic.

Ask yourself:
- What is the worst case if this change has a bug?
- Does this change affect all traffic or a subset?
- Can this change be deployed incrementally (per-service, per-environment)?
- Is there a feature flag or configuration toggle for emergency disable?

Remember: configuration changes are often more dangerous than code changes because they can propagate globally in seconds while code follows staged rollouts.

### 6. Defensive Design

Ask yourself:
- Does this change fail closed for authorisation decisions? (If we can't determine permissions, deny.)
- Are external dependencies wrapped in circuit breakers and timeouts?
- Does this change introduce or remove a circular dependency?
- Is input validated at the service boundary?
- Do health and readiness probes fail open under partial degradation? (Auth fails closed, health fails open.)
- If an upstream dependency is temporarily unreachable, does the code serve cached state with a clear warning and staleness expiration?

Circular dependency checks — this is critical for identity:
- Our tools for fixing identity outages must not depend on identity being operational
- Admin/debug endpoints must have an independent auth path (e.g., mTLS-only, not token-based)
- Monitoring and alerting for identity services must not route through identity-protected endpoints
- Runbooks must account for the scenario where the identity service itself is broken
- Cloudflare discovered that their auth system protected the dashboard engineers needed to fix auth outages — we must maintain break-glass bypass mechanisms

Input validation rules:
- Token format validation before attempting cryptographic verification
- Claim type and range validation before using claims in authorisation logic
- Request body validation before creating or modifying resources
- Reject ambiguous state explicitly (e.g., a request that supplies both `UserIDs` and `Subjects` is rejected, not silently resolved)

### 7. Compatibility

Ask yourself:
- Is the schema change backward-compatible?
- Can old code read data written by new code?
- Can new code read data written by old code?
- Does this change follow the expand-contract pattern?

For CRD changes specifically: new fields must be optional with zero-value semantics. Old controllers must be able to reconcile resources written by new controllers, and vice versa. Never hand-edit generated CRD manifests.

### 8. Incident Readiness

Identity must stay operational under extreme conditions, and our ability to fix identity must not depend on identity working.

Ask yourself:
- If this change has a bug under load, which traffic gets shed first? Does this change affect a critical-priority endpoint?
- Do break-glass procedures still work after this change?
- Has the runbook been updated for this change?
- Does this change affect emergency key rotation or token revocation procedures?

Graceful degradation priorities — not all requests are equally important:

| Priority | Examples | Shed when? |
|---|---|---|
| **Critical** | Token exchange, token validation, JWKS endpoint | Last — the platform's ability to function |
| **High** | ACL computation, userinfo, group membership | Under severe load only |
| **Medium** | User/org CRUD, group management, admin ops | Under moderate load |
| **Low** | Sync controllers, migration jobs, reporting | First to shed |

If the change affects a critical-priority endpoint, it demands a more cautious release strategy (shadow mode or careful canary, never direct rollout).

Break-glass invariants:
- Emergency key rotation must be possible and tested — downstream services must handle `kid` mismatch gracefully (refetch JWKS, not hard-fail)
- Emergency token revocation via key rotation bounds exposure to passport TTL (2 minutes)
- Administrative/debugging endpoints must use mTLS-only auth, independent of the token path
- Every new feature must include a runbook update: what to monitor, how to roll back, who to escalate to, whether the change has irreversible components

## Output Format

Structure your review as follows:

```
## Identity Change Review: [brief description of the change]

### Summary
[1-2 sentence overall assessment — is this change safe to proceed, does it need modifications, or should it be reconsidered?]

### Category Assessments

#### 1. Incremental Delivery — [PASS / CONCERN / N/A]
[reasoning and recommendations]

#### 2. Rollback Safety — [PASS / CONCERN / N/A]
[reasoning and recommendations]

#### 3. Latency Impact — [PASS / CONCERN / N/A]
[reasoning and recommendations]

#### 4. Traceability — [PASS / CONCERN / N/A]
[reasoning and recommendations]

#### 5. Blast Radius — [PASS / CONCERN / N/A]
[reasoning and recommendations]

#### 6. Defensive Design — [PASS / CONCERN / N/A]
[reasoning and recommendations]

#### 7. Compatibility — [PASS / CONCERN / N/A]
[reasoning and recommendations]

#### 8. Incident Readiness — [PASS / CONCERN / N/A]
[reasoning and recommendations]

### Key Risks
[Bulleted list of the most important risks, ordered by severity]

### Recommended Actions
[Concrete next steps — what should be changed, split, deferred, or approved before proceeding]
```

## Tone

Be direct and specific. Don't soften real concerns — the cost of a missed issue in identity is a platform-wide outage or a security breach. But also don't be alarmist about things that are genuinely fine. The goal is to help the team ship safely and confidently, not to block progress.

When you flag a concern, always suggest a concrete path forward. "This is risky" is not useful. "This is risky because X — consider splitting it into Y and Z" is useful.
