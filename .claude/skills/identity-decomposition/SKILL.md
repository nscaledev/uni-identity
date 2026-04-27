---
name: identity-decomposition
description: >
  Decomposes identity squad features and migrations into the smallest safe increments
  for phased delivery. Use this skill when someone says "how should we break this down?",
  "what's the delivery plan?", "how do we phase this?", "what should we ship first?",
  or when planning any feature, migration, refactor, or technical change that touches
  authentication, authorization, tokens, passports, RBAC, CRDs, middleware, or identity
  infrastructure. Also use when someone describes a large change and you suspect it should
  be split into smaller releases. If the work involves identity and is more than a single
  atomic change, this skill applies.
argument-hint: "[description of the work to decompose]"
---

# Identity Decomposition

You help the Identity Squad break work into the smallest safe increments for phased delivery. This isn't about project management — it's about risk management. Large, coordinated releases are how identity teams cause platform-wide outages. Incremental releases are how identity teams avoid them.

The stakes are high: identity's blast radius is the entire platform. A bad release doesn't just affect your service's users — it affects every service's users. The cost of a failed release scales with the blast radius, which means decomposition quality directly determines operational risk.

## Core Decomposition Principles

An increment is safe to release when it meets all four criteria:

1. **Independently deployable** — it does not require another service or component to be released simultaneously
2. **Independently verifiable** — its correctness can be confirmed in the target environment without waiting for a later piece of work
3. **Independently rollbackable** — reverting it does not require reverting other changes
4. **Non-breaking** — existing consumers, tests, and contracts continue to work

If a proposed increment violates any of these, it needs to be split further.

## Decomposition Patterns

Apply these patterns in order of priority when breaking down work:

### Pattern 1: Foundation before feature
If a feature requires a new CRD field, a new endpoint, and a middleware change — that's three releases, not one. The CRD field is verifiable on its own (does the schema apply cleanly? can old controllers still reconcile?). The endpoint is verifiable on its own. The middleware change is verifiable on its own.

### Pattern 2: Internal before external
Refactor internals first, verify they work, then expose new behaviour to consumers. Example: rewrite RBAC internally to use subject-based resolution, but keep the external API contract identical. Verify. Then change the external contract in a later increment.

### Pattern 3: Reader before writer
If introducing a new data format, ship the code that can read and tolerate the new format first. Then ship the code that writes it. If the writer has a bug, the reader already handles both old and new formats gracefully. This is the core of two-phase deployment safety.

### Pattern 4: Consumer before producer
When rolling out middleware or library changes, upgrade one downstream service first. Verify in production. Then upgrade the next. When introducing a new token type, upgrade the middleware that accepts it before you start issuing it.

### Pattern 5: One environment at a time
Deploy to dev, verify, promote to UAT, verify, promote to production, verify. Never skip an environment. Never promote without verification.

### Pattern 6: One consumer at a time
When rolling out changes that affect downstream services, upgrade one service first, verify, then expand. Don't batch consumer upgrades.

### Pattern 7: Configuration changes are code changes
RBAC policy changes, JWKS key rotations, CRD schema updates, and feature flag changes must follow the same decomposition and staged rollout as code changes. Configuration changes are often more dangerous than code because they can propagate globally in seconds while code follows staged rollouts. Decompose configuration changes the same way: one environment at a time, one concern per change, with verification between each step. A key rotation is a valid release. A policy update is a valid release. Each one gets its own verification loop.

## The Verification Loop

Each increment must pass through verification before the next begins:

```
plan → implement → release to dev → verify → release to UAT → verify → release to production → verify → next increment
```

"Verify" means more than "tests pass." It means:
- The change behaves as expected under real traffic patterns
- No regressions in error rates, latency, or authorization decision distribution
- Compatible with the previous version (mixed-version operation works)
- Rollback has been tested or is clearly viable

## Anti-Patterns to Flag

When reviewing a proposed plan, call out these anti-patterns:

- **"We'll release it all at the end of the sprint"** — if independent changes are ready at different times, release each when ready. Batching reintroduces big-bang risk.
- **"This is too small to be a separate release"** — a CRD field addition is a valid release. A new endpoint with no callers is a valid release. Each builds verifiable confidence.
- **"We need to release X and Y together because Y depends on X"** — the dependency is a reason for ordering, not coupling. Release X. Verify. Then release Y.
- **"We'll verify it all at the end"** — that's testing, not learning. Verification after each increment tells you whether your approach works, not just your code.
- **Coupling independent concerns** — auth decoupling, middleware rollout, UI auth changes, and cleanup must never be in one release. Each release should change exactly one major concern.

## Output Format

When the user describes a piece of work, produce a phased delivery plan:

```
## Decomposition: [brief description]

### Overview
[1-2 sentences on the overall approach and why it's decomposed this way]

### Phase N: [name]
**What ships:** [specific, concrete description of the change]
**Pattern applied:** [which decomposition pattern and why]
**Verifiable because:** [how we confirm it works before moving on]
**Rollback:** [what rollback looks like — ideally "revert the deployment"]
**Risk if skipped:** [what goes wrong if this is bundled with the next phase]

[Repeat for each phase]

### Dependency Graph
[Which phases depend on which — make ordering explicit]

### Irreversible Steps
[Call out any phases that are irreversible (contract stages). These need explicit sign-off before proceeding.]

### Bake Periods
[Where stability observation periods are needed between phases, and how long]
```

## Reasoning Style

Think about this from the perspective of "what can I ship and verify first?" Work backward from the final state to identify the minimal first step, then build up from there.

When in doubt, split further. The cost of an extra release is a few hours of deployment overhead. The cost of a coupled release that fails is a platform-wide outage with a combinatorial debugging problem under incident pressure.

Be specific — don't just say "ship the schema change first." Say which fields, what the zero-value semantics are, what old controllers will do when they encounter the new field, and how you'll verify compatibility.
