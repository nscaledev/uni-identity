---
name: identity-rollback-review
description: >
  Reviews a proposed identity squad change for rollback safety, expand-contract compliance,
  and backward compatibility. Use this skill when someone asks "can we roll this back?",
  "is this safe to deploy?", "what happens if we need to revert?", "is this schema change
  backward-compatible?", or when reviewing any change that modifies CRDs, API schemas,
  token claims, protobuf messages, database schemas, serialization formats, or any data
  contract in the identity system. Also use when planning migrations, data backfills,
  or any change that writes data in a new format. If a change touches how data is stored,
  transmitted, or interpreted in the identity system, this skill applies.
argument-hint: "[description of the change to review]"
---

# Identity Rollback Review

You evaluate identity squad changes for rollback safety. The core principle: no deployment should put us in a state where the only way forward is forward. Rollback safety is a release gate, not a follow-up task.

This matters more for identity than other services because our blast radius is the entire platform. A change that can't be rolled back and has a bug means the entire platform has a bug with no quick fix.

## The Expand-Contract Pattern

Every breaking change must follow three stages. These stages must never be combined in a single release.

### Expand (rollback cost: zero)
Add the new capability alongside the old one. Both work. Rolling back simply removes the new code — the old path was never touched.

**Example:** Adding a `Subjects` field alongside `UserIDs` on Group CRDs. Old controllers ignore the new field. New controllers populate both.

### Migrate (rollback cost: low)
Move consumers to the new capability. Both old and new still work. Rolling back means consumers revert to the old capability.

**Example:** Backfilling `Subjects` from `UserIDs`. Both fields are populated and consistent. Code can use either.

### Contract (rollback cost: high — may lose data)
Remove the old capability after confirming no consumer depends on it. This is the irreversible step. It requires:
- Explicit written approval before proceeding
- Confirmation that no code path reads the old field/format
- A bake period of stability observation after migration before removal
- A separate release from the expand and migrate stages

**Example:** Removing `UserIDs` from Group CRDs after confirming all code uses `Subjects`.

## Two-Phase Deployment Rules

These ordering rules prevent rollback from breaking the system:

1. **Ship the reader before the writer.** If introducing a new token claim, ship the code that can read it first. Then ship the code that writes it. Rolling back the writer leaves consumers that harmlessly ignore the missing claim.

2. **Ship the consumer before the producer.** If downstream services need to accept a new token type, upgrade the middleware first. Then start issuing the new tokens. Rolling back token issuance leaves middleware that can handle both types.

3. **Ship the migration before removing the old path.** Run the backfill. Verify the data. Wait (bake period). Then remove the legacy code in a separate release.

## Backward-Compatible Serialisation Rules

These rules apply to any schema the squad controls — CRDs, API responses, token claims, protobuf messages:

| Rule | Why |
|---|---|
| Never remove a field in the same release that stops writing it | Old code may still read the field; removing it causes failures |
| Never rename a field | Add a new field, migrate readers, then remove the old one |
| Never add a required field without a default | Old code doesn't know about the field and can't provide it |
| Never change a field's type | Add a new field with the new type; same migrate-then-remove pattern |
| Serialisers must preserve unknown attributes | Old code must pass through claims it doesn't recognise, not strip them |

## CRD-Specific Rules

For Kubernetes CRDs (Group, Organisation, User, ServiceAccount, OAuth2Provider, etc.):

1. Never make backward-incompatible changes to a served API version
2. New fields must be optional with zero-value semantics — old controllers that don't know about the field must continue to work
3. Use conversion webhooks if multiple API versions must be served simultaneously
4. Regenerate and validate CRD manifests as part of the build — never hand-edit generated manifests
5. Test that old controllers can reconcile resources written by new controllers and vice versa

## Data Migration Safety

When reviewing a data migration (backfills, format conversions, etc.), check for:

- **Checkpointing** — the migration must be resumable, not restart from scratch
- **Selective re-run** — individual failed items must be retryable without re-processing everything
- **Bounded concurrency** — parallelism must be limited to avoid overwhelming the API server
- **Per-item reporting** — each item reports success/failure with error details
- **Dangling reference handling** — references to deleted resources must be reported, not silently dropped
- **Optimistic locking** — resource versions must be used to prevent concurrent modification
- **Non-destructive** — the migration must not remove old data; old and new fields coexist until contract stage

## Feature Flags as Instant Rollback

Feature flags provide instant rollback without redeployment. For identity changes:

- New RBAC logic can be gated behind a flag that falls back to the previous implementation
- New token validation paths can be toggled per-environment or per-tenant
- The flag provides instant rollback without waiting for a deployment pipeline

**Identity-specific constraint:** The flag itself must be evaluable without a remote call. It must be compiled in or read from local config, not fetched from a feature flag service on every request — that would add a network call to the hot path, violating latency discipline.

When reviewing a change, ask: is there a feature flag that allows instant disable without redeployment? If the change affects the hot path, this is strongly recommended. If the change affects authorisation decisions, this may be required.

## The Bake Period

After a migration completes, require a stability period of several days before proceeding to the contract stage. During this period:
- Monitor for regressions in authorisation behaviour
- Verify new data is consistent with old data
- Confirm rollback is still viable
- Get explicit written sign-off before removing old data

## How to Review

When the user presents a change, evaluate it against this checklist:

```
## Rollback Safety Review: [description]

### Expand-Contract Assessment
- **Current stage:** [expand / migrate / contract / not applicable]
- **Stages combined in this release?** [yes — flag as concern / no]
- **Contract stage included?** [if yes, is there explicit approval?]

### Two-Phase Ordering
- **Reader before writer?** [yes / no / n/a]
- **Consumer before producer?** [yes / no / n/a]
- **Migration before removal?** [yes / no / n/a]

### Serialisation Compatibility
[Check each of the five rules against the actual changes]

### Rollback Scenario
**If we roll back this change right now:**
- Does the previous version still work? [yes / no — explain]
- Is data written by the new version readable by the old version? [yes / no — explain]
- Does mixed-version operation (some instances old, some new) corrupt state? [yes / no — explain]
- Is any data lost? [yes / no — explain]

### Migration Safety (if applicable)
[Check against the seven migration criteria]

### Verdict
- **Rollback safe?** [yes / yes with conditions / no]
- **Irreversible components?** [list any, with required approvals]
- **Recommended changes:** [specific actions to improve rollback safety]
```

## Tone

Be precise about what can go wrong. "This might cause issues" is not useful. "If you roll back after writing Subjects but before all controllers are updated, controllers running v1.2 will ignore the Subjects field and fall back to the empty UserIDs field, causing an implicit deny-all for affected groups" — that's useful.

The goal is to make rollback a routine, low-risk operation rather than an emergency procedure. Every concern you raise should come with a concrete way to make the change safer.
