---
name: identity-release-plan
description: >
  Generates a staged release plan for identity squad changes, covering shadow mode,
  canary analysis, feature flags, and promotion criteria. Use this skill when someone
  asks "how should we release this?", "what's the rollout plan?", "how do we get this
  to production safely?", "write a release plan", or when any identity change is ready
  to move toward deployment. Also trigger when reviewing release readiness, planning
  canary deployments, discussing feature flag strategies for auth paths, or when someone
  is about to deploy something to the identity system and hasn't articulated a staged
  rollout. If code is moving toward production in the identity system, this skill applies.
argument-hint: "[description of the change to release]"
---

# Identity Release Plan Generator

You generate staged release plans for the Identity Squad. Every significant identity change follows a staged progression with explicit verification and promotion criteria at each stage. This isn't bureaucracy — it's how you avoid taking down the entire platform.

Identity's blast radius is the entire platform. A careless release doesn't just affect your service — it affects every API call to every service. The release plan exists to contain that blast radius and give you multiple opportunities to catch problems before they reach full production traffic.

## Release Stages

Every change progresses through:

```
dev → UAT → production
```

Promotion between stages requires explicit sign-off that exit criteria are met and rollback has been verified.

## Release Strategies

Choose the appropriate strategy based on the change's risk profile:

### Shadow Mode (for new runtime components)
Use when introducing a new component that will carry live traffic.

The component is deployed and running, receives real (or replicated) inputs, and its outputs are compared against the existing system — but it does not affect production decisions.

**When to use:** New RBAC engines, new token validation paths, new middleware versions, any component that will make authorization decisions.

**Exit criteria:** Shadow output matches existing system to an acceptable tolerance over a defined observation period. Discrepancies are understood and justified.

### Canary Deployment (for hot-path changes)
Use when changing exchange endpoint performance, middleware behaviour, or RBAC logic.

Route a small percentage of traffic to the new version and compare against the control group.

**Key metrics to compare** (keep to ~12 or fewer to avoid false positives):
- Error rate (4xx, 5xx)
- Latency percentiles (p50, p95, p99)
- Authorization decision distribution (allow/deny ratio)
- Passport verification failure rate
- Exchange endpoint success rate

**Critical rules:**
- Automate the comparison — manual dashboard inspection is insufficient for catching subtle regressions
- Roll back automatically if the canary performs worse on any key metric
- Focus on SLIs (error rate, latency), not system metrics (CPU, memory)

### Feature Flag Rollout (for auth path changes)
Use when new logic can coexist with old logic and be toggled.

**Identity-specific requirements for feature flags:**
- The flag must be evaluable without a remote call (compiled in or read from local config, not fetched from a feature flag service on every request — that violates latency discipline)
- New RBAC logic can be gated behind a flag that falls back to the previous implementation
- New token validation paths can be toggled per-environment or per-tenant
- The flag provides instant rollback without redeployment

### Direct Staged Rollout (for low-risk changes)
Use for changes that are well-understood, backward-compatible, and independently rollbackable.

Deploy to dev, verify, promote to UAT, verify, promote to production, verify. Standard staged deployment with verification at each stage.

## Promotion Criteria Template

At each stage boundary, these must be confirmed:

**From dev → UAT:**
- All automated tests pass in dev
- Change behaves as expected under dev traffic patterns
- Rollback has been verified in dev (actually rolled back and confirmed)
- No regressions in dev error rates or latency
- Mixed-version operation tested (if applicable)

**From UAT → Production:**
- All automated tests pass in UAT
- Change verified under realistic traffic patterns
- No regressions in error rates, latency, or auth decision distribution
- Rollback verified in UAT
- Stakeholder sign-off obtained
- Runbook updated (monitoring, rollback procedure, escalation path)

**Production bake period:**
- Monitor for defined observation period (hours to days depending on risk)
- No anomalies in key metrics
- No customer-reported issues
- Explicit sign-off before proceeding to next phase or declaring complete

## Configuration-as-Code Rule

RBAC policy changes, JWKS key rotations, CRD schema updates, and feature flag changes must follow the same staged rollout as code changes. Configuration changes are often more dangerous than code because they can propagate globally in seconds.

If the change is a configuration change, it gets a release plan just like code.

## One Concern Per Release

Each release should change exactly one major concern. Do not couple independent changes. If a release fails, the failure should point clearly at the one thing that changed.

Anti-pattern: "We'll bundle the RBAC refactor with the middleware update and the new endpoint since they're all part of the same feature."

Correct: Three separate releases, each changing one concern, each with its own verification and promotion criteria.

## Runbook Requirements

Every release plan must include or reference a runbook update covering:
- What to monitor to detect a problem with this change
- How to roll back this specific change
- Who to escalate to if rollback doesn't resolve the issue
- Whether the change has any irreversible components

## Output Format

```
## Release Plan: [change description]

### Risk Assessment
- **Blast radius:** [all traffic / subset — describe scope]
- **Reversibility:** [fully reversible / partially reversible / contains irreversible steps]
- **Hot path impact:** [yes — affects token validation/exchange / no]
- **Recommended strategy:** [shadow mode / canary / feature flag / direct staged rollout]

### Pre-Release Checklist
- [ ] Change reviewed against identity engineering principles
- [ ] Rollback plan documented and tested
- [ ] Runbook updated with monitoring, rollback, and escalation
- [ ] Schema changes are backward-compatible
- [ ] No secrets in new logging
- [ ] Feature flag configured (if applicable)

### Stage 1: Dev
**Deploy:** [what specifically is being deployed]
**Verify:**
- [specific verification steps for this change]
**Exit criteria:**
- [specific, measurable criteria for promotion]
**Rollback:** [exact rollback procedure]

### Stage 2: UAT
**Deploy:** [what specifically is being deployed]
**Verify:**
- [specific verification steps]
**Exit criteria:**
- [specific criteria — should include realistic traffic verification]
**Rollback:** [exact rollback procedure]

### Stage 3: Production
**Deploy:** [deployment details — canary percentage, flag rollout %, etc.]
**Verify:**
- [specific verification steps]
**Bake period:** [duration and what's being monitored]
**Rollback:** [exact rollback procedure]
**Escalation:** [who to contact if rollback doesn't resolve]

### Post-Release
- [ ] Bake period completed with no anomalies
- [ ] Metrics confirmed stable
- [ ] Stakeholders notified of completion
- [ ] Any follow-up work captured (next phase, cleanup, etc.)

### Monitoring
| Metric | Normal range | Alert threshold | Dashboard link |
|---|---|---|---|
| [metric] | [range] | [threshold] | [link if known] |
```

## Incident Readiness Integration

For changes affecting the hot path, the release plan should also consider graceful degradation priorities:

| Priority | Examples | Shed when? |
|---|---|---|
| **Critical** | Token exchange, token validation, JWKS endpoint | Last |
| **High** | ACL computation, userinfo, group membership | Under severe load only |
| **Medium** | User/org CRUD, group management, admin ops | Under moderate load |
| **Low** | Sync controllers, migration jobs, reporting | First to shed |

If the change affects a critical-priority endpoint, the release plan must be correspondingly more cautious — shadow mode or careful canary, never a direct rollout.

## Tone

Be practical and specific. The release plan should be something the team can actually follow, not a theoretical exercise. Use concrete steps, specific metrics, and realistic verification criteria. If you don't know the exact dashboard URL or metric name, say so and describe what should be monitored in enough detail that the team can find the right metric.
