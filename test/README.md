# Identity Integration Tests

Identity now has a single main integration suite: `test/api`.

The suite can run in three modes:

1. **Per-PR kind CI**: the GitHub Actions integration workflow creates a fresh KinD cluster,
   deploys identity, creates fixtures, and runs `make test-api-ci`.
2. **Manual / triggered mode**: provide `test/.env` yourself and run the same `test/api` suite
   against an existing environment.
3. **Nightly against staging**: the "API Tests" workflow runs the same suite against the identity
   version deployed on staging.

This keeps one test suite and several execution modes, rather than maintaining separate `api` and
`e2e` test trees.

## Current Execution Modes

### Per-PR kind CI

The integration workflow in
[`../.github/workflows/integration.yaml`](../.github/workflows/integration.yaml)
runs on every pull request and executes:

```sh
make kind-cluster
make integration-infra
make integration-install
make integration-fixtures
make test-api-ci
make test-api-no-skips
```

In practice the workflow invokes the underlying scripts directly, but the behaviour is the same:

- create an isolated KinD cluster
- install cert-manager, ingress-nginx, and unikorn-core
- deploy identity with a random namespace and release name
- create fixtures via mTLS
- write `test/.env`
- run the main `test/api` suite
- fail when any spec skipped: the fixtures supply every token, so a skip means a fixture broke

### Manual / triggered mode

This mode is for developers or manually triggered jobs that point at an existing environment.

Create `test/.env` yourself and run:

```sh
make test-api
```

Required variables:

- `IDENTITY_BASE_URL`
- `API_AUTH_TOKEN`
- `TEST_ORG_ID`
- `TEST_PROJECT_ID`
- `TEST_SUBJECT_SUFFIX` — ends the subject of every user the suite creates
  (`<spec key>-<suffix>@example.com`). Identity keeps every global user it creates and reuses one
  by subject, so on a long-lived environment use a fixed suffix; a new suffix adds one global user
  per created user, and nothing can delete them through the API. The kind fixtures write a random
  suffix for each run.

Optional variables for richer coverage:

- `ADMIN_AUTH_TOKEN`
- `USER_AUTH_TOKEN`
- `TEST_USER_SA_ID`
- `IDENTITY_CA_CERT`
- `PLATFORM_ADMIN_AUTH_TOKEN` — user token bound via legacy `platformAdministrators.subjects`
- `BINDING_ADMIN_AUTH_TOKEN` — user token bound via `globalRoleBindings`; also carries the
  global `identity:oauth2providers` writes no organization role holds, so the oauth2provider
  write specs skip without it.
- `PLATFORM_READER_AUTH_TOKEN` — token for a subject bound to the protected `platform-reader` role
  via an exact `uni` global role binding; the platform-reader suite skips without it.
- `TEST_PLATFORM_READER_ROLE_ID` — Role CRD ID of `platform-reader`, resolved by the fixtures from
  the cluster (protected roles are invisible via the API); the non-grantability test skips without
  it.
- `ACL_CACHE_TIMEOUT` — the server's `--acl-cache-timeout` (default `1m`). Specs that revoke a
  permission wait this long afterwards, so no replica is still serving a cached ACL that allows it.

Notes:

- `API_AUTH_TOKEN` remains the backward-compatible input for the main suite.
- `ADMIN_AUTH_TOKEN` is also accepted and is used by the KinD fixture flow.
- When `IDENTITY_CA_CERT` is set, the Make targets export `SSL_CERT_FILE` so Go HTTP clients trust
  the test CA issued by the KinD environment.
- Specs that install custom resources with no write API — roles, and groups carrying them — need
  cluster access via `KUBECONFIG`. They discover the identity and organization namespaces from
  `TEST_ORG_ID`, and skip when no kubeconfig is configured (an HTTP-API-only run); a present but
  broken `KUBECONFIG` fails fast.

### Nightly against staging

[`../.github/workflows/test-api.yaml`](../.github/workflows/test-api.yaml) runs at 05:00 UTC, a
slot no uni-region or uni-compute schedule uses, and calls
[`../.github/workflows/run-api-suite.yaml`](../.github/workflows/run-api-suite.yaml) for staging
(`uat`). The run:

- checks out the tag that staging reports at `/api/version`, so the tests match the deployed
  release;
- runs no test when that tag predates `make test-api-no-skips` (the nightly support check), says
  so in the job summary, and turns on by itself once staging runs a newer release;
- sweeps the test organization first (`go run ./hack/ci/sweep`, built from the workflow's own
  commit): it deletes `uniqueName` projects, OAuth2 providers, service accounts and groups, users
  with the run's subject suffix, and any `-updated` left on the organization name;
- uses organization-scoped standing fixtures (admin, user-role and auditor service accounts, a
  project, groups and a user, all named `identity-api-tests-*`), which the sweep never matches;
- has no privileged tokens and no kubeconfig, so the specs that need them skip, and the job
  summary lists every skip reason;
- reports to Slack and the test history; it opens no Linear issues.

The workflow's variables and secrets carry the `UAT_` prefix.

### Release evidence (smoke set)

A k8s-cluster-nks staging promotion sends a `release-evidence-request` dispatch, handled by
[`../.github/workflows/release-evidence-dispatch.yml`](../.github/workflows/release-evidence-dispatch.yml).
It refuses any component but `identity`, waits up to 15 minutes until staging reports the
requested version, checks the deployed version again, runs `make test-api-smoke` against staging,
checks the deployed version once more after the tests, and publishes one record per request at
`release-evidence/identity/<version>/<correlation_id>.json` on this repository's
`release-evidence` branch, also when the version check or the tests fail. A cancelled request
publishes nothing.

The record's `suite_result` is `success` only when the smoke set passed and the deployed version
was the requested version before and after it. A failed Slack or analysis step does not change
it, and an evidence run does not write to the test history.

`make test-api-smoke` runs the specs labelled `smoke`, in random order, and fails when none is
labelled or when any selected spec skips. The set is chosen by risk, then filtered: one to three
specs per business capability (version, authentication, token exchange, ACLs, authorization,
the group and service account create, update and delete flows, core reads, request validation),
each of which passed in every run of a sample of full staging runs, deletes anything it creates,
and takes under two seconds. A spec added to the set must meet the same rule.

The evidence attests those capabilities on the deployed version. It does not cover user,
project or organization writes (users share subjects with the nightly run, a project takes about
40 seconds, and the organization is shared), nor anything that needs a privileged token; the
kind run covers those.

## Local KinD Flow

For local kind or Colima usage, use the guide in
[`../docs/integration-testing.md`](../docs/integration-testing.md).

The recommended local command sequence is:

```sh
make integration-install integration-fixtures test-api-ci
```

Or all at once on KinD:

```sh
make integration-test
```

## Load Test

A manually triggered workflow, "Load Test", drives identity's hot paths in a throwaway kind cluster
and gates on how many API-server calls identity makes per request. See
[`load/README.md`](load/README.md).

## Upgrade Path

The repository is in a transition from multiple test entry points toward one main way of running
integration coverage.

Current state:

- PR validation uses a fresh kind-backed deployment and runs `test/api`
- a nightly run executes `test/api` against staging
- manual and legacy jobs can still provide `test/.env` and run `test/api`
- cluster creation remains `kind-cluster`; deployment and fixtures use neutral `integration-*` names

Target state:

- `test/api` is the only integration suite
- local development, PR CI, and manually triggered jobs all execute the same suite
- kind-backed deployment becomes the default execution model wherever practical
- remaining legacy naming is removed once downstream jobs have migrated
