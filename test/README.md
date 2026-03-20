# Identity Integration Tests

Identity now has a single main integration suite: `test/api`.

The suite can run in two modes:

1. **Per-PR kind CI**: the GitHub Actions integration workflow creates a fresh KinD cluster,
   deploys identity, creates fixtures, and runs `make test-api-ci`.
2. **Manual / triggered mode**: provide `test/.env` yourself and run the same `test/api` suite
   against an existing environment.

This keeps one test suite and two execution modes, rather than maintaining separate `api` and
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
```

In practice the workflow invokes the underlying scripts directly, but the behaviour is the same:

- create an isolated KinD cluster
- install cert-manager, ingress-nginx, and unikorn-core
- deploy identity with a random namespace and release name
- create fixtures via mTLS
- write `test/.env`
- run the main `test/api` suite

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

Optional variables for richer coverage:

- `ADMIN_AUTH_TOKEN`
- `USER_AUTH_TOKEN`
- `TEST_USER_SA_ID`
- `IDENTITY_CA_CERT`

Notes:

- `API_AUTH_TOKEN` remains the backward-compatible input for the main suite.
- `ADMIN_AUTH_TOKEN` is also accepted and is used by the KinD fixture flow.
- When `IDENTITY_CA_CERT` is set, the Make targets export `SSL_CERT_FILE` so Go HTTP clients trust
  the test CA issued by the KinD environment.

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

## Upgrade Path

The repository is in a transition from multiple test entry points toward one main way of running
integration coverage.

Current state:

- PR validation uses a fresh kind-backed deployment and runs `test/api`
- manual and legacy jobs can still provide `test/.env` and run `test/api`
- cluster creation remains `kind-cluster`; deployment and fixtures use neutral `integration-*` names

Target state:

- `test/api` is the only integration suite
- local development, PR CI, and manually triggered jobs all execute the same suite
- kind-backed deployment becomes the default execution model wherever practical
- remaining legacy naming is removed once downstream jobs have migrated
