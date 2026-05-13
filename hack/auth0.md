# Auth0 Token Fixtures Setup

This guide describes how the Auth0 token fixtures are produced for the
integration tests under `test/api/suites/passport_auth0_test.go`.

Most fixtures are minted on every run by `hack/ci/fixtures/main.go`; one
(`AUTH0_EXPIRED_JWT_TOKEN`) is seeded manually once via `hack/auth0/`.

## Prerequisites

- The identity server is running with Auth0 exchange flags configured:
  - `--auth0-issuer=https://<tenant>.auth0.com/`
  - `--auth0-audience=<primary-audience-identifier>`
  - `--auth0-opaque-fallback-enabled=true` (for the opaque fallback test)
- The primary Auth0 API exposes the `identity:token:exchange` scope.
- The minting client has been granted that scope on the primary audience.
- The minting client has the `password` and `password-realm` grants enabled
  on the Auth0 database connection used for fixture users.
- An active user mapped in identity user data, plus an inactive user, plus
  (optionally) the wrong-issuer tenant — all provisionable via the terraform
  in `terraform/`.

## Required Auth0 minting credentials

Export these in your shell (or write them into `test/.env.install`) **before**
running `make integration-fixtures`. The fixture script reads them, mints
fresh tokens, and writes the resulting `AUTH0_*` lines into `test/.env`.

```bash
AUTH0_DOMAIN=<tenant>.auth0.com
AUTH0_AUDIENCE=<primary-audience-identifier>
AUTH0_CLIENT_ID=<minting-client-id>
AUTH0_CLIENT_SECRET=<minting-client-secret>
AUTH0_USERNAME=<active-user-email>
AUTH0_PASSWORD=<active-user-password>
```

The mapped active user's email is also written as `AUTH0_EXPECTED_SUBJECT`,
which the tests assert against the minted passport's `sub`.

## Optional per-fixture credentials

Each block enables one additional fixture. Omit the block to leave its
`AUTH0_*_JWT_TOKEN` blank, in which case the matching Ginkgo case Skips.

Inactive-user fixture (rejection because identity has no active mapping):

```bash
AUTH0_INACTIVE_USERNAME=<inactive-user-email>
AUTH0_INACTIVE_PASSWORD=<inactive-user-password>
```

Wrong-audience fixture (same tenant, different `aud`):

```bash
AUTH0_WRONG_AUDIENCE=<other-audience-on-same-tenant>
```

Wrong-issuer fixture (separate tenant, mirrored user):

```bash
AUTH0_WRONG_ISSUER_DOMAIN=<other-tenant>.auth0.com
AUTH0_WRONG_ISSUER_CLIENT_ID=<minting-client-on-other-tenant>
AUTH0_WRONG_ISSUER_CLIENT_SECRET=<...>
```

Audience, realm, scope, username, and password are inherited from the primary
credentials. The wrong-issuer tenant must therefore expose an API with the
same `AUTH0_AUDIENCE` identifier (Auth0 audience identifiers are scoped per
tenant, so reusing the same URL string is fine) and have the same user
mirrored on the same DB connection name — otherwise the verifier would short-
circuit on the audience check before reaching the issuer check.

Overrides with sensible defaults:

```bash
AUTH0_REALM=Username-Password-Authentication
AUTH0_SCOPE="openid profile email identity:token:exchange"
```

## Expired-token fixture (one-time seed)

The verifier checks `aud` and `exp` against the same audience. To exercise the
expired path without short-circuiting on `aud`, the token must be minted
against the primary audience and then allowed to expire. Auth0 silently clamps
very short `token_lifetime` values up to ~300s, so it's simpler to mint once
and let it expire naturally.

```bash
echo "AUTH0_EXPIRED_JWT_TOKEN=$(go run ./hack/auth0)" >> test/.env.install
```

Then wait for the primary audience's `token_lifetime` to elapse (e.g. 15
minutes for the default 900s primary TTL). Once expired the token stays
expired indefinitely — until Auth0 rotates the tenant's signing key, at which
point re-mint.

`hack/auth0/` reads the same `AUTH0_DOMAIN`/`AUDIENCE`/`CLIENT_ID`/
`CLIENT_SECRET`/`USERNAME`/`PASSWORD` env vars listed above.

## Running the fixtures

```bash
make integration-install integration-fixtures
```

`integration-install` writes `test/.env.install` with cluster connection
details; `integration-fixtures` then sources that, runs the fixture script,
and writes `test/.env` containing both the in-cluster fixtures and the
minted Auth0 fixtures.

## Tokens written to `test/.env`

- `AUTH0_VALID_JWT_TOKEN` — primary audience, active user
- `AUTH0_INACTIVE_USER_JWT_TOKEN` — primary audience, inactive user
- `AUTH0_WRONG_AUDIENCE_JWT_TOKEN` — different audience on the same tenant
- `AUTH0_WRONG_ISSUER_JWT_TOKEN` — different tenant
- `AUTH0_OPAQUE_TOKEN` — opaque token (no `audience` requested)
- `AUTH0_EXPIRED_JWT_TOKEN` — passed through from the operator-seeded env
- `AUTH0_EXPECTED_SUBJECT` — `AUTH0_USERNAME` echoed back for assertion

## Safety notes

- Do not commit real tokens or client secrets. `test/.env` and
  `test/.env.install` are gitignored.
- Rotate credentials regularly in Auth0.
- The wrong-issuer tenant should not share a JWKS or trust path with the
  primary tenant.
