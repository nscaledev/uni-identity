# hack/ci — Composable CI Scripts

This directory contains the integration test infrastructure for identity. The scripts follow
the **composable install model**: each service defines its own `hack/ci/install` unit, and
higher-level services call it directly to deploy dependencies. Fix once, fix everywhere.

## Scripts

| Script | Called by | Purpose |
|--------|-----------|---------|
| `setup-infra` | CI workflow, `make integration-infra` | Installs cluster-level prerequisites (cert-manager, ingress-nginx, unikorn-core). Idempotent. |
| `install` | CI workflow, `make integration-install`, downstream services | Deploys identity into a running cluster with a given namespace and release name. Outputs a `.env` fragment to stdout. |
| `wait-policies` | `make integration-install` (after `install`) | Blocks until the policy controller has published the Cerbos policy store AND the PDP sidecar verifiably loaded it. Without it, shadow-mode traffic during the empty-store window logs false divergence and poisons the gate. |
| `fixtures/main.go` | CI workflow, `make integration-fixtures` | Creates test resources via the identity API using mTLS. Outputs a `.env` fragment to stdout. |
| `divergence-gate` | CI workflow, `make integration-divergence-gate` | Fails if the shadow comparator logged ANY `cerbos shadow divergence` during the run; prints (but tolerates) `cerbos shadow evaluation failure` lines and asserts the server never restarted. Run after the API suite, **before** `decision-flip`. Zero divergence covers identity-served kinds, non-impersonated traffic only: the comparator covers impersonated requests since A14, but the kind fixtures send no `X-Impersonate` traffic (follow-up: fixtures exercising impersonation). |
| `decision-flip` | CI workflow, `make integration-decision-flip` | Applies a Role CR + kubectl group rebind and asserts a live decision flips 403→200 on both engines, then that shadow divergence ceases. Deliberately opens a transient divergence window — must run **after** the gate. |

## Output contracts

### `install` stdout

```
IDENTITY_BASE_URL=https://identity-<suffix>.<ingress-ip>.nip.io
IDENTITY_NAMESPACE=unikorn-identity-<suffix>
IDENTITY_RELEASE=identity-<suffix>
IDENTITY_CA_CERT=/path/to/hack/ci/ca-bundle.pem
```

Redirect to a file (`> test/.env.install`) and source it before running fixtures.

### `fixtures` stdout

```
IDENTITY_BASE_URL=https://identity-<suffix>.<ingress-ip>.nip.io
IDENTITY_CA_CERT=/absolute/path/to/hack/ci/ca-bundle.pem
TEST_ORG_ID=<uuid>
TEST_PROJECT_ID=<uuid>
TEST_ADMIN_GROUP_ID=<uuid>
TEST_USER_GROUP_ID=<uuid>
TEST_ADMIN_SA_ID=<uuid>
TEST_USER_SA_ID=<uuid>
ADMIN_AUTH_TOKEN=<jwt>   # administrator role — full org-level identity CRUD
USER_AUTH_TOKEN=<jwt>    # user role — project-scoped access
```

Redirect to `test/.env`. The Ginkgo e2e suite reads this file via `viper`.

## Files

| File | Purpose |
|------|---------|
| `kind-config.yaml` | KinD cluster config (ingress-ready node label) |
| `test-values.yaml` | Helm value overrides for CI: pre-configures the `ci-fixtures` system account, runs the server in shadow authorization mode (feeding `divergence-gate`), and injects open-vocabulary `radar:*`/`envir:*` roles transcribed from the real deployment repo so the whole generate→compile→publish pipeline is exercised on them |
| `ca-bundle.pem` | CA cert extracted by `setup-infra` — **gitignored**, regenerated per cluster |

## Running locally

**Prerequisites:** `kind`, `kubectl`, `helm`, `jq`, `yq`, `openssl`, Go, Docker.  
On macOS also install [Colima](https://github.com/abiosoft/colima) and start it with enough resources:

```sh
colima start --cpu 6 --memory 8 --disk 60
```

**One-time DNS fix (macOS only)** — your router won't forward nip.io queries:

```sh
sudo mkdir -p /etc/resolver && echo "nameserver 8.8.8.8" | sudo tee /etc/resolver/nip.io
```

**Cluster setup (first time):**

```sh
make kind-cluster       # creates the KinD cluster
```

```sh
make integration-infra  # bootstraps cloud-provider-kind if needed, then installs
                        # cert-manager, ingress-nginx, unikorn-core — idempotent
```

**Run the tests:**

```sh
make integration-test
```

The full run finishes with the shadow-divergence gate and then the
decision-flip e2e (in that order — the flip deliberately opens a transient
divergence window that would poison the gate).

## Composability example

A downstream service (e.g. compute) that depends on identity calls this script directly:

```sh
# In compute's CI:
../identity/hack/ci/setup-infra          # idempotent — safe to call multiple times
../identity/hack/ci/install \
  --namespace "unikorn-identity-${RAND}" \
  --release-name "identity-${RAND}" \
  --values ../identity/hack/ci/test-values.yaml \
  > identity.env
. identity.env
# ... install region, then compute, then run compute's own fixtures and tests
```

Identity's install logic is defined once here. Downstream services never duplicate it.
