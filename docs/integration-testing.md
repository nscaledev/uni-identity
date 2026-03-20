# Integration Testing — Developer and CI Guide

This guide covers how identity integration tests run locally and in GitHub Actions.

Identity now uses a **single main integration suite** in `test/api`. The difference between local,
per-PR CI, and manually triggered execution is the environment setup, not the test tree.

## Execution Modes

There are currently two supported ways to run the suite:

### 1. Per-PR CI

The integration workflow in
[`../.github/workflows/integration.yaml`](../.github/workflows/integration.yaml)
creates a fresh KinD cluster on every pull request, deploys identity, creates fixtures, and runs:

```sh
make test-api-ci
```

This is the authoritative CI path and the preferred model for regression coverage.

### 2. Manual / Triggered Mode

The same `test/api` suite can also run against an existing environment by supplying `test/.env`
yourself and invoking:

```sh
make test-api
```

This mode exists for developer workflows and manually triggered jobs that still target a persistent
environment.

## Choosing a Local Cluster

You can use either **KinD** (Linux and Mac) or **Colima** (Mac). Both work — the scripts
auto-detect which one you are using and adjust accordingly.

| | KinD | Colima |
|---|---|---|
| Platform | Linux, Mac | Mac |
| Cluster create | `make kind-cluster` | `colima start --kubernetes` |
| Image loading | `make images-kind-load` (auto) | `make images` (auto) |
| Port exposure | via `extraPortMappings` | via Lima port forwarding |
| Infra setup | `make integration-infra` | `make integration-infra` |

## Prerequisites

| Tool | Purpose | KinD | Colima |
|------|---------|------|--------|
| [`kind`](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) | Local Kubernetes cluster | required | not needed |
| [`colima`](https://github.com/abiosoft/colima#installation) | Mac-native Kubernetes via Lima | not needed | required |
| [`kubectl`](https://kubernetes.io/docs/tasks/tools/) | Cluster interaction | ✓ | ✓ |
| [`helm`](https://helm.sh/docs/intro/install/) ≥ 3.14 | Chart deployment | ✓ | ✓ |
| [`yq`](https://github.com/mikefarah/yq) | YAML parsing in install scripts | ✓ | ✓ |
| [`jq`](https://stedolan.github.io/jq/) | JSON parsing in install scripts | ✓ | ✓ |
| `openssl` | TLS cert polling in install scripts | ✓ | ✓ |
| Go (version from `go.mod`) | Building images and running fixtures | ✓ | ✓ |
| Docker | Building container images | ✓ | ✓ |

All tools must be on `PATH`.

## One-time Cluster Setup

### KinD

```sh
make kind-cluster integration-infra
```

`kind-cluster` creates a cluster named `identity-test` by default. It skips creation if that cluster
already exists.

### Colima

```sh
colima start --kubernetes
make integration-infra
```

Skip `make kind-cluster` when using Colima.

`integration-infra` installs cert-manager, ingress-nginx, and unikorn-core (resolved from the exact
version pinned in `go.mod`), then waits for the CA certificates to be issued. It is idempotent.

## Running the Main Suite Locally

After the cluster is ready, run:

```sh
make integration-install integration-fixtures test-api-ci
```

Or all at once on KinD:

```sh
make integration-test
```

This performs:

1. `integration-install` — builds images from source, deploys identity with a random release name and
   namespace, and waits for TLS and JOSE key readiness
2. `integration-fixtures` — creates test resources via the identity HTTP API using mTLS and writes
   `test/.env`
3. `test-api-ci` — runs the main `test/api` suite in randomised, race-detected mode

Each run uses a fresh random suffix (`KIND_SUFFIX`), so release names, namespaces, and ingress
hostnames vary from run to run. This catches hardcoded names.

## Iterating Without Rebuilding

After an initial `make integration-install integration-fixtures`, re-run just the suite with:

```sh
make test-api
```

Focus on a subset with:

```sh
make test-api-focus FOCUS="RBAC Matrix"
```

To redeploy without recreating the cluster or reinstalling infra:

```sh
make integration-install integration-fixtures test-api-ci
```

## Manual / Existing Environment Mode

If you are targeting an existing environment instead of deploying via kind, create `test/.env`
yourself and run the same main suite:

```sh
make test-api
```

Minimum required variables:

- `IDENTITY_BASE_URL`
- `API_AUTH_TOKEN`
- `TEST_ORG_ID`
- `TEST_PROJECT_ID`

Optional variables used by the richer kind-generated flow:

- `ADMIN_AUTH_TOKEN`
- `USER_AUTH_TOKEN`
- `TEST_USER_SA_ID`
- `IDENTITY_CA_CERT`

If `IDENTITY_CA_CERT` is present, the Make targets export `SSL_CERT_FILE` so the suite can trust
the test ingress certificate.

## What the Main Suite Covers

The `test/api/` suite currently covers:

- Organization and project discovery
- ACL discovery
- Quota discovery
- Group CRUD and list/read flows
- Role discovery
- Service account discovery
- User discovery
- Multi-principal RBAC matrix coverage when admin and user tokens are available

The RBAC matrix runs only when both `ADMIN_AUTH_TOKEN` and `USER_AUTH_TOKEN` are present. This is
the standard case for kind-generated fixtures.

## How Auth Bootstrapping Works

`hack/ci/fixtures` uses an mTLS client certificate to authenticate. The certificate common name
(`ci-fixtures`) is pre-configured as a system account in `hack/ci/test-values.yaml` with the
`platform-administrator` role. No token exchange is needed — the CN maps directly to the role.

> `platform-administrator` is protected and not visible or assignable via the public API. It is
> only grantable at deploy time via Helm values.

The fixture creates:

- one organization
- one project
- one administrator service account
- one user service account

It writes both:

- `API_AUTH_TOKEN` for backward-compatible API suite consumers
- `ADMIN_AUTH_TOKEN` / `USER_AUTH_TOKEN` for explicit multi-principal coverage

## Pre-PR Checklist

Run these before pushing:

```sh
make touch
make license
make validate
make lint
make generate
[[ -z $(git status --porcelain) ]]
make test-unit
make integration-install integration-fixtures test-api-ci
```

If you do not have a cluster yet:

- KinD: prepend `make kind-cluster integration-infra`
- Colima: run `colima start --kubernetes && make integration-infra`

## Makefile Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KIND_CLUSTER` | `identity-test` | KinD cluster name. Override to use a different cluster. |
| `KIND_SUFFIX` | random 8 chars | Suffix for release name and namespace. |
| `KIND_NAMESPACE` | `unikorn-identity-$(KIND_SUFFIX)` | Kubernetes namespace for the deploy. |
| `KIND_RELEASE` | `identity-$(KIND_SUFFIX)` | Helm release name. |

Example:

```sh
KIND_SUFFIX=abc12345 make integration-fixtures test-api-ci
```

## Compatibility and Upgrade Path

Identity is moving toward one execution model and one suite.

Current state:

- `test/api` is the main integration suite
- per-PR CI runs that suite against a fresh kind deployment
- manual jobs and developers can still run the same suite against an existing environment
- `kind-cluster` remains the cluster-creation entry point
- provider-neutral `integration-*` targets handle infra, deploy, fixtures, and the full run

Target state:

- local development, PR CI, and manually triggered workflows all use the same kind-backed setup
- `test/api` remains the only integration suite
- legacy alias target names are removed once downstream automation is migrated

This means new coverage should be added to `test/api`, not to a separate `e2e` tree.

## Troubleshooting

**`nginx is serving the wrong TLS cert`**  
cert-manager has issued the cert but nginx has not reloaded yet. Check ingress-nginx:

```sh
kubectl get pods -n ingress-nginx
```

**`JOSE signing key not created after 60s`**  
Check the server logs:

```sh
kubectl logs -n <namespace> -l app.kubernetes.io/name=identity
```

**`Certificate not ready`**  
Run `make integration-infra` again. It is idempotent.

**`Previous release conflicts`**  
`hack/ci/install` automatically uninstalls previous `identity-*` releases because of cluster-scoped
resources. If a previous uninstall was interrupted:

```sh
helm list -A --filter '^identity-' -o json | jq -r '.[] | "\(.name) \(.namespace)"' | \
  while read rel ns; do helm uninstall "$rel" -n "$ns"; done
```

**`Stale namespaces`**  
Old namespaces do not affect new runs, but can be removed with:

```sh
kubectl get ns | grep unikorn-identity | awk '{print $1}' | xargs kubectl delete ns
```

**`Colima: port 443 not reachable`**  
Check the ingress service:

```sh
kubectl get svc -n ingress-nginx
```

If the external IP is not `localhost` or `127.0.0.1`, restart Colima.
