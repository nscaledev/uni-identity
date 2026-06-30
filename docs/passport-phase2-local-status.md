# Passport Token Exchange Phase 2 Local Status

Status captured: 2026-05-15 15:20:40 BST.

This note records the current local Colima deployment state for Passport Token
Exchange Phase 2 and the remaining blockers before meaningful end-to-end
provider testing can run.

## Source Branches

The local repositories under `/Users/fqw4m72pvl/src/nscale/uni` are checked out as
follows:

| Component | Branch | Upstream reference |
| --- | --- | --- |
| `uni-identity` | `alansy/phase-2` | Phase 2 identity branch |
| `uni-region` | `alansy/id-191` | <https://github.com/nscaledev/uni-region/pull/477> |
| `uni-compute` | `alansy/id-192` | <https://github.com/nscaledev/uni-compute/pull/275> |
| `uni-kubernetes` | `alansy/id-192` | <https://github.com/nscaledev/uni-kubernetes/pull/404> |

`uni-region`, `uni-compute`, and `uni-kubernetes` were built using a temporary Go
workspace at `/tmp/uni-phase2-work/go.work` so their builds resolve local Phase 2
dependencies from the checked-out identity/region branches. This avoided changing
their `go.mod` files.

## Deployed Local Stack

The current Kubernetes context is `colima`. The ingress LoadBalancer IP is
`192.168.64.3`.

| Component | Namespace | Release | Host | Image tag |
| --- | --- | --- | --- | --- |
| identity | `unikorn-identity-4bf10750` | `identity-4bf10750` | `identity-4bf10750.192.168.64.3.nip.io` | `v1.14.0-rc1` |
| region | `unikorn-region-4bf10750` | `region-4bf10750` | `region-4bf10750.192.168.64.3.nip.io` | `v1.16.3` |
| compute | `unikorn-compute-4bf10750` | `compute-4bf10750` | `compute-4bf10750.192.168.64.3.nip.io` | `v1.16.2` |
| kubernetes | `unikorn-kubernetes-4bf10750` | `kubernetes-4bf10750` | `api-4bf10750.192.168.64.3.nip.io` | `v1.14.0-rc1` |

Verification completed:

- All identity, region, compute, and kubernetes pods were `Running`.
- cert-manager certificates for the four services were `Ready`.
- HTTPS ingress routing works when using `curl --resolve`.
- Identity OIDC discovery returned `200`.
- Region, compute, and kubernetes returned `404` for `/`, which is expected and
  confirms routing/TLS to the services.

## Current Issues

### DNS Is Not Configured

The UNI Development guide expects both host DNS and in-cluster DNS to resolve the
service FQDNs.

Current state:

- `/etc/resolver/unikorn.nscale.com` is missing.
- `/etc/hosts` does not contain the current local UNI host mappings.
- `kube-system/coredns-custom` does not exist.
- A short-lived BusyBox pod failed to resolve
  `identity-4bf10750.192.168.64.3.nip.io`.

This is a blocker for Passport propagation testing because region, compute, and
kubernetes are configured to call identity/region using hostnames. The services
may fail token exchange or upstream calls with DNS lookup errors even though
their pods are healthy.

### OpenStack Credentials Are Missing

Alan confirmed provider-backed testing needs an OpenStack credential secret
referenced from `region.yaml`.

Current state:

- No OpenStack credential secret exists in `unikorn-region-4bf10750`.
- `kubectl get regions.region.unikorn-cloud.org -A` returned no Region resources.
- The current region Helm release has no `regions:` configured.

The secret must contain these keys:

```text
domain-id
project-id
user-id
password
```

Do not commit these values.

For the current manual deployment, the secret belongs in
`unikorn-region-4bf10750`. For the standard `uni-developer-env` layout, it belongs
in `unikorn-region`.

### Local Dev Flow Diverges From `uni-developer-env`

The recommended Notion path points to `nscaledev/uni-developer-env`, which uses
Tilt, dnsmasq, mkcert, standard namespaces, and standard hosts such as:

```text
identity.unikorn.nscale.com
region.unikorn.nscale.com
compute.unikorn.nscale.com
api.unikorn.nscale.com
```

The current stack was installed manually using suffixed namespaces and `nip.io`
hosts to preserve the already-deployed Phase 2 identity release. This is workable
for local API work, but DNS and values must be adjusted consistently.

### UI/Admin Flow Is Not Configured

This stack is not ready for the full local UI flow from the UNI Development
guide:

- `platformAdministrators.subjects` is empty in the identity release.
- `kubectl get oauth2client -A` returned no resources.
- UI was not deployed.

This does not block raw API tests, but it does block browser/UI-based validation.

### Colima Status Is Inconsistent

`kubectl config current-context` and `docker context show` both report `colima`,
and the cluster is usable. However, `colima status` reports `colima is not
running`. Treat this as a local Colima tooling inconsistency unless Colima
lifecycle commands are needed.

## Blocked On

1. OpenStack credentials from Nick or another owner.
2. A decision on whether to continue with the current suffixed manual stack or
   move to the standard `uni-developer-env` Tilt stack.
3. DNS configuration for the chosen host layout.
4. Region Helm upgrade with a `regions:` entry that references the OpenStack
   credential secret.

## Current Manual Stack: Suggested Next Steps

### 1. Configure Host DNS

For the current suffixed deployment, add host mappings for the ingress IP:

```text
192.168.64.3 identity-4bf10750.192.168.64.3.nip.io region-4bf10750.192.168.64.3.nip.io compute-4bf10750.192.168.64.3.nip.io api-4bf10750.192.168.64.3.nip.io
```

### 2. Configure CoreDNS

Create a `coredns-custom` ConfigMap in `kube-system` with the same host mappings,
then restart CoreDNS. Example shape:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-custom
  namespace: kube-system
data:
  phase2.server: |
    nip.io:53 {
        hosts /etc/coredns/NodeHosts {
          ttl 60
          reload 15s
          192.168.64.3 identity-4bf10750.192.168.64.3.nip.io
          192.168.64.3 region-4bf10750.192.168.64.3.nip.io
          192.168.64.3 compute-4bf10750.192.168.64.3.nip.io
          192.168.64.3 api-4bf10750.192.168.64.3.nip.io
          fallthrough
        }
    }
```

Then run:

```sh
kubectl rollout restart deploy coredns -n kube-system
```

### 3. Create The OpenStack Secret

Once credentials are available:

```sh
kubectl -n unikorn-region-4bf10750 create secret generic uni-alan-dev-credentials \
  --from-literal=domain-id='<domain-id>' \
  --from-literal=project-id='<project-id>' \
  --from-literal=user-id='<user-id>' \
  --from-literal=password='<password>'
```

### 4. Upgrade Region With A Region Entry

Use a values overlay like:

```yaml
tag: v1.16.3

regions:
  - name: glo1
    provider: openstack
    openstack:
      endpoint: https://compute.glo1.dev.nscale.com:5000
      serviceAccountSecret:
        namespace: unikorn-region-4bf10750
        name: uni-alan-dev-credentials

ca:
  secretNamespace: cert-manager
  secretName: unikorn-ca

ingress:
  class: nginx
  clusterIssuer: unikorn-issuer

identity:
  host: identity-4bf10750.192.168.64.3.nip.io

region:
  host: region-4bf10750.192.168.64.3.nip.io

compute:
  host: compute-4bf10750.192.168.64.3.nip.io
```

Then upgrade `region-4bf10750` in namespace `unikorn-region-4bf10750`.

## References

- UNI Development:
  <https://www.notion.so/nscalecloud/UNI-Development-d50ba0e76d1c4ded953131f07960ca1b>
- Phase 2 PRD:
  <https://www.notion.so/nscalecloud/PRD-Passport-Token-Exchange-Phase-2-335caf6bfadc803c8308f251eab3365f>
- Phase 2 QA:
  <https://www.notion.so/nscalecloud/QA-Verification-Passport-Token-Exchange-Phase-2-349caf6bfadc81e8a5bde58a337cb363>
- Local dev env repo:
  <https://github.com/nscaledev/uni-developer-env>
