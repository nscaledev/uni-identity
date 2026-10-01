# `pkg/provisioners/oauth2client`

This package provisions operational secret state for the built-in OAuth2 client model.

## Intent

This is the simplest provisioner in the repo.

Its job is to ensure an `OAuth2Client` has generated client-secret material so the built-in
identity implementation can authenticate confidential clients.

That matters primarily for the local first-party IdP path used in development, testing, and
self-contained deployments. It is not a major part of the expected long-term production story,
where third-party IdPs are more central.

## What Is Specific Here

### Credentials Secret

The client's credentials live in a Secret named `<client>-credentials` in the client's namespace:

- `id` is the client ID (the `OAuth2Client` name)
- `secret` is the client secret
- the `unikorn-cloud.org/oauth2client` label carries the client name, so tools like
  External Secrets `PushSecret` can select it
- an owner reference to the `OAuth2Client` lets Kubernetes garbage collection remove it

This is the same layout `OAuth2Provider.Spec.ClientSecretName` consumes.

On provision:

- Secret exists: it is left alone
- Secret missing, `Status.Secret` set: the value is copied across unchanged, so existing clients
  keep working through the migration
- neither: a random secret is generated

The Secret is then copied into `Status.Secret`.

### Why Status Is Still Written

The Secret is the source of truth. `Status.Secret` is a copy kept only so a rollback to a release
that reads status sees the same secret. It will be removed once no supported release reads it.

### Why The Read Is Uncached

The controller reads the Secret through the manager's API reader. A cached read would make the
manager list and watch every Secret in the cluster, needing cluster-wide RBAC and memory for no
gain, as reconciles only run on `OAuth2Client` generation changes. The controller needs only `get`
and `create` on Secrets in its own namespace.

### No Child Resource Lifecycle

Unlike the organization and project provisioners, this package does not create projected
namespaces, manage descendants, or coordinate teardown ordering. The credentials Secret is removed
by garbage collection, so deprovision does nothing.

## Invariants

- a confidential OAuth2 client has a credentials Secret with a non-empty `secret` key
- an existing secret value is never regenerated, whether it lives in the Secret or in status
- provisioning is idempotent once the Secret exists
- deprovision has no child-resource work to perform

## Caveats

- The generated secret is effectively a persistent PSK today; expiry and rotation are not yet
  modeled.
- The Secret is not watched. If it is deleted, it is only recreated (from the status copy) on the
  next reconcile of the `OAuth2Client`.
- A Secret with an empty `secret` key is an error; it is not overwritten, and logins for that client
  fail until someone fixes it.
- This provisioner is operationally important for the built-in IdP/client-auth path, but that path
  is more relevant to development and self-contained deployments than to the main production
  direction.
- Even though the provisioned side effect is trivial, the resource still participates in the
  controller/finalizer lifecycle. During same-release teardown, the `OAuth2Client` can become stuck
  if the controller disappears before it reconciles finalizer removal.

## Related Documentation

- [`pkg/oauth2`](../../oauth2/README.md), which consumes the generated client secret for built-in
  client authentication
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `OAuth2Client` resource
- [`../core/pkg/manager`](../../../core/pkg/manager/README.md), which defines the shared manager
  lifecycle this provisioner still participates in despite its simplicity
