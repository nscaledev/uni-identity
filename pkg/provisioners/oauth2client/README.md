# `pkg/provisioners/oauth2client`

This package provisions operational secret state for the built-in OAuth2 client model.

## Intent

This is the simplest provisioner in the repo.

Its job is to ensure an `OAuth2Client` has generated client-secret material in status so the
built-in identity implementation can authenticate confidential clients.

That matters primarily for the local first-party IdP path used in development, testing, and
self-contained deployments. It is not a major part of the expected long-term production story,
where third-party IdPs are more central.

## What Is Specific Here

### Generated Client Secret Material

On provision, if `Status.Secret` is empty, the provisioner generates a random secret and stores it
in status.

If the secret already exists, the provisioner leaves it alone. So the current model is:

- generate once
- persist
- do not rotate automatically

### No Child Resource Lifecycle

Unlike the organization and project provisioners, this package does not create projected
namespaces, manage descendants, or coordinate teardown ordering.

It is purely a status-materialization provisioner.

## Invariants

- a confidential OAuth2 client should have a generated secret in status
- provisioning is idempotent once the secret exists
- deprovision has no child-resource work to perform

## Caveats

- The generated secret is effectively a persistent PSK today; expiry and rotation are not yet
  modeled.
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
  `OAuth2Client` resource and status secret field
- [`../core/pkg/manager`](../../../core/pkg/manager/README.md), which defines the shared manager
  lifecycle this provisioner still participates in despite its simplicity
