# OAuth2 Providers

## Purpose

This package is the organization-scoped CRUD client for upstream OAuth2/OIDC
provider configuration.

It is intentionally much simpler than handlers such as
[users](../users/README.md), [groups](../groups/README.md), or
[projects](../projects/README.md). Its job is just to store and retrieve the
provider configuration that the built-in
[pkg/oauth2](../../oauth2/README.md) implementation can use for federated
login.

## What Is Specific Here

- providers are organization-scoped
- the package supports both global listing and organization-local listing
- writes follow the same read/modify/write and optimistic-locking conventions as
  the rest of the handler layer
- the user-facing read model intentionally omits sensitive details such as the
  client secret

## Invariants And Guard Rails

- provider resources live in the organization namespace selected by
  [pkg/handler/organizations](../organizations/README.md)
- identity metadata and organization labels are stamped onto stored resources in
  the same way as other handler-managed objects
- updates preserve conflict detection through optimistic-locking patch
- client secret handling should remain more restrictive than ordinary config
  fields, even though the current built-in auth path is no longer the main
  production center of gravity

## Caveats

- this package inherits the current `v1` organization-namespace handoff model
  rather than defining a new scoping pattern of its own
- it is operationally relevant mainly to the built-in local auth flow; the
  longer-term production direction is greater reliance on third-party identity
  providers directly rather than identity acting as the primary long-term IdP
  surface itself
- the code still contains a note about secret visibility and client-secret write
  requirements, which suggests the secret-handling model is intentionally
  cautious but not yet fully tightened

## Related Packages

- [pkg/oauth2](../../oauth2/README.md), which consumes these provider
  definitions for the built-in federated login flow
- [pkg/handler/organizations](../organizations/README.md), which provides the
  current organization scoping model
- [pkg/apis/unikorn/v1alpha1](../../apis/unikorn/v1alpha1/README.md), which
  defines the stored provider resource
