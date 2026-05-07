# Development Guidelines

## Required Reading

**Before writing any code**, fetch and read the Platform Architecture Specification:

https://raw.githubusercontent.com/nscaledev/uni-specifications/refs/heads/main/SPECIFICATION.md

**Before writing any test code, CI scripts, or fixtures**, also fetch and read the Integration
Testing Strategy:

https://raw.githubusercontent.com/nscaledev/uni-specifications/refs/heads/main/specifications/testing/kind-integration-testing.md

Use `WebFetch` to retrieve these at the start of any task. They are not optional background
reading — the patterns they define are required, not suggested.

## Pre-commit / Pre-push Checklist

The following make commands must pass before committing and pushing changes:

```sh
make touch
make license
make validate
make lint
make generate
[[ -z $(git status --porcelain) ]]  # generated code must be checked in
make test-unit
```

## Test Writing

All new tests must follow the patterns established in `test/api/`:

- **BDD structure**: Use `Describe > Context > Describe > It` nesting.
  `Describe` names the resource or component. `Context` describes the scenario
  ("When listing...", "Given invalid auth"). Inner `Describe` names the precondition.
  `It` states the assertion in plain English.

- **Typed client**: Use `test/api.APIClient` or the e2e equivalent in `test/e2e/client.go`.
  Never make raw `http.Client` calls in test files — always go through a typed wrapper that
  returns OpenAPI structs.

- **Response body assertions**: Assert on response body fields (`Metadata.Id`, `Metadata.Name`,
  `Metadata.ProvisioningStatus`, `Spec.*`, `Status.*`) not only HTTP status codes. Status-only
  assertions are acceptable exclusively for pure authorization (RBAC) tests.

- **Endpoint URLs**: Use `test/api.Endpoints` (from `test/api/endpoints.go`) for all URL paths.
  Do not hard-code URL strings in test files.

- **Test data lifecycle**: Register cleanup with `DeferCleanup` immediately after resource
  creation. See `test/api/fixtures.go:CreateGroupWithCleanup` as the canonical pattern.

- **Build tags**: Integration tests use `//go:build integration`.
  E2e tests use `//go:build e2e`. Never omit the build tag.

## Documentation Maintenance

The package documentation under `pkg/**/README.md` is part of the implementation contract for this
repository, not optional commentary.

- Before making changes, consult the relevant package documentation so code changes stay aligned
  with the documented architecture, invariants, caveats, and API conventions.
- When implementation changes alter behaviour, architecture, lifecycle semantics, error handling,
  or trust boundaries, update the affected package documentation in the same change.
- Keep the documentation link graph coherent:
  - avoid dead links
  - add links for any new meaningful package documentation
  - update higher-level rollups when lower-level package responsibilities move
- If a code change invalidates an existing caveat or TODO in the docs, correct it rather than
  leaving stale guidance behind.
- Treat the top-level `README.md` and `pkg/README.md` as landing pages that should remain
  technically accurate for new starters, external observers, and AI coding assistants.
