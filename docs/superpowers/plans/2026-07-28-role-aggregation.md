# ID-368 Implementation Plan — Phase A (delta validation & read fixes), Phase B (role aggregation)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phase A (Tasks 1–6, ships first, no CRD change): delta-based grant validation so org admins can manage members of groups carrying roles they cannot grant, plus the `grantable` flag, silent-revocation guard, named errors, and guard-test coverage of `additionalRoles`. Phase B (Tasks 7–14): Kubernetes-style role aggregation so labelled third-party roles become grantable by org admins, with the maintainer's sign-off conditions folded in (whole-lattice aggregation, `roleRefs` + `roleSelectors`, the aggregate exposing its scopes and composed description, mutating-fold integration coverage).

**Phase gate:** Phase B starts only after Phase A is merged. Task 12 additionally requires the maintainer's ruling on membership gating (spec, "Handler and API changes" item 4) — every other Phase B task is unblocked regardless of that ruling.

**Architecture:** Handler-level changes only. Group create validates every requested role via `AllowRole`; group update validates only roles being *added* (delta), while a separate removal guard rejects dropping roles the caller cannot grant. The roles list stops hiding ungrantable roles (protected stays hidden — two different reasons for absence get two different filters) and exposes `grantable: bool` per caller. All grant-refusal errors name the offending role.

**Tech Stack:** Go, controller-runtime fake client for unit tests, oapi-codegen from `pkg/openapi/server.spec.yaml`, Ginkgo/Gomega integration tests against a KinD deployment.

**Spec:** `docs/superpowers/specs/2026-07-28-role-aggregation-design.md`. The users/service-account membership gate (Task 12) carries an explicit decision gate pending the maintainer's ruling; if the ruling is "ungated everywhere", Task 12 collapses to documentation only.

## Global Constraints

- Module path: `github.com/unikorn-cloud/identity`.
- New Go files start with the license header used by `test/api/suites/roles_test.go` (`Copyright 2026 Nscale.` + Apache 2.0 text). `make license` must pass.
- Before EVERY commit: `make touch license validate lint generate && [[ -z $(git status --porcelain) ]]` after staging, and `make test-unit` (per project CLAUDE.md). Generated code is checked in with the change that caused it.
- Commit style: conventional commits referencing ID-368.
- Integration tests: `//go:build integration`, BDD `Describe > Context > Describe > It`, typed client only, endpoints via `test/api.Endpoints`, cleanup via `DeferCleanup`.
- Branches: Phase A on `id-368-phase-a`, Phase B on `id-368-phase-b`, each off `main`, created before that phase's first commit.

---

### Task 1: Delta-based grant validation with named errors (groups handler)

**Files:**
- Modify: `pkg/handler/groups/client.go` (`validateRoleIDs` ~line 342, `generate` ~373, `Create` ~403, `Update` ~421)
- Test: `pkg/handler/groups/client_test.go` (new)

**Interfaces:**
- Consumes: `rbac.AllowRole`, `rbac.NewContext`.
- Produces: `validateRoleIDs(ctx, organizationID, roleIDs, currentRoleIDs []string)` — grant check applies only to `roleIDs − currentRoleIDs`; `generate(ctx, organization, in, current *unikornv1.Group)` with `current == nil` on create; `roleDisplayName(role *unikornv1.Role) string` (Task 2 and Task 3 reuse it).

- [ ] **Step 1: Write the failing tests**

`pkg/handler/groups/client_test.go` (internal test package — it exercises unexported functions):

```go
package groups //nolint:testpackage // exercises unexported validation helpers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

const (
	testNamespace      = "identity"
	testOrganizationID = "acbaf1e5-6414-4066-b74e-2d95dc766299"
)

func testClient(t *testing.T, roles ...*unikornv1.Role) *Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, role := range roles {
		builder = builder.WithObjects(role)
	}

	// Match New's real signature (client, namespace, issuer); the issuer is
	// unused by role validation — pass its zero value.
	return New(builder.Build(), testNamespace, nil)
}

func testACL(endpoints openapi.AclEndpoints) context.Context {
	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}
	return rbac.NewContext(context.Background(), &openapi.Acl{Organizations: &organizations})
}

func testRole(id, name string, protected bool, endpoint string) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      id,
			Namespace: testNamespace,
			Labels:    map[string]string{"unikorn-cloud.org/name": name},
		},
		Spec: unikornv1.RoleSpec{
			Protected: protected,
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{{Name: endpoint, Operations: []unikornv1.Operation{unikornv1.Read}}},
			},
		},
	}
}

func TestValidateRoleIDsChecksOnlyAdditions(t *testing.T) {
	t.Parallel()

	radar := testRole("radar-id", "radar", false, "radar:things")
	basic := testRole("basic-id", "basic", false, "identity:groups")
	c := testClient(t, radar, basic)

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	// Caller holds identity:groups but nothing radar.
	ctx := testACL(openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}})

	// Create (no current): every role is an addition — radar refused, named.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"radar-id"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "radar")

	// Update re-sending an existing radar role: not an addition — allowed.
	// This is the reported bug: members-only edits must not fail on roles
	// that were already on the group.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"radar-id", "basic-id"}, []string{"radar-id"})
	require.NoError(t, err)

	// Adding radar to a group that does not have it: refused.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"radar-id", "basic-id"}, []string{"basic-id"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "radar")
}

func TestValidateRoleIDsProtectedAndMissing(t *testing.T) {
	t.Parallel()

	hidden := testRole("hidden-id", "hidden", true, "identity:groups")
	c := testClient(t, hidden)

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}})

	// Protected roles are refused even when already on the group — they
	// should never be on an API-managed group at all.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"hidden-id"}, []string{"hidden-id"})
	require.Error(t, err)

	// Unknown role IDs are refused with a clear error.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"nope"}, nil)
	require.Error(t, err)
}
```

(Match `openapi.AclOperation` constant names — `openapi.Read` etc. — to what `pkg/rbac/grant_guard_test.go` uses; adjust if they are `AclOperationRead`-style. Match `New`'s real parameter list from `pkg/handler/groups/client.go` — if the issuer parameter is not nil-able, pass the zero value of its concrete type.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/handler/groups/... -v`
Expected: FAIL (compile error: `validateRoleIDs` has the old three-argument signature)

- [ ] **Step 3: Implement delta validation**

In `pkg/handler/groups/client.go`:

```go
// roleDisplayName returns the role's human name for error messages, falling
// back to the ID.
func roleDisplayName(role *unikornv1.Role) string {
	if name, ok := role.Labels["unikorn-cloud.org/name"]; ok {
		return name
	}

	return role.Name
}

func (c *Client) validateRoleIDs(ctx context.Context, organizationID ids.OrganizationID, roleIDs, currentRoleIDs []string) ([]string, error) {
	normalizedRoleIDs := deduplicateStrings(roleIDs)

	// Validate roles exist.
	for _, roleID := range normalizedRoleIDs {
		var resource unikornv1.Role

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: roleID}, &resource); err != nil {
			if kerrors.IsNotFound(err) {
				return nil, errors.OAuth2InvalidRequest(fmt.Sprintf("role ID %s does not exist", roleID)).WithError(err)
			}

			return nil, fmt.Errorf("%w: failed to validate role ID", err)
		}

		if resource.Spec.Protected {
			return nil, errors.HTTPForbidden("requested role is protected")
		}

		// Only roles being ADDED are grant-checked.  Re-sending a group's
		// existing role list (e.g. a members-only edit) must not fail on
		// roles the caller could not grant; the escalation guard applies to
		// the delta, and removals are guarded separately (ID-368).
		if slices.Contains(currentRoleIDs, roleID) {
			continue
		}

		// Check that the user is allowed to grant the role, this closes a security
		// hole where a user can cause privilige escalation by just knowing the
		// elevated role ID.  As these are typically generated by hashing the name
		// guessing them is pretty trivial.
		if err := rbac.AllowRole(ctx, &resource, organizationID); err != nil {
			return nil, errors.HTTPForbidden(fmt.Sprintf("role %q (%s) cannot be granted: the caller does not hold all its permissions", roleDisplayName(&resource), roleID)).WithError(err)
		}
	}

	return normalizedRoleIDs, nil
}
```

Thread `current` through `generate`:

```go
func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.GroupWrite, current *unikornv1.Group) (*unikornv1.Group, error) {
	userIDs, subjects, err := c.populateSubjectsAndUserIDs(ctx, organization, in)
	if err != nil {
		return nil, err
	}

	var currentRoleIDs []string

	if current != nil {
		currentRoleIDs = current.Spec.RoleIDs
	}

	roleIDs, err := c.validateRoleIDs(ctx, organization.ID, in.Spec.RoleIDs, currentRoleIDs)
	...rest unchanged...
```

Call sites: `Create` (~409) passes `nil`; `Update` (~432) passes `current` (already fetched at ~427). `slices` is already imported via the file's existing usage — verify.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/handler/groups/... -v && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
make touch license lint && make test-unit
git add pkg/handler/groups && git commit -m "fix(handler/groups): grant-check only roles added to a group, name refused roles

Members-only edits and updates to groups carrying roles the caller cannot
grant no longer fail on the pre-existing roles. Create still validates every
role (all are additions). Grant refusals now name the role.

Part of ID-368."
```

---

### Task 2: Roles API — grantable flag, split the protected filter

**Files:**
- Modify: `pkg/openapi/server.spec.yaml` (`roleRead` schema, ~line 1993)
- Modify: `pkg/handler/roles/client.go` (convert ~46, List ~68)
- Test: `pkg/handler/roles/client_test.go` (new)

**Interfaces:**
- Consumes: `rbac.AllowRole`, `rbac.NewContext`.
- Produces: `openapi.RoleRead.Grantable bool` (generated); `GET .../roles` returns all non-protected roles with per-caller `grantable`. Protected and ungrantable are two different reasons for absence — only protected stays hidden.

- [ ] **Step 1: Extend the API schema and regenerate**

In `pkg/openapi/server.spec.yaml` at `roleRead:` (~1993):

```yaml
    roleRead:
      description: A role.
      type: object
      required:
      - metadata
      - grantable
      properties:
        metadata:
          $ref: 'https://raw.githubusercontent.com/unikorn-cloud/core/v1.17.1/pkg/openapi/common.spec.yaml#/components/schemas/resourceReadMetadata'
        grantable:
          description: |-
            Whether the calling principal holds every permission in this role
            and may therefore grant it to groups. Roles with grantable set to
            false are visible for display purposes but cannot be added to or
            removed from groups by this caller.
          type: boolean
```

Run: `make generate && go build ./...`
Expected: `pkg/openapi` gains `Grantable bool` on `RoleRead`; build FAILS in `pkg/handler/roles` until convert is updated — the compiler drives the change.

- [ ] **Step 2: Write the failing handler test**

`pkg/handler/roles/client_test.go`:

```go
package roles_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/roles"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

const (
	namespace          = "identity"
	testOrganizationID = "acbaf1e5-6414-4066-b74e-2d95dc766299"
)

func newRole(name string, protected bool, orgScopes []unikornv1.RoleScope) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"unikorn-cloud.org/name": name},
		},
		Spec: unikornv1.RoleSpec{
			Protected: protected,
			Scopes:    unikornv1.RoleScopes{Organization: orgScopes},
		},
	}
}

func TestListReturnsUngrantableRolesWithFlag(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	grantableRole := newRole("basic", false, []unikornv1.RoleScope{
		{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}},
	})
	radar := newRole("radar", false, []unikornv1.RoleScope{
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
	})
	hidden := newRole("internal", true, nil)

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(grantableRole, radar, hidden).Build()

	// Caller holds identity:groups read at org scope, but nothing radar.
	endpoints := openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}}
	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}
	ctx := rbac.NewContext(context.Background(), &openapi.Acl{Organizations: &organizations})

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	result, err := roles.New(cli, namespace).List(ctx, orgID)
	require.NoError(t, err)

	byName := map[string]openapi.RoleRead{}
	for _, r := range result {
		byName[r.Metadata.Name] = r
	}

	require.Len(t, result, 2, "protected roles stay hidden, ungrantable roles do not")
	require.True(t, byName["basic"].Grantable)
	require.False(t, byName["radar"].Grantable)
	require.NotContains(t, byName, "internal")
}
```

Run: `go test ./pkg/handler/roles/... -v`
Expected: FAIL

- [ ] **Step 3: Implement**

`pkg/handler/roles/client.go` — split the two filter reasons and thread grantability:

```go
func convert(in unikornv1.Role, grantable bool) openapi.RoleRead {
	out := openapi.RoleRead{
		Metadata:  conversion.ResourceReadMetadata(&in, in.Spec.Tags),
		Grantable: grantable,
	}

	return out
}

func (c *Client) convertList(ctx context.Context, in unikornv1.RoleList, organizationID ids.OrganizationID) openapi.Roles {
	var out openapi.Roles

	for _, resource := range in.Items {
		grantable := rbac.AllowRole(ctx, &resource, organizationID) == nil

		out = append(out, convert(resource, grantable))
	}

	slices.SortFunc(out, func(a, b openapi.RoleRead) int {
		return cmp.Compare(a.Metadata.Name, b.Metadata.Name)
	})

	return out
}

func (c *Client) List(ctx context.Context, organizationID ids.OrganizationID) (openapi.Roles, error) {
	var result unikornv1.RoleList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	// Protected roles are internal and never exposed.  Ungrantable roles ARE
	// exposed (grantable: false) so clients can resolve and display roles
	// referenced by groups; hiding them caused silent role revocation on
	// group round-trips (ID-368).  These are two different reasons for
	// absence and must not share a filter.
	result.Items = slices.DeleteFunc(result.Items, func(role unikornv1.Role) bool {
		return role.Spec.Protected
	})

	return c.convertList(ctx, result, organizationID), nil
}
```

- [ ] **Step 4: Run tests and commit**

Run: `go test ./pkg/handler/roles/... -v && go build ./...`
Expected: PASS

```bash
make touch license validate lint generate && make test-unit
git status --porcelain   # generated openapi code must be staged too
git add -A && git commit -m "feat(handler/roles): expose ungrantable roles with a grantable flag

Protected roles stay hidden (internal); merely-ungrantable roles are now
returned with grantable: false so clients can resolve and display them.

Part of ID-368."
```

---

### Task 3: Groups API — reject silent removal of ungrantable roles

**Files:**
- Modify: `pkg/handler/groups/client.go` (`Update` ~421)
- Test: extend `pkg/handler/groups/client_test.go` (from Task 1)

**Interfaces:**
- Consumes: `rbac.AllowRole`, `roleDisplayName` (Task 1).
- Produces: `validateRoleRemovals(ctx, organizationID, current *unikornv1.Group, requestedRoleIDs []string) error`, wired into `Update`.

- [ ] **Step 1: Write the failing test**

Append to `pkg/handler/groups/client_test.go`:

```go
func TestValidateRoleRemovalsRejectsUngrantableDrop(t *testing.T) {
	t.Parallel()

	radar := testRole("radar-id", "radar", false, "radar:things")
	c := testClient(t, radar)

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	current := &unikornv1.Group{Spec: unikornv1.GroupSpec{RoleIDs: []string{"radar-id"}}}

	// Caller cannot grant radar: dropping it must be rejected, naming it.
	// Without this, a client that cannot resolve the role silently revokes
	// it by round-tripping the group.
	ctx := testACL(openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}}})
	err = c.validateRoleRemovals(ctx, orgID, current, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "radar")

	// Keeping it is fine (no removal).
	require.NoError(t, c.validateRoleRemovals(ctx, orgID, current, []string{"radar-id"}))

	// A caller who CAN grant radar may drop it.
	ctx = testACL(openapi.AclEndpoints{{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}}})
	require.NoError(t, c.validateRoleRemovals(ctx, orgID, current, nil))

	// A dangling role reference (role deleted) may always be dropped.
	dangling := &unikornv1.Group{Spec: unikornv1.GroupSpec{RoleIDs: []string{"no-such-role"}}}
	require.NoError(t, c.validateRoleRemovals(ctx, orgID, dangling, nil))
}
```

Run: `go test ./pkg/handler/groups/... -run TestValidateRoleRemovals -v`
Expected: FAIL (`validateRoleRemovals` undefined)

- [ ] **Step 2: Implement**

In `pkg/handler/groups/client.go`:

```go
// validateRoleRemovals rejects updates that drop a role the caller cannot
// grant.  Without this, a client that cannot see an ungrantable role
// silently revokes it by round-tripping the group (ID-368).  Roles that no
// longer exist may always be dropped: a dangling reference conveys no
// permissions.
func (c *Client) validateRoleRemovals(ctx context.Context, organizationID ids.OrganizationID, current *unikornv1.Group, requestedRoleIDs []string) error {
	for _, roleID := range current.Spec.RoleIDs {
		if slices.Contains(requestedRoleIDs, roleID) {
			continue
		}

		var resource unikornv1.Role

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: roleID}, &resource); err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}

			return fmt.Errorf("%w: failed to validate role removal", err)
		}

		if err := rbac.AllowRole(ctx, &resource, organizationID); err != nil {
			return errors.HTTPForbidden(fmt.Sprintf("role %q (%s) cannot be removed from the group: the caller does not hold all its permissions", roleDisplayName(&resource), roleID)).WithError(err)
		}
	}

	return nil
}
```

Wire into `Update`, after `current` is fetched (~427) and before the patch:

```go
	if err := c.validateRoleRemovals(ctx, organizationID, current, request.Spec.RoleIDs); err != nil {
		return err
	}
```

- [ ] **Step 3: Run tests and commit**

Run: `go test ./pkg/handler/groups/... -v`
Expected: PASS

```bash
make touch license lint && make test-unit
git add pkg/handler/groups && git commit -m "fix(handler/groups): reject silent removal of roles the caller cannot grant

Part of ID-368."
```

---

### Task 4: Guard test sees additionalRoles

**Files:**
- Modify: `pkg/rbac/grant_guard_test.go` (chartValues struct ~55, loadChartRoles ~59, new test)

**Interfaces:**
- Consumes: existing `aclForHolder`/`asRole` helpers and the typed organization ID variable already in the file.
- Produces: the guard covers every role the chart can install, not only the built-in `roles:` map.

- [ ] **Step 1: Extend parsing**

```go
type chartRole struct {
	Description string            `json:"description"`
	Protected   bool              `json:"protected"`
	Labels      map[string]string `json:"labels"`
	Scopes      struct {
		Global       endpointOperations `json:"global"`
		Organization endpointOperations `json:"organization"`
		Project      endpointOperations `json:"project"`
	} `json:"scopes"`
}

type chartValues struct {
	Roles           map[string]chartRole `json:"roles"`
	AdditionalRoles map[string]chartRole `json:"additionalRoles"`
}
```

and in `loadChartRoles`, after `require.NotEmpty(t, values.Roles)`:

```go
	for name, role := range values.AdditionalRoles {
		_, clash := values.Roles[name]
		require.False(t, clash, "additionalRoles key %q conflicts with built-in role", name)

		values.Roles[name] = role
	}
```

- [ ] **Step 2: Add the coverage test**

```go
// TestNonBuiltinRolesAdminGrantable asserts every non-protected role outside
// the built-in grant tree is either labelled for aggregation into
// administrator (admin-grantable at runtime once aggregation lands, ID-368
// Phase B) or already grantable by administrator from its spec alone.
// Vacuous while additionalRoles is empty; it exists to catch the next role
// someone adds without thinking about the grant lattice.
func TestNonBuiltinRolesAdminGrantable(t *testing.T) {
	t.Parallel()

	roles := loadChartRoles(t)
	admin, ok := roles["administrator"]
	require.True(t, ok)

	// Every role name present in the chart's built-in roles: map today.
	// Cross-check against values.yaml when touching this list.
	builtins := map[string]bool{
		"platform-administrator": true, "region-service": true, "kubernetes-service": true,
		"compute-service": true, "storage-service": true,
		"administrator": true, "auditor": true,
	}

	for name, role := range roles {
		if builtins[name] || role.Protected {
			continue
		}

		if role.Labels["rbac.unikorn-cloud.org/aggregate-to-administrator"] == "true" {
			continue
		}

		ctx := rbac.NewContext(context.Background(), aclForHolder(admin))
		require.NoError(t, rbac.AllowRole(ctx, asRole(role), organizationID),
			"role %q is neither aggregate-to-administrator labelled nor admin-grantable; admins will be unable to manage groups containing it (ID-368)", name)
	}
}
```

(Use the exact typed organization ID variable name the file's existing tests pass to `AllowRole` — shown here as `organizationID`. Extend the `builtins` map with `user`/`reader` if those exist in values.yaml under those names — check when implementing, do not invent entries.)

- [ ] **Step 3: Run and commit**

Run: `go test ./pkg/rbac/... -v`
Expected: PASS (vacuous for now — `additionalRoles: {}`)

```bash
make touch license lint && make test-unit
git add pkg/rbac && git commit -m "test(rbac): guard grantability of additionalRoles, not only built-ins

Part of ID-368."
```

---

### Task 5: Integration tests

**Files:**
- Create: `test/api/k8s.go`, `test/api/suites/group_membership_test.go`
- Modify: `test/api/suites/roles_test.go` (only if assertions break on the new field/unhidden roles)

**Interfaces:**
- Consumes: Tasks 1–3 deployed via the chart; `test/api` typed client and suite variables (`client`, `ctx`, `config` from `suite_test.go`).
- Produces: end-to-end proof of the reported fix: an admin manages members of a group carrying a role they cannot grant.

- [ ] **Step 1: k8s fixture helpers**

Roles have no write API and an admin cannot create a group carrying an ungrantable role via the API (that is the point), so both fixtures are installed with a Kubernetes client. `test/api/k8s.go`:

```go
package api

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/controller-runtime/pkg/client"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// NewKubernetesClient builds a controller-runtime client from KUBECONFIG for
// installing fixtures that have no HTTP API (e.g. Role CRs).  Integration
// runs always have cluster access — the same kubeconfig drives hack/ci.
func NewKubernetesClient() (client.Client, error) {
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := unikornv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	return client.New(config, client.Options{Scheme: scheme})
}

// OrganizationNamespace resolves the namespace provisioned for an
// organization by reading its CR from the identity service namespace.
func OrganizationNamespace(ctx context.Context, cli client.Client, identityNamespace, orgID string) (string, error) {
	org := &unikornv1.Organization{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: identityNamespace, Name: orgID}, org); err != nil {
		return "", err
	}

	// The organization controller records the provisioned namespace on the
	// CR status — use the exact field name from organization_types.go.
	if org.Status.Namespace == "" {
		return "", fmt.Errorf("organization %s has no provisioned namespace", orgID)
	}

	return org.Status.Namespace, nil
}

// InstallFixture creates any CR and returns a cleanup func.
func InstallFixture(ctx context.Context, cli client.Client, object client.Object) (func(), error) {
	if err := cli.Create(ctx, object); err != nil {
		return nil, err
	}

	return func() { _ = cli.Delete(context.Background(), object) }, nil
}
```

NOTE for the implementer: verify the `Organization` status field name in `pkg/apis/unikorn/v1alpha1/organization_types.go` (shown as `Status.Namespace`); verify `TestConfig` exposes the identity service namespace (add a `Namespace` field plumbed from `test/.env`/`hack/ci` if absent — that plumbing is part of this task). The fixture Group CR must carry the labels the handler normally sets (org scope label and name label) — copy the label keys from `pkg/handler/common`'s `SetIdentityMetadataOrganizationScope` usage rather than guessing.

- [ ] **Step 2: The suite**

`test/api/suites/group_membership_test.go` (`//go:build integration` + license header):

```go
var _ = Describe("Group membership with ungrantable roles", func() {
	Context("When a group carries a role the admin cannot grant", func() {
		Describe("Given an unlabelled third-party role fixture and a group referencing it", func() {
			var (
				roleID  string
				groupID string
			)

			BeforeEach(func() {
				kube, err := api.NewKubernetesClient()
				Expect(err).NotTo(HaveOccurred())

				roleID = fmt.Sprintf("radar-fixture-%d", GinkgoParallelProcess())

				role := &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleID,
						Namespace: config.Namespace,
						Labels:    map[string]string{"unikorn-cloud.org/name": roleID},
					},
					Spec: unikornv1.RoleSpec{
						Scopes: unikornv1.RoleScopes{
							Organization: []unikornv1.RoleScope{{
								Name:       "radar:things",
								Operations: []unikornv1.Operation{unikornv1.Read},
							}},
						},
					},
				}

				cleanupRole, err := api.InstallFixture(ctx, kube, role)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(cleanupRole)

				orgNamespace, err := api.OrganizationNamespace(ctx, kube, config.Namespace, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				groupID = fmt.Sprintf("radar-group-%d", GinkgoParallelProcess())

				group := &unikornv1.Group{
					ObjectMeta: metav1.ObjectMeta{
						Name:      groupID,
						Namespace: orgNamespace,
						// Copy the org-scope and name label keys the handler
						// sets — see the NOTE in Step 1.
					},
					Spec: unikornv1.GroupSpec{RoleIDs: []string{roleID}},
				}

				cleanupGroup, err := api.InstallFixture(ctx, kube, group)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(cleanupGroup)
			})

			It("should list the role as visible but not grantable", func() {
				roles, err := client.ListRoles(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				var found *identityopenapi.RoleRead
				for i := range roles {
					if roles[i].Metadata.Id == roleID {
						found = &roles[i]
					}
				}
				Expect(found).NotTo(BeNil(), "ungrantable roles must be visible")
				Expect(found.Grantable).To(BeFalse())
			})

			It("should let the admin change members without touching roles", func() {
				payload := api.NewGroupPayload().
					WithName(groupID).
					WithRoleIDs([]string{roleID}).
					WithUserIDs([]string{config.AdminUserID}).
					Build()

				updated, err := client.UpdateGroup(ctx, config.OrgID, groupID, payload)
				Expect(err).NotTo(HaveOccurred())
				Expect(*updated.Spec.UserIDs).To(ContainElement(config.AdminUserID))
				Expect(updated.Spec.RoleIDs).To(ContainElement(roleID), "the ungrantable role must survive the round-trip")
			})

			It("should refuse to drop the role, naming it", func() {
				payload := api.NewGroupPayload().
					WithName(groupID).
					WithRoleIDs(nil).
					Build()

				resp, err := client.UpdateGroupRaw(ctx, config.OrgID, groupID, payload)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
				Expect(string(resp.Body)).To(ContainSubstring(roleID), "error must name the role")
			})
		})
	})
})
```

NOTE: `client`, `ctx`, `config` are the suite variables from `suite_test.go`; `UpdateGroup`/`UpdateGroupRaw` — use the typed group-update methods `test/api/api_client.go` exposes, adding a thin wrapper there if only one variant exists (never raw `http.Client`). `config.AdminUserID` — add to `TestConfig` from the fixtures env if absent. Imports follow the existing suites (`fmt`, `net/http`, ginkgo/gomega dot-imports, `metav1`, `unikornv1`, `identityopenapi`, `api`).

- [ ] **Step 3: Run**

Per top-level README "Integration Testing": one-time `make kind-cluster integration-infra`, then the documented integration target. If `roles_test.go` assertions fail because the list now includes previously hidden roles, update them to assert on `Grantable` explicitly.
Expected: new suite PASSES.

- [ ] **Step 4: Commit**

```bash
make touch license validate lint generate && make test-unit
git add test && git commit -m "test(integration): member management on groups with ungrantable roles

Part of ID-368."
```

---

### Task 6: Documentation

**Files:**
- Modify: `pkg/handler/groups/README.md`, `pkg/handler/roles/README.md`, `pkg/rbac/README.md`

**Interfaces:** none — documentation contract per project CLAUDE.md.

- [ ] **Step 1: Update the docs**

- `pkg/handler/groups/README.md`: delta validation semantics (create checks all, update checks additions only), the removal guard, named errors, and the accepted consequence — a caller with `identity:groups` update may add members to an existing group whose roles they could not grant; org-internal, admin-only today, superseded for aggregated roles by ID-368 Phase B.
- `pkg/handler/roles/README.md`: the list no longer hides ungrantable roles; `grantable` semantics; protected remains hidden and why the two filters are separate.
- `pkg/rbac/README.md`: in the grant-lattice caveat (~217-232), note grantability is now enforced on the role delta for group updates, and that the guard test covers `additionalRoles`.

- [ ] **Step 2: Full pre-push checklist and commit**

```bash
make touch license validate lint generate
[[ -z $(git status --porcelain) ]] || echo "UNCOMMITTED CHANGES - investigate"
make test-unit
git add -A && git commit -m "docs: delta grant validation, grantable flag and removal guard

Part of ID-368."
```

Hand off for PR against `main` (do not push without the user's say-so).

---

# Phase B — role aggregation

Branch: `git checkout -b id-368-phase-b` off `main` after Phase A merges. All Phase A behaviours (delta validation, grantable flag, removal guard) are assumed present.

---

### Task 7: CRD — aggregationRule (refs + selectors), aggregated status, effective scopes

**Files:**
- Modify: `pkg/apis/unikorn/v1alpha1/types.go` (Role markers ~line 186-196, `RoleSpec` ~199, `RoleStatus` ~245)
- Create: `pkg/apis/unikorn/v1alpha1/role_helpers.go`
- Test: `pkg/apis/unikorn/v1alpha1/role_helpers_test.go`

**Interfaces:**
- Produces: `AggregationRule{RoleRefs []string, RoleSelectors []metav1.LabelSelector}` (`Spec.AggregationRule *AggregationRule`); `RoleStatus{AggregatedScopes RoleScopes, AggregatedDescriptions []string, MissingRoleRefs []string}`; `func MergeRoleScopes(lists ...[]RoleScope) []RoleScope`; `func (r *Role) EffectiveScopes() RoleScopes`. Later tasks use exactly these names.

- [ ] **Step 1: Write the failing tests**

`pkg/apis/unikorn/v1alpha1/role_helpers_test.go`:

```go
package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

func TestMergeRoleScopesDeduplicatesAndSorts(t *testing.T) {
	t.Parallel()

	a := []unikornv1.RoleScope{
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
		{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create}},
	}
	b := []unikornv1.RoleScope{
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Update, unikornv1.Read}},
	}

	out := unikornv1.MergeRoleScopes(a, b)

	require.Equal(t, []unikornv1.RoleScope{
		{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create}},
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read, unikornv1.Update}},
	}, out)
}

func TestMergeRoleScopesEmpty(t *testing.T) {
	t.Parallel()

	require.Nil(t, unikornv1.MergeRoleScopes(nil, nil))
}

func TestEffectiveScopesUnionsSpecAndStatus(t *testing.T) {
	t.Parallel()

	role := &unikornv1.Role{
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global:       []unikornv1.RoleScope{{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Read}}},
				Organization: []unikornv1.RoleScope{{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create}}},
			},
		},
		Status: unikornv1.RoleStatus{
			AggregatedScopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}}},
			},
		},
	}

	effective := role.EffectiveScopes()

	require.Equal(t, role.Spec.Scopes.Global, effective.Global)
	require.Equal(t, []unikornv1.RoleScope{
		{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create}},
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
	}, effective.Organization)
	require.Nil(t, effective.Project)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/apis/unikorn/v1alpha1/... -run 'TestMergeRoleScopes|TestEffectiveScopes' -v`
Expected: FAIL (compile: `MergeRoleScopes`, `EffectiveScopes`, `AggregatedScopes` undefined)

- [ ] **Step 3: Add the CRD fields and helpers**

In `types.go`: add `+kubebuilder:subresource:status` to the `Role` marker block (matching `OAuth2Client` at ~line 51), then:

```go
// AggregationRule selects other roles whose scopes are folded into this
// role's status by the role controller, mirroring Kubernetes' aggregated
// ClusterRoles.  Sources are the union of RoleRefs and RoleSelectors
// matches; either or both may be set.
type AggregationRule struct {
	// RoleRefs name source roles explicitly.  Pinned intent: a ref to a
	// role that does not exist is surfaced via status.missingRoleRefs.
	// +listType=set
	RoleRefs []string `json:"roleRefs,omitempty"`
	// RoleSelectors match opt-in source roles by label.
	RoleSelectors []metav1.LabelSelector `json:"roleSelectors,omitempty"`
}

// RoleSpec defines the role's requested state.
type RoleSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Protected means this is an unexported internal role.
	Protected bool `json:"protected,omitempty"`
	// AggregationRule, when set, makes the role controller fold matching
	// roles' organization and project scopes into this role's
	// status.aggregatedScopes at organization scope.  Global scopes and
	// protected roles are never aggregated.
	AggregationRule *AggregationRule `json:"aggregationRule,omitempty"`
	// Scopes are a list of uniquely named scopes for the role.
	Scopes RoleScopes `json:"scopes,omitempty"`
}

type RoleStatus struct {
	// AggregatedScopes are scopes folded in from other roles by the role
	// controller per spec.aggregationRule.  Owned by the controller; a
	// role's effective permissions are spec.scopes plus these.
	AggregatedScopes RoleScopes `json:"aggregatedScopes,omitempty"`
	// AggregatedDescriptions are the source roles' descriptions, written in
	// the same reconcile pass as the scopes so the aggregate's
	// documentation cannot drift from its contents.
	// +listType=set
	AggregatedDescriptions []string `json:"aggregatedDescriptions,omitempty"`
	// MissingRoleRefs lists aggregationRule.roleRefs that name roles which
	// do not exist — a configuration error.
	// +listType=set
	MissingRoleRefs []string `json:"missingRoleRefs,omitempty"`
}
```

Create `role_helpers.go`:

```go
package v1alpha1

import (
	"cmp"
	"slices"
)

// MergeRoleScopes returns the union of the supplied scope lists,
// deduplicated by endpoint name with operations unioned, sorted by name
// then operation for stable, diff-friendly output.  Returns nil when the
// union is empty.
func MergeRoleScopes(lists ...[]RoleScope) []RoleScope {
	merged := map[string]map[Operation]struct{}{}

	for _, list := range lists {
		for _, scope := range list {
			if merged[scope.Name] == nil {
				merged[scope.Name] = map[Operation]struct{}{}
			}

			for _, operation := range scope.Operations {
				merged[scope.Name][operation] = struct{}{}
			}
		}
	}

	if len(merged) == 0 {
		return nil
	}

	out := make([]RoleScope, 0, len(merged))

	for name, operations := range merged {
		scope := RoleScope{Name: name, Operations: make([]Operation, 0, len(operations))}

		for operation := range operations {
			scope.Operations = append(scope.Operations, operation)
		}

		slices.Sort(scope.Operations)

		out = append(out, scope)
	}

	slices.SortFunc(out, func(a, b RoleScope) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return out
}

// EffectiveScopes returns the role's spec scopes unioned with any
// controller-aggregated scopes.  All permission consumers (ACL building,
// grantability checks) must use this, not Spec.Scopes directly.
func (r *Role) EffectiveScopes() RoleScopes {
	return RoleScopes{
		Global:       MergeRoleScopes(r.Spec.Scopes.Global, r.Status.AggregatedScopes.Global),
		Organization: MergeRoleScopes(r.Spec.Scopes.Organization, r.Status.AggregatedScopes.Organization),
		Project:      MergeRoleScopes(r.Spec.Scopes.Project, r.Status.AggregatedScopes.Project),
	}
}
```

- [ ] **Step 4: Regenerate, test, commit**

Run: `make generate && go test ./pkg/apis/unikorn/v1alpha1/... -v`
Expected: deepcopy + CRD manifests updated and staged; tests PASS.

```bash
make touch license validate lint generate && make test-unit
git add -A && git commit -m "feat(apis): add role aggregation rule and aggregated status

Part of ID-368 Phase B."
```

---

### Task 8: Fold logic (pure function)

**Files:**
- Create: `pkg/controllers/role/aggregate.go`
- Test: `pkg/controllers/role/aggregate_test.go`

**Interfaces:**
- Consumes: Task 7 types and `MergeRoleScopes`.
- Produces: package `role` with:

```go
type Aggregate struct {
	Scopes          unikornv1.RoleScopes
	Descriptions    []string
	MissingRoleRefs []string
}

func BuildAggregate(target *unikornv1.Role, all []unikornv1.Role) (*Aggregate, error)
```

- [ ] **Step 1: Write the failing tests**

`pkg/controllers/role/aggregate_test.go`:

```go
package role_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/controllers/role"
)

const (
	aggregateLabel = "rbac.unikorn-cloud.org/aggregate-to-administrator"
	descriptionKey = "unikorn-cloud.org/description"
)

func admin() *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "administrator"},
		Spec: unikornv1.RoleSpec{
			AggregationRule: &unikornv1.AggregationRule{
				RoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{aggregateLabel: "true"}}},
			},
		},
	}
}

func source(name string, labels map[string]string, protected bool, scopes unikornv1.RoleScopes) unikornv1.Role {
	return unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      labels,
			Annotations: map[string]string{descriptionKey: name + " capability"},
		},
		Spec: unikornv1.RoleSpec{Protected: protected, Scopes: scopes},
	}
}

func TestAggregateFoldsOrgAndProjectToOrgWithDescriptions(t *testing.T) {
	t.Parallel()

	radar := source("radar", map[string]string{aggregateLabel: "true"}, false, unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{{Name: "radar:config", Operations: []unikornv1.Operation{unikornv1.Read}}},
		Project:      []unikornv1.RoleScope{{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Create}}},
		Global:       []unikornv1.RoleScope{{Name: "radar:fleet", Operations: []unikornv1.Operation{unikornv1.Read}}},
	})

	out, err := role.BuildAggregate(admin(), []unikornv1.Role{radar})
	require.NoError(t, err)

	require.Equal(t, []unikornv1.RoleScope{
		{Name: "radar:config", Operations: []unikornv1.Operation{unikornv1.Read}},
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Create}},
	}, out.Scopes.Organization)
	require.Nil(t, out.Scopes.Global, "global scopes must never fold")
	require.Nil(t, out.Scopes.Project)
	require.Equal(t, []string{"radar capability"}, out.Descriptions)
	require.Empty(t, out.MissingRoleRefs)
}

func TestAggregateUnionsRefsAndSelectors(t *testing.T) {
	t.Parallel()

	labelled := source("labelled", map[string]string{aggregateLabel: "true"}, false, unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{{Name: "a:things", Operations: []unikornv1.Operation{unikornv1.Read}}},
	})
	pinned := source("pinned", nil, false, unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{{Name: "b:things", Operations: []unikornv1.Operation{unikornv1.Read}}},
	})

	target := admin()
	target.Spec.AggregationRule.RoleRefs = []string{"pinned", "gone"}

	out, err := role.BuildAggregate(target, []unikornv1.Role{labelled, pinned})
	require.NoError(t, err)

	require.Len(t, out.Scopes.Organization, 2, "refs and selector matches both fold")
	require.Equal(t, []string{"gone"}, out.MissingRoleRefs, "dangling refs are reported, not fatal")
}

func TestAggregateSkipsUnlabelledProtectedAndSelf(t *testing.T) {
	t.Parallel()

	unlabelled := source("plain", nil, false, unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{{Name: "plain:things", Operations: []unikornv1.Operation{unikornv1.Read}}},
	})
	protected := source("secret", map[string]string{aggregateLabel: "true"}, true, unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{{Name: "secret:things", Operations: []unikornv1.Operation{unikornv1.Read}}},
	})

	target := admin()
	target.Labels = map[string]string{aggregateLabel: "true"}
	target.Spec.Scopes.Organization = []unikornv1.RoleScope{{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create}}}

	out, err := role.BuildAggregate(target, []unikornv1.Role{unlabelled, protected, *target})
	require.NoError(t, err)
	require.Nil(t, out.Scopes.Organization, "unlabelled, protected and self must not fold")
	require.Empty(t, out.Descriptions)
}

func TestAggregateIgnoresSourceStatus(t *testing.T) {
	t.Parallel()

	src := source("other-aggregate", map[string]string{aggregateLabel: "true"}, false, unikornv1.RoleScopes{})
	src.Status.AggregatedScopes.Organization = []unikornv1.RoleScope{{Name: "transitive:things", Operations: []unikornv1.Operation{unikornv1.Read}}}

	out, err := role.BuildAggregate(admin(), []unikornv1.Role{src})
	require.NoError(t, err)
	require.Nil(t, out.Scopes.Organization, "no transitive aggregation")
}

func TestAggregateNoRule(t *testing.T) {
	t.Parallel()

	target := &unikornv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "plain"}}

	out, err := role.BuildAggregate(target, nil)
	require.NoError(t, err)
	require.Equal(t, unikornv1.RoleScopes{}, out.Scopes)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/controllers/role/... -v`
Expected: FAIL (package does not exist)

- [ ] **Step 3: Implement**

`pkg/controllers/role/aggregate.go`:

```go
package role

import (
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

const descriptionAnnotation = "unikorn-cloud.org/description"

// Aggregate is the computed fold of a role's aggregation rule.
type Aggregate struct {
	// Scopes to write to status.aggregatedScopes.
	Scopes unikornv1.RoleScopes
	// Descriptions of the folded sources, for status.aggregatedDescriptions.
	Descriptions []string
	// MissingRoleRefs are roleRefs that named no existing role.
	MissingRoleRefs []string
}

// BuildAggregate applies the target role's aggregation rule over all roles.
// Fold rules (see the role aggregation design doc): source organization and
// project scopes land at organization scope; global scopes never fold
// (cross-organization authority); protected sources never fold; sources
// contribute spec scopes only, so aggregation is not transitive; the target
// never folds into itself.  Sources are the union of roleRefs and
// roleSelectors matches.
func BuildAggregate(target *unikornv1.Role, all []unikornv1.Role) (*Aggregate, error) {
	out := &Aggregate{}

	rule := target.Spec.AggregationRule
	if rule == nil {
		return out, nil
	}

	selectors := make([]labels.Selector, 0, len(rule.RoleSelectors))

	for i := range rule.RoleSelectors {
		selector, err := metav1.LabelSelectorAsSelector(&rule.RoleSelectors[i])
		if err != nil {
			return nil, err
		}

		selectors = append(selectors, selector)
	}

	matches := func(source *unikornv1.Role) bool {
		if slices.Contains(rule.RoleRefs, source.Name) {
			return true
		}

		for _, selector := range selectors {
			if selector.Matches(labels.Set(source.Labels)) {
				return true
			}
		}

		return false
	}

	seen := map[string]bool{}
	scopes := make([][]unikornv1.RoleScope, 0, len(all))

	for i := range all {
		source := &all[i]

		if source.Name == target.Name || source.Spec.Protected || !matches(source) {
			continue
		}

		seen[source.Name] = true
		scopes = append(scopes, source.Spec.Scopes.Organization, source.Spec.Scopes.Project)

		if description, ok := source.Annotations[descriptionAnnotation]; ok && description != "" {
			out.Descriptions = append(out.Descriptions, description)
		}
	}

	for _, ref := range rule.RoleRefs {
		if !seen[ref] && ref != target.Name {
			out.MissingRoleRefs = append(out.MissingRoleRefs, ref)
		}
	}

	out.Scopes.Organization = unikornv1.MergeRoleScopes(scopes...)

	slices.Sort(out.Descriptions)
	out.Descriptions = slices.Compact(out.Descriptions)
	slices.Sort(out.MissingRoleRefs)

	return out, nil
}
```

(Edge case encoded above: a `roleRef` naming a *protected* role is skipped by the fold but NOT reported missing — the role exists; it is just never aggregable. If review prefers reporting it, extend `MissingRoleRefs` semantics then.)

- [ ] **Step 4: Run tests and commit**

Run: `go test ./pkg/controllers/role/... -v`
Expected: PASS (all 5 tests)

```bash
make touch license lint && make test-unit
git add pkg/controllers/role && git commit -m "feat(controllers/role): aggregation fold logic with refs, selectors and descriptions

Part of ID-368 Phase B."
```

---

### Task 9: Role controller — reconciler, manager, binary, image, chart

**Files:**
- Create: `pkg/controllers/role/reconciler.go`, `pkg/controllers/role/manager.go`, `cmd/unikorn-role-controller/main.go`, `docker/unikorn-role-controller/Dockerfile`, `charts/identity/templates/role-controller/{deployment,serviceaccount,role,rolebinding}.yaml`
- Modify: `Makefile` (CONTROLLERS list ~line 15), `charts/identity/templates/_helpers.tpl` (~line 12), `charts/identity/values.yaml` (`roleController:` block; `administrator` AND `auditor` gain `aggregationRule`; roles template renders `labels`/`aggregationRule`), `charts/identity/templates/roles.yaml`
- Test: `pkg/controllers/role/reconciler_test.go`

**Interfaces:**
- Consumes: `BuildAggregate` (Task 8), CRD fields (Task 7).
- Produces: `role.NewReconciler(client)`, `role.Factory{}` (a `coremanager.ControllerFactory`); chart deploys `unikorn-role-controller`; `administrator` aggregates `aggregate-to-administrator`, `auditor` aggregates `aggregate-to-auditor` (maintainer condition 1 — whole lattice).

- [ ] **Step 1: Write the failing reconciler test**

`pkg/controllers/role/reconciler_test.go`:

```go
package role_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/controllers/role"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	return scheme
}

func TestReconcileWritesAndWithdrawsAggregatedStatus(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	adminRole := admin() // from aggregate_test.go
	adminRole.Namespace = "identity"

	radar := source("radar", map[string]string{aggregateLabel: "true"}, false, unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}}},
	})
	radar.Namespace = "identity"

	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&unikornv1.Role{}).
		WithObjects(adminRole, &radar).
		Build()

	reconciler := role.NewReconciler(cli)
	key := types.NamespacedName{Namespace: "identity", Name: "administrator"}

	_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	updated := &unikornv1.Role{}
	require.NoError(t, cli.Get(ctx, key, updated))
	require.Equal(t, []unikornv1.RoleScope{
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
	}, updated.Status.AggregatedScopes.Organization)
	require.Equal(t, []string{"radar capability"}, updated.Status.AggregatedDescriptions)

	// Deleting the source withdraws permissions AND descriptions.
	require.NoError(t, cli.Delete(ctx, &radar))

	_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	require.NoError(t, cli.Get(ctx, key, updated))
	require.Nil(t, updated.Status.AggregatedScopes.Organization)
	require.Empty(t, updated.Status.AggregatedDescriptions)
}

func TestReconcileReportsMissingRefs(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	target := admin()
	target.Namespace = "identity"
	target.Spec.AggregationRule.RoleRefs = []string{"gone"}

	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithStatusSubresource(&unikornv1.Role{}).WithObjects(target).Build()
	reconciler := role.NewReconciler(cli)
	key := types.NamespacedName{Namespace: "identity", Name: "administrator"}

	_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	updated := &unikornv1.Role{}
	require.NoError(t, cli.Get(ctx, key, updated))
	require.Equal(t, []string{"gone"}, updated.Status.MissingRoleRefs)
}

func TestReconcileIgnoresNonAggregatingAndMissingRoles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	plain := source("plain", nil, false, unikornv1.RoleScopes{})
	plain.Namespace = "identity"

	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithStatusSubresource(&unikornv1.Role{}).WithObjects(&plain).Build()
	reconciler := role.NewReconciler(cli)

	_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "identity", Name: "plain"}})
	require.NoError(t, err)

	_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "identity", Name: "missing"}})
	require.NoError(t, err)
}
```

Run: `go test ./pkg/controllers/role/... -run TestReconcile -v`
Expected: FAIL (`role.NewReconciler` undefined)

- [ ] **Step 2: Implement the reconciler**

`pkg/controllers/role/reconciler.go`:

```go
package role

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// Reconciler maintains aggregated status on aggregating roles.  It is a
// custom fan-in reconciler (one output derived from many inputs) rather
// than a coremanager provisioner, which models per-object lifecycles.
type Reconciler struct {
	client client.Client
}

func NewReconciler(client client.Client) *Reconciler {
	return &Reconciler{client: client}
}

var _ reconcile.Reconciler = &Reconciler{}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	target := &unikornv1.Role{}

	if err := r.client.Get(ctx, req.NamespacedName, target); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	if target.Spec.AggregationRule == nil {
		return reconcile.Result{}, nil
	}

	all := &unikornv1.RoleList{}

	if err := r.client.List(ctx, all, &client.ListOptions{Namespace: req.Namespace}); err != nil {
		return reconcile.Result{}, err
	}

	aggregate, err := BuildAggregate(target, all.Items)
	if err != nil {
		return reconcile.Result{}, err
	}

	desired := unikornv1.RoleStatus{
		AggregatedScopes:       aggregate.Scopes,
		AggregatedDescriptions: aggregate.Descriptions,
		MissingRoleRefs:        aggregate.MissingRoleRefs,
	}

	if equality.Semantic.DeepEqual(target.Status, desired) {
		return reconcile.Result{}, nil
	}

	updated := target.DeepCopy()
	updated.Status = desired

	return reconcile.Result{}, r.client.Status().Patch(ctx, updated, client.MergeFrom(target))
}
```

- [ ] **Step 3: Manager, binary, image, Makefile**

`pkg/controllers/role/manager.go` — mirror `pkg/controllers/organization/manager.go` exactly (Metadata/Options/Reconciler/RegisterWatches plus any further interface methods that file implements), with:

```go
// Reconciler returns a new reconciler instance.
func (*Factory) Reconciler(_ *options.Options, _ coremanager.ControllerOptions, manager manager.Manager) reconcile.Reconciler {
	return NewReconciler(manager.GetClient())
}

// RegisterWatches adds any watches that would trigger a reconcile.  Any
// role event re-enqueues every aggregating role in that namespace (fan-in).
func (*Factory) RegisterWatches(manager manager.Manager, controller controller.Controller) error {
	mapper := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, changed *unikornv1.Role) []reconcile.Request {
		all := &unikornv1.RoleList{}

		if err := manager.GetClient().List(ctx, all, &client.ListOptions{Namespace: changed.Namespace}); err != nil {
			return nil
		}

		var requests []reconcile.Request

		for i := range all.Items {
			if all.Items[i].Spec.AggregationRule == nil {
				continue
			}

			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: all.Items[i].Namespace, Name: all.Items[i].Name},
			})
		}

		return requests
	})

	return controller.Watch(source.Kind(manager.GetCache(), &unikornv1.Role{}, mapper))
}
```

(Match `handler.TypedEnqueueRequestsFromMapFunc`/`source.Kind` call shapes to the pinned controller-runtime version — the organization manager is the reference.)

`cmd/unikorn-role-controller/main.go`:

```go
package main

import (
	"github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/identity/pkg/controllers/role"
)

func main() {
	manager.Run(&role.Factory{})
}
```

`docker/unikorn-role-controller/Dockerfile` — copy `docker/unikorn-organization-controller/Dockerfile`, replacing the binary name with `unikorn-role-controller`.

`Makefile` — append `unikorn-role-controller` to the `CONTROLLERS` list (~line 15).

Run: `go build ./cmd/unikorn-role-controller && go test ./pkg/controllers/role/... -v`
Expected: builds clean, tests PASS.

- [ ] **Step 4: Chart — controller deployment, RBAC, aggregation wiring**

Copy `charts/identity/templates/organization-controller/{deployment,serviceaccount,role,rolebinding}.yaml` to `charts/identity/templates/role-controller/`, replacing `organization-controller`→`role-controller` and `organizationController(Image)`→`roleController(Image)`. No clusterrole — this controller is namespace-local. In `role.yaml`, keep the lease/event rules verbatim and set the resource rules to exactly:

```yaml
- apiGroups:
  - identity.unikorn-cloud.org
  resources:
  - roles
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - identity.unikorn-cloud.org
  resources:
  - roles/status
  verbs:
  - update
  - patch
```

`_helpers.tpl`:

```yaml
{{- define "unikorn.roleControllerImage" -}}
{{- .Values.roleController.image | default (printf "%s/unikorn-role-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default (include "unikorn.defaultTag" .))) }}
{{- end }}
```

`values.yaml` — new block after `organizationController:`:

```yaml
# Role controller specific configuration.
roleController:
  # Allows override of the image.
  image:

  # Allows resource limits to be set.
  resources:
    limits:
      cpu: 100m
      memory: 100Mi
```

`templates/roles.yaml` — render optional per-role `labels` and `aggregationRule`:

```yaml
  labels:
    {{- include "unikorn.labels" $ | nindent 4 }}
    unikorn-cloud.org/name: {{ $name }}
    {{- with $spec.labels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
```

and inside `spec:` before the `scopes` block:

```yaml
  {{- with $spec.aggregationRule }}
  aggregationRule:
    {{- toYaml . | nindent 4 }}
  {{- end }}
```

`values.yaml` — both lattice positions aggregate (maintainer condition 1):

```yaml
  administrator:
    description: Organization administrator
    aggregationRule:
      roleSelectors:
      - matchLabels:
          rbac.unikorn-cloud.org/aggregate-to-administrator: "true"
    scopes:
      ...unchanged...
  auditor:
    description: Organization auditor
    aggregationRule:
      roleSelectors:
      - matchLabels:
          rbac.unikorn-cloud.org/aggregate-to-auditor: "true"
    scopes:
      ...unchanged...
```

Run: `make validate`
Expected: PASS; rendered `administrator` and `auditor` Roles carry their rules; no other role changes.

- [ ] **Step 5: Full checks and commit**

```bash
make touch license validate lint generate && make test-unit
git add -A && git commit -m "feat(controllers/role): role aggregation controller, chart wiring for administrator and auditor

Part of ID-368 Phase B."
```

---

### Task 10: Consume effective scopes — ACL builder, AllowRole, lattice guard

**Files:**
- Modify: `pkg/rbac/rbac.go` (`accumulateGlobalPermissions` ~378, `accumulateOrganizationPermissions` ~393, `accumulateProjectPermissions` ~413), `pkg/rbac/handler.go` (`AllowRole` ~361), `pkg/rbac/grant_guard_test.go`
- Test: `pkg/rbac/aggregation_test.go` (new)

**Interfaces:**
- Consumes: `EffectiveScopes()` (Task 7), `role.BuildAggregate` (Task 8).
- Produces: ACLs and grant checks computed over effective scopes; guard test asserts lattice consistency over aggregated roles. No signature changes.

- [ ] **Step 1: Write the failing test**

`pkg/rbac/aggregation_test.go` — mirror the ACL-construction idiom from `grant_guard_test.go` (`aclForHolder`, typed organization ID):

```go
func TestAllowRoleUsesEffectiveScopes(t *testing.T) {
	t.Parallel()

	// radar: org + project scoped third-party permissions, labelled for admin.
	radar := unikornv1.Role{ /* as Task 8's source(), with radar:config org read + radar:things project create */ }

	admin := &unikornv1.Role{ /* administrator with RoleSelectors matching the label, org block: identity:groups CRUD */ }

	aggregate, err := controllerrole.BuildAggregate(admin, []unikornv1.Role{radar})
	require.NoError(t, err)
	admin.Status.AggregatedScopes = aggregate.Scopes

	// A caller holding ONLY admin's spec scopes cannot grant radar, and can
	// no longer grant admin itself (admin now conveys radar too).
	bare := rbac.NewContext(context.Background(), aclWithOrgEndpoints(openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
	}))
	require.Error(t, rbac.AllowRole(bare, &radar, orgID))
	require.Error(t, rbac.AllowRole(bare, admin, orgID), "granting admin must require its aggregated permissions too")

	// A caller with the post-aggregation ACL can grant both.
	full := rbac.NewContext(context.Background(), aclWithOrgEndpoints(openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
		{Name: "radar:config", Operations: openapi.AclOperations{openapi.Read}},
		{Name: "radar:things", Operations: openapi.AclOperations{openapi.Create}},
	}))
	require.NoError(t, rbac.AllowRole(full, &radar, orgID))
	require.NoError(t, rbac.AllowRole(full, admin, orgID))
}
```

(Write the two role literals out in full — the Task 8 test constructors show the exact shape; keep the `openapi.AclOperation` constant style used by `grant_guard_test.go`.)

Run: `go test ./pkg/rbac/... -run TestAllowRoleUsesEffectiveScopes -v`
Expected: FAIL on the second assertion — today `AllowRole` reads `Spec.Scopes` only, so the bare ACL wrongly suffices to grant the aggregated admin role.

- [ ] **Step 2: Switch AllowRole and the ACL builder to effective scopes**

`pkg/rbac/handler.go` — `AllowRole` starts with `scopes := role.EffectiveScopes()` and the three loops iterate `scopes.Global/Organization/Project` (bodies unchanged; update the doc comment).

`pkg/rbac/rbac.go` — the three `accumulate*Permissions` functions read `role.EffectiveScopes().Global/Organization/Project` instead of `role.Spec.Scopes.*`.

Run: `go test ./pkg/rbac/... -v`
Expected: PASS (existing tests use spec-only roles, for which effective == spec).

- [ ] **Step 3: Lattice guard over aggregated roles (maintainer condition 1)**

In `grant_guard_test.go`: extend `chartRole` with `AggregationRule *unikornv1.AggregationRule \`json:"aggregationRule"\`` (Labels was added in Phase A Task 4). Add:

```go
// TestAggregatedLatticeConsistency asserts that aggregation cannot reproduce
// the application:* failure: any source role grantable by a lattice position
// must be grantable by every position above it.  Concretely: everything
// auditor aggregates must also be grantable by administrator post-aggregation.
func TestAggregatedLatticeConsistency(t *testing.T) {
	t.Parallel()

	chartRoles := loadChartRoles(t)

	// Materialise chart roles as CRs, labels and rules included.
	all := make([]unikornv1.Role, 0, len(chartRoles))
	byName := map[string]*unikornv1.Role{}

	for name, chartRole := range chartRoles {
		resource := asRole(chartRole) // extend asRole to carry Labels and AggregationRule
		resource.Name = name
		all = append(all, *resource)
		byName[name] = resource
	}

	// Simulate the controller over administrator and auditor.
	for _, aggregating := range []string{"administrator", "auditor"} {
		target := byName[aggregating]
		require.NotNil(t, target)

		aggregate, err := controllerrole.BuildAggregate(target, all)
		require.NoError(t, err)

		target.Status.AggregatedScopes = aggregate.Scopes
	}

	adminACL := rbac.NewContext(context.Background(), aclForEffectiveHolder(byName["administrator"]))

	// Everything auditor can grant, administrator must be able to grant.
	for name, resource := range byName {
		if resource.Spec.Protected {
			continue
		}

		auditorACL := rbac.NewContext(context.Background(), aclForEffectiveHolder(byName["auditor"]))

		if rbac.AllowRole(auditorACL, resource, organizationID) != nil {
			continue // auditor cannot grant it; no constraint on admin
		}

		require.NoError(t, rbac.AllowRole(adminACL, resource, organizationID),
			"role %q is grantable by auditor but not administrator — lattice violation (ID-368)", name)
	}
}
```

`aclForEffectiveHolder` is `aclForHolder` computed over `EffectiveScopes()` instead of the chart scopes — add it beside the existing helper. Extend `asRole` to copy `Labels` into `ObjectMeta.Labels` and `AggregationRule` into the spec.

Run: `go test ./pkg/rbac/... -v`
Expected: PASS (built-in chart carries no labelled sources yet; the test bites when third-party/`additionalRoles` entries appear — which is its job).

- [ ] **Step 4: Commit**

```bash
make touch license lint && make test-unit
git add pkg/rbac && git commit -m "feat(rbac): compute ACLs and grantability over effective role scopes, guard the aggregated lattice

Part of ID-368 Phase B."
```

---

### Task 11: Roles API — expose effective scopes and composed description

**Files:**
- Modify: `pkg/openapi/server.spec.yaml` (`roleRead` ~1993), `pkg/handler/roles/client.go`
- Test: extend `pkg/handler/roles/client_test.go` (from Phase A Task 2)

**Interfaces:**
- Consumes: `EffectiveScopes()`, `status.aggregatedDescriptions`.
- Produces: `roleRead.scopes` (effective, reusing the existing `aclEndpoints` schema shape) and `roleRead.aggregatedDescriptions` ([]string). The API's answer about a role now says what it holds (maintainer condition 2).

- [ ] **Step 1: Extend the schema and regenerate**

In `server.spec.yaml`, extend `roleRead` (which gained `grantable` in Phase A):

```yaml
        scopes:
          description: |-
            The role's effective permissions, including any aggregated from
            other roles by the role controller.
          type: object
          properties:
            global:
              $ref: '#/components/schemas/aclEndpoints'
            organization:
              $ref: '#/components/schemas/aclEndpoints'
            project:
              $ref: '#/components/schemas/aclEndpoints'
        aggregatedDescriptions:
          description: |-
            Descriptions of roles aggregated into this one. Together with the
            role's own description this documents what the role currently
            grants.
          type: array
          items:
            type: string
```

(Verify the `aclEndpoints` schema name in the file — it is referenced by the ACL endpoints; use the exact key.)

Run: `make generate && go build ./...`
Expected: `RoleRead` gains `Scopes` and `AggregatedDescriptions`; handler compiles (new fields optional) — the failing test in Step 2 drives the wiring.

- [ ] **Step 2: Failing test, then wire the handler**

Append to `pkg/handler/roles/client_test.go`:

```go
func TestListExposesEffectiveScopesAndDescriptions(t *testing.T) {
	t.Parallel()

	// as TestListReturnsUngrantableRolesWithFlag's setup, plus:
	aggregated := newRole("administrator", false, []unikornv1.RoleScope{
		{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Create}},
	})
	aggregated.Status.AggregatedScopes.Organization = []unikornv1.RoleScope{
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
	}
	aggregated.Status.AggregatedDescriptions = []string{"Radar fleet management"}

	// ...build client with this role, list, then:
	role := byName["administrator"]
	require.NotNil(t, role.Scopes)
	require.NotNil(t, role.Scopes.Organization)
	// Effective scopes include both spec and aggregated endpoints.
	names := []string{}
	for _, e := range *role.Scopes.Organization {
		names = append(names, e.Name)
	}
	require.ElementsMatch(t, []string{"identity:groups", "radar:things"}, names)
	require.Equal(t, []string{"Radar fleet management"}, *role.AggregatedDescriptions)
}
```

Implement in `convert` (which already takes `grantable`): map `in.EffectiveScopes()` to the generated scopes type (small local loop converting `[]RoleScope` → `openapi.AclEndpoints`, operation names are identical strings), and copy `Status.AggregatedDescriptions` when non-empty. Fake-client note: build it `WithStatusSubresource(&unikornv1.Role{})` and set status after create, or construct the object with status populated — match what the Task 9 reconciler test does.

Run: `go test ./pkg/handler/roles/... -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
make touch license validate lint generate && make test-unit
git add -A && git commit -m "feat(handler/roles): expose effective scopes and aggregated descriptions on roleRead

Part of ID-368 Phase B."
```

---

### Task 12: Membership enforcement parity — DECISION GATE

**Do not start until the maintainer rules on gated-vs-ungated membership** (spec, "Handler and API changes" item 4).

**If the ruling is UNGATED:** no code. Document the rule ("membership changes are administration on every path; role-list changes are grants") in `pkg/handler/users/README.md`, `pkg/handler/serviceaccounts/README.md`, `pkg/handler/groups/README.md`, and close the ID-367 linkage accordingly. Fold into Task 14's docs commit.

**If the ruling is GATED:**

**Files:**
- Create: `pkg/handler/common/membership.go`
- Modify: `pkg/handler/users/client.go` (`updateGroups` ~122, call sites ~433/~520/~556), `pkg/handler/serviceaccounts/client.go` (`updateGroups` ~207, call sites ~264/~356/~425)
- Test: `pkg/handler/common/membership_test.go`

**Interfaces:**
- Produces: `func AllowGroupMembershipChange(ctx context.Context, cli client.Client, namespace string, organizationID ids.OrganizationID, group *unikornv1.Group) error`; both handlers' `updateGroups` gain trailing `organizationID ids.OrganizationID, enforceGrant bool` parameters — create/update pass `true`, **delete passes `false`** (principal deletion is cleanup, not a privilege change; gating it would block deleting principals in groups with ungrantable roles).

- [ ] **Step 1: Failing test** — `membership_test.go`: caller without the group's role permissions is refused with the role named; caller holding them passes; dangling role reference passes. Same fake-client + `rbac.NewContext` pattern as the groups tests.
- [ ] **Step 2: Implement** — `AllowGroupMembershipChange` loops the group's `RoleIDs`, `Get`s each role (NotFound → continue), `rbac.AllowRole` over it (effective scopes via Task 10), refusing with an `errors.HTTPForbidden` naming the role.
- [ ] **Step 3: Wire both handlers** — inside each `updateGroups` loop, when a group's membership actually changes and `enforceGrant` is true, call the helper before patching. The compiler finds every call site via the signature change.
- [ ] **Step 4: Tests, checks, commit** as usual — `go build ./... && make test-unit`, commit `fix(handler): enforce the group grant rule on user and service account membership changes`.

---

### Task 13: Integration tests — aggregation end-to-end

**Files:**
- Create: `test/api/suites/role_aggregation_test.go`
- Consumes: `test/api/k8s.go` helpers from Phase A Task 5, suite variables from `suite_test.go`.

- [ ] **Step 1: The suite** (`//go:build integration`, BDD structure, license header). Fixture: labelled radar-shaped Role CR via `api.InstallFixture` with `DeferCleanup`, name suffixed `GinkgoParallelProcess()`. Cases:

```go
var _ = Describe("Role Aggregation", func() {
	Context("When a third-party role is labelled for administrator aggregation", func() {
		Describe("Given the labelled fixture role is installed", func() {
			// fixture: org scope radar:config [read], project scope
			// radar:things [create]  <- MUTATING project-scoped permission,
			// maintainer condition 4.

			It("should become grantable and appear in admin's effective scopes", func() {
				// Eventually (60s/2s): ListRoles shows fixture Grantable:true.
				// And the administrator roleRead.Scopes.Organization contains
				// radar:config AND radar:things (project promoted to org),
				// and AggregatedDescriptions contains the fixture description.
				// Record the observed promotion in the design doc per AC 11.
			})

			It("should let the admin grant it and manage the group", func() {
				// CreateGroupWithCleanup with the fixture role ID; update
				// members; assert both succeed and role list survives.
			})

			It("should withdraw permissions when the label is removed", func() {
				// Patch fixture removing the label (k8s client, MergeFrom).
				// Eventually: Grantable false; admin roleRead scopes no longer
				// contain radar endpoints; group role-grant now refused with
				// the role named.
			})
		})
	})

	Context("When a read-only role is labelled for auditor and administrator", func() {
		Describe("Given the lattice labels are applied", func() {
			It("should fold into both roles' effective scopes", func() {
				// Fixture with both aggregate-to-auditor and
				// aggregate-to-administrator labels, read-only org scope.
				// Eventually: BOTH administrator and auditor roleRead.Scopes
				// contain the endpoint (observable via the admin client);
				// fixture shows Grantable:true for the admin caller.
			})
		})
	})
})
```

Write the bodies in full following the Phase A suite's idioms (`client.ListRoles(ctx, config.OrgID)`, typed group update wrappers, `Eventually` with 60s/2s). The comments above define the exact assertions each `It` must make.

- [ ] **Step 2: Run** per the README's integration target; fix any `roles_test.go` assertions broken by the new `scopes` field.
- [ ] **Step 3: Commit** — `test(integration): role aggregation end-to-end, lattice and mutating-fold coverage`.

---

### Task 14: Documentation and fold-outcome record

**Files:**
- Modify: `pkg/rbac/README.md`, `pkg/handler/roles/README.md`, `pkg/handler/groups/README.md`, `pkg/controllers/README.md`, `pkg/apis/unikorn/v1alpha1/README.md`, top-level `README.md` ("3rd Party User RBAC" ~line 356), `docs/superpowers/specs/2026-07-28-role-aggregation-design.md`
- Create: `pkg/controllers/role/README.md`

- [ ] **Step 1: Update the docs**

- Top-level README "3rd Party User RBAC": the label instruction, including the lattice requirement —

```markdown
* To make a role manageable by organization administrators, label it
  `rbac.unikorn-cloud.org/aggregate-to-administrator: "true"`.  A role must
  opt into every built-in role that should be able to grant it: label
  read-only roles with BOTH `aggregate-to-auditor` and
  `aggregate-to-administrator`, otherwise auditors could grant something
  administrators cannot.  Global scopes and protected roles are never
  aggregated.  Fill the role's description — it becomes part of the
  aggregating role's documented contents.
```

- `pkg/controllers/role/README.md`: purpose, fold rules, refs-vs-selectors semantics, `missingRoleRefs`, ownership split (helm owns spec, controller owns status), trust argument.
- `pkg/rbac/README.md`: grant lattice caveat gains the aggregation story; grantability computed over effective scopes; the lattice guard.
- `pkg/apis/unikorn/v1alpha1/README.md`: new fields; `EffectiveScopes()` as the mandatory accessor.
- `pkg/controllers/README.md`, `pkg/handler/roles/README.md`, `pkg/handler/groups/README.md`: one-paragraph updates each; link the new controller README.
- **Design doc**: record the observed mutating project→org fold consequence from Task 13 (maintainer condition 4 — "record that and move on"), plus Task 12's ruling and outcome.

- [ ] **Step 2: Full pre-push checklist and commit**

```bash
make touch license validate lint generate
[[ -z $(git status --porcelain) ]] || echo "UNCOMMITTED CHANGES - investigate"
make test-unit
git add -A && git commit -m "docs: role aggregation across rbac, handlers, controllers and 3rd party RBAC

Part of ID-368 Phase B."
```

Hand off for PR against `main` (do not push without the user's say-so).

---

## Regression coverage map (ticket AC → test)

| Ticket AC | Test |
|---|---|
| A1 member management unblocked | `TestValidateRoleIDsChecksOnlyAdditions` (unit); "let the admin change members" (integration, Task 5) |
| A2 readable roles / filter split | `TestListReturnsUngrantableRolesWithFlag` (unit); "list the role as visible but not grantable" (integration) |
| A3 no silent revocation | `TestValidateRoleRemovalsRejectsUngrantableDrop` (unit); "refuse to drop the role, naming it" (integration) |
| A4 actionable errors | error-content assertions inside A1/A3 tests (`require.Contains(err, "radar")`) |
| A5 additionalRoles in CI | `TestNonBuiltinRolesAdminGrantable` (guard) |
| B7 aggregation rule | `TestAggregateUnionsRefsAndSelectors`, `TestAggregateSkipsUnlabelledProtectedAndSelf`, `TestAggregateNoRule` |
| B8 controller add/withdraw + descriptions | `TestReconcileWritesAndWithdrawsAggregatedStatus`, `TestReconcileReportsMissingRefs` |
| B9 whole lattice | `TestAggregatedLatticeConsistency` (guard); read-only dual-label integration case |
| B10 aggregate says what it holds | `TestListExposesEffectiveScopesAndDescriptions` (unit); scope assertions in Task 13 |
| B11 end-to-end + mutating fold | Task 13 suite, first Context (mutating `radar:things [create]` fixture) |
| B12 enforcement parity | Task 12 (per ruling): `membership_test.go` or documented ungated rule |
| Escalation invariant regression (never weaken) | `TestBuiltinRoleGrantability` (existing, untouched); `TestAllowRoleUsesEffectiveScopes` (grant of aggregate requires aggregated permissions) |
