/*
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/controller"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	testNamespace = "test-namespace"
	configMapName = "identity-cerbos-policies"
)

// errGateRefused is the failure injected into the fake gate; the reconciler
// must surface it verbatim so callers can classify the refusal.
var errGateRefused = errors.New("gate refused")

// fakeGate stubs the exec'd compile gate so the reconciler's publish logic
// can be unit tested without Docker or a cerbos binary.
type fakeGate struct {
	calls int
	err   error
}

func (g *fakeGate) Compile(_ context.Context, _ string) error {
	g.calls++

	return g.err
}

// newRole builds a minimal valid Role granting read on the given endpoint at
// organization scope, mirroring the fixture roles the generate package tests
// use.
func newRole(id, endpoint string) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      id,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{
						Name:       endpoint,
						Operations: []unikornv1.Operation{unikornv1.Read},
					},
				},
			},
		},
	}
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, unikornv1.AddToScheme(s))

	return s
}

func newClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	return fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objects...).Build()
}

func newReconciler(c client.Client, gate controller.CompileGate, recorder record.EventRecorder) *controller.Reconciler {
	options := &controller.Options{
		ConfigMapName: configMapName,
		CerbosBinary:  "/usr/local/bin/cerbos",
	}

	return controller.New(c, recorder, testNamespace, options, gate)
}

func doReconcile(t *testing.T, r *controller.Reconciler) {
	t.Helper()

	result, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, result)
}

// getConfigMap fetches the published policy store ConfigMap.
func getConfigMap(t *testing.T, c client.Client) *corev1.ConfigMap {
	t.Helper()

	configMap := &corev1.ConfigMap{}
	require.NoError(t, c.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: configMapName}, configMap))

	return configMap
}

// expectedData computes the ConfigMap data the reconciler must publish for
// the given roles.  The content is generate.Generate's byte-exact output; the
// keys re-encode the hash-suffix contract independently of the implementation
// (base "-" first-8-hex-of-sha256 ".yaml") so a drift in the published key
// scheme fails here even if the implementation is self-consistent.
func expectedData(t *testing.T, roles ...*unikornv1.Role) map[string]string {
	t.Helper()

	items := make([]unikornv1.Role, len(roles))
	for i := range roles {
		items[i] = *roles[i]
	}

	output, err := generate.Generate(items)
	require.NoError(t, err)

	files, err := output.Files()
	require.NoError(t, err)

	data := map[string]string{}

	for name, content := range files {
		sum := sha256.Sum256(content)
		key := strings.TrimSuffix(name, ".yaml") + "-" + hex.EncodeToString(sum[:])[:8] + ".yaml"
		data[key] = string(content)
	}

	return data
}

// TestReconcileCreatesConfigMap pins the happy path: with no ConfigMap yet
// (the steady state after the one-time A1->A3 upgrade deletes the Helm-owned
// one), a reconcile generates policies from the Roles in the namespace,
// passes the compile gate once and creates the ConfigMap with hash-suffixed
// keys and the managed-by label.
func TestReconcileCreatesConfigMap(t *testing.T) {
	t.Parallel()

	roleA := newRole("role-a", "identity:groups")
	roleB := newRole("role-b", "identity:projects")

	c := newClient(t, roleA, roleB)
	gate := &fakeGate{}

	doReconcile(t, newReconciler(c, gate, record.NewFakeRecorder(8)))

	configMap := getConfigMap(t, c)
	require.Equal(t, expectedData(t, roleA, roleB), configMap.Data)
	require.Empty(t, configMap.BinaryData)
	require.Equal(t, "unikorn-policy-controller", configMap.Labels["app.kubernetes.io/managed-by"])
	require.Equal(t, 1, gate.calls)
}

// TestReconcileUnchangedContentIsNoOp pins the no-op path: when the existing
// ConfigMap data is already identical the reconciler must not run the gate
// nor issue any write (the hash-suffixed key set encodes the content, so an
// update would be pure churn and, worse, harmless-looking writes would mask
// publish bugs).
func TestReconcileUnchangedContentIsNoOp(t *testing.T) {
	t.Parallel()

	role := newRole("role-a", "identity:groups")

	c := newClient(t, role)
	gate := &fakeGate{}
	r := newReconciler(c, gate, record.NewFakeRecorder(8))

	doReconcile(t, r)

	published := getConfigMap(t, c)

	doReconcile(t, r)

	unchanged := getConfigMap(t, c)
	require.Equal(t, published.ResourceVersion, unchanged.ResourceVersion, "an unchanged store must not be rewritten")
	require.Equal(t, 1, gate.calls, "an unchanged store must not be recompiled")
}

// TestReconcileGateRefusalKeepsLastGood pins the fail-closed contract: when
// the compile gate refuses the candidate store the reconciler must surface
// the error, emit a warning event, and leave the last-good ConfigMap
// byte-identical — a broken store must never be published.
func TestReconcileGateRefusalKeepsLastGood(t *testing.T) {
	t.Parallel()

	roleA := newRole("role-a", "identity:groups")

	c := newClient(t, roleA)
	gate := &fakeGate{}
	recorder := record.NewFakeRecorder(8)
	r := newReconciler(c, gate, recorder)

	doReconcile(t, r)

	lastGood := getConfigMap(t, c)

	// A new role arrives but the candidate store now fails the gate.
	require.NoError(t, c.Create(t.Context(), newRole("role-b", "identity:projects")))

	gate.err = errGateRefused

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, errGateRefused)

	kept := getConfigMap(t, c)
	require.Equal(t, lastGood.Data, kept.Data, "a refused store must leave the last-good policies untouched")
	require.Equal(t, lastGood.ResourceVersion, kept.ResourceVersion)

	select {
	case event := <-recorder.Events:
		require.Contains(t, event, corev1.EventTypeWarning)
		require.Contains(t, event, "PolicyStoreRejected")
	default:
		require.Fail(t, "expected a warning event for the refused store")
	}
}

// TestReconcileOversizeRefusalKeepsLastGood pins the size-gate fail-closed
// contract, the sibling of the compile gate: when the candidate store would
// exceed the configured ConfigMap ceiling the reconciler must surface
// ErrPolicyStoreTooLarge, emit a PolicyStoreTooLarge warning event, and leave
// the last-good ConfigMap byte-identical.  Without this gate an over-cap store
// fails publish as an opaque error and silently freezes at last-good with no
// dedicated signal — A22 turns that silent freeze into a legible refusal.
func TestReconcileOversizeRefusalKeepsLastGood(t *testing.T) {
	t.Parallel()

	// Seed a last-good store that differs from what the role generates, so
	// the reconcile is not a no-op and actually reaches the size gate.
	lastGood := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      configMapName,
		},
		Data: map[string]string{"last-good.yaml": "keep me"},
	}

	c := newClient(t, newRole("role-a", "identity:groups"), lastGood)
	gate := &fakeGate{}
	recorder := record.NewFakeRecorder(8)

	// A tiny ceiling refuses any non-empty candidate.  The gate is left
	// passing, so a refusal proves the SIZE gate fired — and it must run
	// before the compile gate (cheap-first), which the gate.calls == 0
	// assertion below pins.
	options := &controller.Options{
		ConfigMapName:       configMapName,
		CerbosBinary:        "/usr/local/bin/cerbos",
		MaxPolicyStoreBytes: 8,
	}
	r := controller.New(c, recorder, testNamespace, options, gate)

	seeded := getConfigMap(t, c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrPolicyStoreTooLarge)

	kept := getConfigMap(t, c)
	require.Equal(t, seeded.Data, kept.Data, "an oversize store must leave the last-good policies untouched")
	require.Equal(t, seeded.ResourceVersion, kept.ResourceVersion, "a refused store must not write the ConfigMap")
	require.Equal(t, 0, gate.calls, "the size gate must refuse before the compile gate runs")

	select {
	case event := <-recorder.Events:
		require.Contains(t, event, corev1.EventTypeWarning)
		require.Contains(t, event, "PolicyStoreTooLarge")
	default:
		require.Fail(t, "expected a warning event for the oversize store")
	}
}

// TestReconcileGateRefusalDoesNotCreate pins the fail-closed contract for
// first publish: if the very first candidate store is refused, no ConfigMap
// may appear — the sidecar keeps serving deny-by-default from its empty
// (optional) volume.
func TestReconcileGateRefusalDoesNotCreate(t *testing.T) {
	t.Parallel()

	c := newClient(t, newRole("role-a", "identity:groups"))
	r := newReconciler(c, &fakeGate{err: errGateRefused}, record.NewFakeRecorder(8))

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, errGateRefused)

	configMap := &corev1.ConfigMap{}
	getErr := c.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: configMapName}, configMap)
	require.True(t, kerrors.IsNotFound(getErr), "a refused first publish must not create the ConfigMap")
}

// TestReconcileRoleDeletionShrinksStore pins that a Role deletion (which the
// watch predicate re-triggers on) regenerates the store without the deleted
// role: its resource policy keys disappear and the shared derived-roles
// document swaps to a new hash-suffixed key.
func TestReconcileRoleDeletionShrinksStore(t *testing.T) {
	t.Parallel()

	roleA := newRole("role-a", "identity:groups")
	roleB := newRole("role-b", "identity:projects")

	c := newClient(t, roleA, roleB)
	gate := &fakeGate{}
	r := newReconciler(c, gate, record.NewFakeRecorder(8))

	doReconcile(t, r)

	before := getConfigMap(t, c)
	require.Len(t, before.Data, 3, "derived roles + one resource policy per endpoint")

	require.NoError(t, c.Delete(t.Context(), roleB))

	doReconcile(t, r)

	after := getConfigMap(t, c)
	require.Equal(t, expectedData(t, roleA), after.Data)

	for key := range after.Data {
		require.NotContains(t, key, "projects", "the deleted role's resource policy must be gone")
	}
}

// TestReconcileRecreatesDeletedConfigMap pins NotFound handling: if the
// ConfigMap disappears (helm upgrade pruning, operator error) the next
// reconcile re-gates and recreates it from the Roles rather than assuming
// last-published state.
func TestReconcileRecreatesDeletedConfigMap(t *testing.T) {
	t.Parallel()

	role := newRole("role-a", "identity:groups")

	c := newClient(t, role)
	gate := &fakeGate{}
	r := newReconciler(c, gate, record.NewFakeRecorder(8))

	doReconcile(t, r)

	published := getConfigMap(t, c)
	require.NoError(t, c.Delete(t.Context(), published))

	doReconcile(t, r)

	recreated := getConfigMap(t, c)
	require.Equal(t, published.Data, recreated.Data)
	require.Equal(t, 2, gate.calls, "recreation must re-run the compile gate")
}

// TestReconcileEmptyRoleSetPublishesEmptyStore pins the zero-role case: an
// empty store is valid (Cerbos serves deny-by-default from an empty policy
// directory), there is nothing to compile, and the ConfigMap is still
// published so ownership is visible.
func TestReconcileEmptyRoleSetPublishesEmptyStore(t *testing.T) {
	t.Parallel()

	c := newClient(t)
	gate := &fakeGate{}

	doReconcile(t, newReconciler(c, gate, record.NewFakeRecorder(8)))

	configMap := getConfigMap(t, c)
	require.Empty(t, configMap.Data)
	require.Equal(t, 0, gate.calls, "an empty store has nothing to compile")
}

// TestReconcileClearsForeignBinaryData pins the trust boundary that the
// published store is exactly Data: the kubelet projects BinaryData keys into
// the volume too, so any foreign BinaryData must be swept on publish.
func TestReconcileClearsForeignBinaryData(t *testing.T) {
	t.Parallel()

	role := newRole("role-a", "identity:groups")

	tampered := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      configMapName,
		},
		Data:       expectedData(t, role),
		BinaryData: map[string][]byte{"rogue.yaml": []byte("boo")},
	}

	c := newClient(t, role, tampered)
	gate := &fakeGate{}

	doReconcile(t, newReconciler(c, gate, record.NewFakeRecorder(8)))

	configMap := getConfigMap(t, c)
	require.Empty(t, configMap.BinaryData)
	require.Equal(t, expectedData(t, role), configMap.Data)
	require.Equal(t, 1, gate.calls)
}
