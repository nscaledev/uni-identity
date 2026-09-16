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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/controller"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// errConfigMapUnavailable stands in for a ConfigMap write that the API
// server refuses, so a test can assert the reconciler surfaces it.
var errConfigMapUnavailable = errors.New("configmap API unavailable")

const (
	testNamespace = "test-namespace"
	configMapName = "identity-cerbos-policies"
)

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

// updateFailingClient injects a ConfigMap publication failure while leaving
// reads and Role writes available through the underlying fake client.
type updateFailingClient struct {
	client.Client
	err error
}

func (c *updateFailingClient) Update(ctx context.Context, object client.Object, options ...client.UpdateOption) error {
	if _, ok := object.(*corev1.ConfigMap); ok {
		return c.err
	}

	return c.Client.Update(ctx, object, options...)
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
	// Every successful reconcile schedules the safety-net re-verify (see
	// TestReconcileSchedulesSafetyNetResync); it must never come back with no
	// requeue, which would leave a later-missed deletion or tamper un-healed
	// until the informer cache's ~10h resync.
	require.Positive(t, result.RequeueAfter)
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
// (base "-" first-32-hex-of-sha256 ".yaml") so a drift in the published key
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

	// Every publish carries the publication marker, so the expected data
	// does too: it is part of the ConfigMap, just not part of the policy
	// store the PDP sees.
	data := map[string]string{".store-version": "{\"schema\":1,\"state\":\"valid\"}\n"}

	for name, content := range files {
		sum := sha256.Sum256(content)
		key := strings.TrimSuffix(name, ".yaml") + "-" + hex.EncodeToString(sum[:])[:32] + ".yaml"
		data[key] = string(content)
	}

	return data
}

// TestReconcileCreatesConfigMap pins the happy path: with no ConfigMap yet
// (the steady state after the one-time upgrade from the Helm-owned empty
// ConfigMap to the controller-written store, which deletes that ConfigMap), a
// reconcile generates policies from the Roles in the namespace,
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

// TestReconcileDeterministicGateRejectionWithdrawsLastGood pins that a
// compile or policy-test rejection derived from the current Role set cannot
// leave formerly allowed policies serving.  The classified error and warning
// event remain visible after the store is replaced with deny-all.
func TestReconcileDeterministicGateRejectionWithdrawsLastGood(t *testing.T) {
	t.Parallel()

	for name, rejection := range map[string]error{
		"CompileFailure": controller.ErrCompileFailed,
		"TestFailure":    controller.ErrTestsFailed,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			roleA := newRole("role-a", "identity:groups")
			c := newClient(t, roleA)
			gate := &fakeGate{}
			recorder := record.NewFakeRecorder(8)
			r := newReconciler(c, gate, recorder)

			doReconcile(t, r)
			lastGood := getConfigMap(t, c)
			require.NotEmpty(t, lastGood.Data, "the fixture must begin with serving grants")

			require.NoError(t, c.Create(t.Context(), newRole("role-b", "identity:projects")))

			gate.err = rejection

			_, err := r.Reconcile(t.Context(), reconcile.Request{})
			require.ErrorIs(t, err, rejection)

			withdrawn := getConfigMap(t, c)
			require.Equal(t, map[string]string{".store-version": "{\"schema\":1,\"state\":\"withdrawn\"}\n"}, withdrawn.Data,
				"a deterministically rejected store must withdraw every policy document, and say so")
			require.NotEqual(t, lastGood.ResourceVersion, withdrawn.ResourceVersion)

			select {
			case event := <-recorder.Events:
				require.Contains(t, event, corev1.EventTypeWarning)
				require.Contains(t, event, "PolicyStoreRejected")
				require.Contains(t, event, "withdrew all published policies")
			default:
				require.Fail(t, "expected a warning event for the rejected store")
			}
		})
	}
}

// TestReconcileRepeatedDeterministicRejectionDoesNotRewriteEmptyStore guards
// against a ConfigMap watch hot loop.  The API normalizes an empty data map to
// nil, so a subsequent rejected reconcile must publish nil too and remain a
// CreateOrUpdate no-op.
func TestReconcileRepeatedDeterministicRejectionDoesNotRewriteEmptyStore(t *testing.T) {
	t.Parallel()

	roleA := newRole("role-a", "identity:groups")
	c := newClient(t, roleA)
	gate := &fakeGate{}
	r := newReconciler(c, gate, record.NewFakeRecorder(8))

	doReconcile(t, r)
	require.NoError(t, c.Create(t.Context(), newRole("role-b", "identity:projects")))

	gate.err = controller.ErrCompileFailed

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrCompileFailed)

	withdrawn := getConfigMap(t, c)

	_, err = r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrCompileFailed)

	again := getConfigMap(t, c)
	require.Equal(t, withdrawn.ResourceVersion, again.ResourceVersion,
		"a withdrawn store must not be rewritten on every reconcile")

	// The marker also removes the reason this test used to normalize Data to
	// nil: a withdrawal is no longer an empty map, so the API server has
	// nothing to normalize away.  A Data wiped out of band — an older
	// controller, a manual edit — is instead repaired exactly once.
	wiped := getConfigMap(t, c)
	wiped.Data = nil
	require.NoError(t, c.Update(t.Context(), wiped))

	_, err = r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrCompileFailed)

	repaired := getConfigMap(t, c)
	require.Equal(t, map[string]string{".store-version": "{\"schema\":1,\"state\":\"withdrawn\"}\n"}, repaired.Data,
		"a wiped store must be repaired to the withdrawal marker")

	_, err = r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrCompileFailed)

	stable := getConfigMap(t, c)
	require.Equal(t, repaired.ResourceVersion, stable.ResourceVersion, "the repair must not repeat")
}

// TestPublicationMarkerRecordsTheState makes the marker contract explicit
// rather than implicit in the expected-data fixture. A consumer cannot tell a
// deliberately withdrawn store from one that was never published — both
// project as an empty directory — so every publish records which it is, and a
// withdrawal records it with no policy document beside it. The enclave's
// readiness endpoint gates on exactly this.
func TestPublicationMarkerRecordsTheState(t *testing.T) {
	t.Parallel()

	role := newRole("role-a", "identity:groups")
	c := newClient(t, role)
	gate := &fakeGate{}
	r := newReconciler(c, gate, record.NewFakeRecorder(8))

	doReconcile(t, r)

	published := getConfigMap(t, c)
	require.JSONEq(t, `{"schema":1,"state":"valid"}`, published.Data[".store-version"])
	require.Greater(t, len(published.Data), 1, "a valid publication carries policy documents beside the marker")

	gate.err = controller.ErrCompileFailed

	require.NoError(t, c.Create(t.Context(), newRole("role-b", "identity:projects")))

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrCompileFailed)

	require.Equal(t, map[string]string{".store-version": "{\"schema\":1,\"state\":\"withdrawn\"}\n"}, getConfigMap(t, c).Data,
		"a withdrawal is the marker and nothing else")
}

// TestReconcileTransientGateFailureKeepsLastGood pins the other side of the
// failure classification: an inconclusive compiler infrastructure failure is
// not evidence that the authoritative Role set is invalid, so replacing a
// valid store would be unsafe.
func TestReconcileTransientGateFailureKeepsLastGood(t *testing.T) {
	t.Parallel()

	roleA := newRole("role-a", "identity:groups")
	c := newClient(t, roleA)
	gate := &fakeGate{}
	r := newReconciler(c, gate, record.NewFakeRecorder(8))

	doReconcile(t, r)
	lastGood := getConfigMap(t, c)

	require.NoError(t, c.Create(t.Context(), newRole("role-b", "identity:projects")))

	gate.err = fmt.Errorf("%w: compiler unavailable", controller.ErrGateFailed)

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrGateFailed)

	kept := getConfigMap(t, c)
	require.Equal(t, lastGood.Data, kept.Data)
	require.Equal(t, lastGood.ResourceVersion, kept.ResourceVersion)
}

// TestReconcileOversizeRefusalWithdrawsLastGood pins the size-gate fail-closed
// contract: a candidate that deterministically cannot be published must
// withdraw formerly served grants while surfacing ErrPolicyStoreTooLarge and
// a PolicyStoreTooLarge warning event.
func TestReconcileOversizeRefusalWithdrawsLastGood(t *testing.T) {
	t.Parallel()

	roleA := newRole("role-a", "identity:groups")
	c := newClient(t, roleA)
	gate := &fakeGate{}
	recorder := record.NewFakeRecorder(8)
	doReconcile(t, newReconciler(c, gate, recorder))
	lastGood := getConfigMap(t, c)
	require.NotEmpty(t, lastGood.Data, "the fixture must begin with serving grants")

	require.NoError(t, c.Create(t.Context(), newRole("role-b", "identity:projects")))

	// A tiny ceiling refuses any non-empty candidate.  The gate is left
	// passing, so a refusal proves the SIZE gate fired — and it must run
	// before the compile gate (cheap-first), which the unchanged call count
	// assertion below pins.
	options := &controller.Options{
		ConfigMapName:       configMapName,
		CerbosBinary:        "/usr/local/bin/cerbos",
		MaxPolicyStoreBytes: 8,
	}
	r := controller.New(c, recorder, testNamespace, options, gate)

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrPolicyStoreTooLarge)

	withdrawn := getConfigMap(t, c)
	require.Equal(t, map[string]string{".store-version": "{\"schema\":1,\"state\":\"withdrawn\"}\n"}, withdrawn.Data,
		"an oversize authoritative store must withdraw every policy document, and say so")
	require.NotEqual(t, lastGood.ResourceVersion, withdrawn.ResourceVersion)
	require.Equal(t, 1, gate.calls, "the size gate must refuse before the compile gate runs again")

	select {
	case event := <-recorder.Events:
		require.Contains(t, event, corev1.EventTypeWarning)
		require.Contains(t, event, "PolicyStoreTooLarge")
	default:
		require.Fail(t, "expected a warning event for the oversize store")
	}
}

// TestReconcileGenerationFailureWithdrawsLastGood pins the failure mode that
// bypasses the compile gate entirely: once the authoritative Role list has
// been read, deterministic generation rejection must remove old grants rather
// than serving permissions no longer represented by valid current input.
func TestReconcileGenerationFailureWithdrawsLastGood(t *testing.T) {
	t.Parallel()

	role := newRole("role-a", "identity:groups")
	c := newClient(t, role)
	gate := &fakeGate{}
	recorder := record.NewFakeRecorder(8)
	r := newReconciler(c, gate, recorder)

	doReconcile(t, r)
	lastGood := getConfigMap(t, c)
	require.NotEmpty(t, lastGood.Data, "the fixture must begin with serving grants")

	current := &unikornv1.Role{}
	require.NoError(t, c.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: role.Name}, current))
	current.Spec.Scopes.Organization[0].Name = "identity:*"
	require.NoError(t, c.Update(t.Context(), current))

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, generate.ErrInvalidScope)

	withdrawn := getConfigMap(t, c)
	require.Equal(t, map[string]string{".store-version": "{\"schema\":1,\"state\":\"withdrawn\"}\n"}, withdrawn.Data,
		"a generation failure must withdraw every policy document, and say so")
	require.NotEqual(t, lastGood.ResourceVersion, withdrawn.ResourceVersion)
	require.Equal(t, 1, gate.calls, "a generation failure must not run the compile gate")

	select {
	case event := <-recorder.Events:
		require.Contains(t, event, "PolicyStoreRejected")
		require.Contains(t, event, "withdrew all published policies")
	default:
		require.Fail(t, "expected a warning event for the rejected store")
	}
}

// TestReconcileWithdrawalPublishFailureKeepsLastGood pins the unavoidable
// exception to deterministic withdrawal: if the ConfigMap update fails, the
// old store remains but both the rejection and publish failure stay visible.
func TestReconcileWithdrawalPublishFailureKeepsLastGood(t *testing.T) {
	t.Parallel()

	roleA := newRole("role-a", "identity:groups")
	baseClient := newClient(t, roleA)
	gate := &fakeGate{}
	doReconcile(t, newReconciler(baseClient, gate, record.NewFakeRecorder(8)))
	lastGood := getConfigMap(t, baseClient)

	require.NoError(t, baseClient.Create(t.Context(), newRole("role-b", "identity:projects")))

	recorder := record.NewFakeRecorder(8)
	failingClient := &updateFailingClient{Client: baseClient, err: errConfigMapUnavailable}
	gate.err = controller.ErrCompileFailed

	_, err := newReconciler(failingClient, gate, recorder).Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrCompileFailed)
	require.ErrorIs(t, err, errConfigMapUnavailable)

	kept := getConfigMap(t, baseClient)
	require.Equal(t, lastGood.Data, kept.Data)
	require.Equal(t, lastGood.ResourceVersion, kept.ResourceVersion)

	select {
	case event := <-recorder.Events:
		require.Contains(t, event, "PolicyStoreRejected")
		require.Contains(t, event, "failed to withdraw published policies")
	default:
		require.Fail(t, "expected a warning event for the failed withdrawal")
	}
}

// TestReconcileGateRefusalPublishesEmptyStore pins the fail-closed contract for
// first publish: if the very first candidate store is rejected, the controller
// explicitly publishes an empty ConfigMap so deny-all is visible and owned.
func TestReconcileGateRefusalPublishesEmptyStore(t *testing.T) {
	t.Parallel()

	c := newClient(t, newRole("role-a", "identity:groups"))
	r := newReconciler(c, &fakeGate{err: controller.ErrCompileFailed}, record.NewFakeRecorder(8))

	_, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.ErrorIs(t, err, controller.ErrCompileFailed)

	configMap := getConfigMap(t, c)
	require.Equal(t, map[string]string{".store-version": "{\"schema\":1,\"state\":\"withdrawn\"}\n"}, configMap.Data,
		"a refused store publishes the withdrawal marker and no policy document")
	require.Equal(t, "unikorn-policy-controller", configMap.Labels["app.kubernetes.io/managed-by"])
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
	require.Len(t, before.Data, 4, "derived roles + one resource policy per endpoint + the marker")

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

// TestReconcileRestoresMutatedData pins drift correction: if the published
// ConfigMap's Data is tampered out of band (a key altered, added or removed),
// the next reconcile sees the store is no longer current, re-gates it and
// republishes the generated store — a hand-edited policy cannot persist.  This
// is the Data-mutation sibling of TestReconcileClearsForeignBinaryData and,
// with TestReconcileRecreatesDeletedConfigMap, the drift half of the
// ConfigMap-watch self-healing contract.
func TestReconcileRestoresMutatedData(t *testing.T) {
	t.Parallel()

	role := newRole("role-a", "identity:groups")

	c := newClient(t, role)
	gate := &fakeGate{}
	r := newReconciler(c, gate, record.NewFakeRecorder(8))

	doReconcile(t, r)

	published := getConfigMap(t, c)

	// Tamper with the published store: replace its data with a bogus policy,
	// as a hand-edit or a partial write would.
	tampered := published.DeepCopy()
	tampered.Data = map[string]string{"rogue.yaml": "boo"}
	require.NoError(t, c.Update(t.Context(), tampered))

	doReconcile(t, r)

	restored := getConfigMap(t, c)
	require.Equal(t, expectedData(t, role), restored.Data, "tampered data must be restored to the generated store")
	require.Equal(t, 2, gate.calls, "restoring drift must re-run the compile gate")
}

// TestReconcileSchedulesSafetyNetResync pins the periodic safety net: both the
// publish path and the already-current no-op path request a bounded requeue,
// so the store is re-verified — and a missed deletion or tamper self-healed —
// on a fixed interval even if no Role or ConfigMap event ever fires.  This is
// the belt-and-suspenders backstop to the watches; without it a missed event
// would leave drift until the informer cache's ~10h resync.
func TestReconcileSchedulesSafetyNetResync(t *testing.T) {
	t.Parallel()

	role := newRole("role-a", "identity:groups")

	c := newClient(t, role)
	r := newReconciler(c, &fakeGate{}, record.NewFakeRecorder(8))

	// Publish path.
	result, err := r.Reconcile(t.Context(), reconcile.Request{})
	require.NoError(t, err)
	require.Positive(t, result.RequeueAfter, "a publish must schedule the safety-net re-verify")

	// No-op path: the store is now current, but it must still reschedule.
	result, err = r.Reconcile(t.Context(), reconcile.Request{})
	require.NoError(t, err)
	require.Positive(t, result.RequeueAfter, "an unchanged store must still schedule the safety-net re-verify")
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
	require.Equal(t, map[string]string{".store-version": "{\"schema\":1,\"state\":\"valid\"}\n"}, configMap.Data,
		"no roles is a VALID publication of no policies, not a withdrawal")
	require.Equal(t, 0, gate.calls, "a store with no policy document has nothing to compile")
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
