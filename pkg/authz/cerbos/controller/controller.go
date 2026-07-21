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

// Package controller reconciles Role custom resources into the Cerbos policy
// store ConfigMap the PDP sidecar mounts.  Every Role event collapses into
// one fan-in reconcile that regenerates the whole store from the Roles in
// the identity namespace (pkg/authz/cerbos/generate), refuses to publish
// anything the exec'd `cerbos compile` gate rejects, and publishes under
// content-hash-suffixed ConfigMap keys so the sidecar's directory watcher
// actually sees every change.  See the package README for the full contract.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// managedByLabel marks the published ConfigMap as controller-owned.
	// Repo convention is labels, never ownerReferences, so there is no
	// garbage collection: helm uninstall orphans the ConfigMap (see the
	// package README's operational notes).
	managedByLabel = "app.kubernetes.io/managed-by"

	// managedByValue is the controller binary's name.
	managedByValue = "unikorn-policy-controller"

	// hashLength is the number of hex characters of the content SHA-256
	// suffixed onto every published key.
	hashLength = 8

	// storeSuffix is the extension shared by generated policy files; the
	// hash slots in before it so Cerbos still sees *.yaml files.
	storeSuffix = ".yaml"

	// eventPolicyStoreRejected is the reason on the warning event emitted
	// when the compile gate refuses a candidate store.
	eventPolicyStoreRejected = "PolicyStoreRejected"

	// eventPolicyStoreTooLarge is the reason on the warning event emitted
	// when the pre-publish size gate refuses a candidate store that would
	// exceed the ConfigMap size ceiling.
	eventPolicyStoreTooLarge = "PolicyStoreTooLarge"

	// defaultMaxPolicyStoreBytes is the default policy-store size ceiling:
	// the ~1 MiB (1<<20) the Kubernetes API server enforces on a ConfigMap's
	// data (the etcd request-size limit, k8s ValidateConfigMap).  Overridable
	// via Options.MaxPolicyStoreBytes.
	defaultMaxPolicyStoreBytes = 1 << 20

	// resyncPeriod is the safety-net interval on which every successful
	// reconcile requeues itself, so the published store is re-verified even if
	// no Role or ConfigMap event ever fires.  The ConfigMap watch (registered
	// in pkg/controllers/policy) is the primary trigger that self-heals a
	// deleted or tampered store; this bounded periodic requeue is the
	// belt-and-suspenders backstop for any missed event, far tighter than the
	// informer cache's ~10h resync.
	resyncPeriod = 10 * time.Minute
)

// ErrPolicyStoreTooLarge is returned when a candidate store would exceed the
// configured ConfigMap size ceiling (Reconciler.maxStoreBytes).  It is refused
// before publication so the sidecar keeps serving the last-good store; the
// sentinel makes the refusal classifiable with errors.Is, like the compile
// gate's ErrCompileFailed/ErrTestsFailed.
var ErrPolicyStoreTooLarge = errors.New("policy store exceeds the ConfigMap size limit")

// Reconciler regenerates and publishes the policy store ConfigMap.  It is a
// custom fan-in reconciler, not a coremanager.NewReconciler object-lifecycle
// reconciler: the reconciled unit is the whole Role set, not one object, so
// there are no finalizers and no status to manage.
type Reconciler struct {
	// client must be an UNCACHED client: reads of the ConfigMap through a
	// cache-backed client would spin up a cluster-wide ConfigMap informer,
	// which the chart's namespaced RBAC (deliberately scoped to the one
	// policy store object) forbids.
	client client.Client

	// recorder emits Kubernetes events against the policy store ConfigMap.
	recorder record.EventRecorder

	// namespace is the identity namespace holding the Roles and the
	// ConfigMap (--namespace).
	namespace string

	// configMapName is the controller-owned policy store ConfigMap name
	// (--cerbos-policies-configmap).
	configMapName string

	// gate validates every candidate store before publication.
	gate CompileGate

	// maxStoreBytes is the size ceiling (key+value bytes across Data) above
	// which a candidate store is refused before publication instead of
	// failing an opaque publish: the whole store lives in one ConfigMap,
	// which the API server caps at ~1 MiB.  Defaulted from
	// Options.MaxPolicyStoreBytes in New.
	maxStoreBytes int
}

var _ reconcile.Reconciler = &Reconciler{}

// New returns a policy store reconciler.
func New(client client.Client, recorder record.EventRecorder, namespace string, options *Options, gate CompileGate) *Reconciler {
	maxStoreBytes := options.MaxPolicyStoreBytes
	if maxStoreBytes <= 0 {
		maxStoreBytes = defaultMaxPolicyStoreBytes
	}

	return &Reconciler{
		client:        client,
		recorder:      recorder,
		namespace:     namespace,
		configMapName: options.ConfigMapName,
		gate:          gate,
		maxStoreBytes: maxStoreBytes,
	}
}

// Reconcile regenerates the policy store from all Roles in the namespace and
// publishes it if it changed and passes the compile gate.  The request is a
// synthetic fan-in key (every Role event maps to the same request), so its
// content is deliberately ignored.  All failure paths return an error and
// leave the published ConfigMap untouched: last-good policies keep serving.
// Every successful reconcile requests a bounded requeue (resyncPeriod) so a
// deleted or tampered store is re-verified and self-healed even if its watch
// event is somehow missed.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)

	roles, data, err := r.generateStore(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}

	current, err := r.storeIsCurrent(ctx, data)
	if err != nil {
		return reconcile.Result{}, err
	}

	if current {
		return reconcile.Result{RequeueAfter: resyncPeriod}, nil
	}

	if size := policyStoreSize(data); size > r.maxStoreBytes {
		// Refuse before compiling (cheap-first): a store too large to fit
		// the ConfigMap must surface as a dedicated, classifiable refusal,
		// not freeze last-good behind an opaque publish error.  Same
		// fail-closed contract as the compile gate — leave the ConfigMap
		// untouched and alarm via an event on the store object.
		logger.Error(ErrPolicyStoreTooLarge, "refusing to publish policy store", "roles", roles, "bytes", size, "limit", r.maxStoreBytes)
		r.recorder.Eventf(r.configMapRef(), corev1.EventTypeWarning, eventPolicyStoreTooLarge,
			"Refusing to publish generated policy store (%d bytes exceeds the %d-byte ConfigMap limit), keeping last-good policies", size, r.maxStoreBytes)

		return reconcile.Result{}, fmt.Errorf("%w: %d bytes exceeds %d", ErrPolicyStoreTooLarge, size, r.maxStoreBytes)
	}

	if err := r.compileCheck(ctx, data); err != nil {
		// Refuse to publish: leave the ConfigMap untouched so the
		// sidecar keeps serving the last-good store, surface the
		// classified error (compile vs test failure) and alarm via an
		// event on the store object.
		logger.Error(err, "refusing to publish policy store", "roles", roles)
		r.recorder.Eventf(r.configMapRef(), corev1.EventTypeWarning, eventPolicyStoreRejected,
			"Refusing to publish generated policy store, keeping last-good policies: %v", err)

		return reconcile.Result{}, err
	}

	result, err := r.publish(ctx, data)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("publishing policy store: %w", err)
	}

	logger.Info("published policy store", "operation", result, "roles", roles, "files", len(data))

	return reconcile.Result{RequeueAfter: resyncPeriod}, nil
}

// generateStore lists the Roles in the namespace and generates their policy
// store as hash-keyed ConfigMap data, returning the role count for logging.
// Fail closed: a Role the generator rejects (or an unmarshalable document)
// aborts the whole publish and keeps last-good, exactly like a gate refusal.
func (r *Reconciler) generateStore(ctx context.Context) (int, map[string]string, error) {
	roles := &unikornv1.RoleList{}
	if err := r.client.List(ctx, roles, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return 0, nil, fmt.Errorf("listing roles: %w", err)
	}

	output, err := generate.Generate(roles.Items)
	if err != nil {
		return 0, nil, fmt.Errorf("generating policies: %w", err)
	}

	files, err := output.Files()
	if err != nil {
		return 0, nil, fmt.Errorf("serializing policies: %w", err)
	}

	return len(roles.Items), hashKeyedData(files), nil
}

// storeIsCurrent reports whether the published ConfigMap already holds
// exactly the desired data, making the reconcile a no-op.  The hash-suffixed
// key set encodes the content, but values are compared too so a
// hand-tampered value cannot hide behind a matching key, and BinaryData
// counts as a difference because the kubelet projects its keys into the
// policy volume as well.
func (r *Reconciler) storeIsCurrent(ctx context.Context, data map[string]string) (bool, error) {
	existing := &corev1.ConfigMap{}

	if err := r.client.Get(ctx, types.NamespacedName{Namespace: r.namespace, Name: r.configMapName}, existing); err != nil {
		// NotFound is simply "not current": recreate from the Roles
		// (this also absorbs the one-time A1->A3 helm upgrade deleting
		// the previously chart-owned ConfigMap).
		if kerrors.IsNotFound(err) {
			return false, nil
		}

		return false, fmt.Errorf("reading policy store: %w", err)
	}

	return maps.Equal(existing.Data, data) && len(existing.BinaryData) == 0, nil
}

// publish creates or updates the ConfigMap with the gated data, labelling it
// as controller-managed.
func (r *Reconciler) publish(ctx context.Context, data map[string]string) (controllerutil.OperationResult, error) {
	configMap := r.configMapRef()

	return controllerutil.CreateOrUpdate(ctx, r.client, configMap, func() error {
		if configMap.Labels == nil {
			configMap.Labels = map[string]string{}
		}

		configMap.Labels[managedByLabel] = managedByValue
		configMap.Data = data
		configMap.BinaryData = nil

		return nil
	})
}

// configMapRef returns the policy store ConfigMap identity, used both for
// publication and as the involved object on events.
func (r *Reconciler) configMapRef() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.namespace,
			Name:      r.configMapName,
		},
	}
}

// policyStoreSize is the ConfigMap data size the API server validates against
// its ~1 MiB limit: the sum of key and value bytes across Data.  Counting the
// keys (the API server's data check may weigh only values) is deliberately
// conservative — refuse at or slightly before the true limit, never after.
func policyStoreSize(data map[string]string) int {
	total := 0

	for k, v := range data {
		total += len(k) + len(v)
	}

	return total
}

// compileCheck materializes the candidate store in a scratch directory and
// runs the compile gate on it.  The directory uses the hash-suffixed names
// so the gated bytes are exactly the published bytes.  An empty store is
// valid by construction (Cerbos serves deny-by-default from an empty policy
// directory) and has nothing to compile.
func (r *Reconciler) compileCheck(ctx context.Context, data map[string]string) error {
	if len(data) == 0 {
		return nil
	}

	// The deployment mounts an emptyDir at /tmp: distroless with a
	// read-only root filesystem has no other writable scratch space.
	dir, err := os.MkdirTemp("", "cerbos-policies-*")
	if err != nil {
		return fmt.Errorf("%w: creating scratch directory: %w", ErrGateFailed, err)
	}

	defer os.RemoveAll(dir)

	for name, content := range data {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return fmt.Errorf("%w: writing candidate store: %w", ErrGateFailed, err)
		}
	}

	return r.gate.Compile(ctx, dir)
}

// hashKeyedData converts generated files into ConfigMap data under
// content-hash-suffixed keys: <base>-<sha256[:8]>.yaml.
//
// The suffix is load-bearing, not cosmetic.  The kubelet updates ConfigMap
// volumes by atomically swapping a hidden ..data symlink
// (kubernetes pkg/volume/util/atomic_writer.go), and Cerbos's disk watcher
// ignores hidden-name events and only reloads the exact visible paths in an
// event batch (cerbos@v0.53.0 internal/storage/disk/dirwatch.go:147-165,
// 200-246) — so a content change under an UNCHANGED key never reloads.  Key
// adds/removes do produce visible symlink create/delete events, and deletes
// are processed before creates (dirwatch.go:184-186), so swapping the key on
// every content change reloads reliably and without a duplicate-definition
// window.  Unchanged files keep byte-identical keys: no events, no reload
// needed.
//
// Generated base names are already sanitized to [a-zA-Z0-9._-] (see
// generate.policyFileName), and the suffix stays inside that set, so every
// key remains a valid ConfigMap key.
func hashKeyedData(files map[string][]byte) map[string]string {
	data := make(map[string]string, len(files))

	for name, content := range files {
		data[hashKey(name, content)] = string(content)
	}

	return data
}

// hashKey returns the published ConfigMap key for one generated file.
func hashKey(name string, content []byte) string {
	sum := sha256.Sum256(content)

	return strings.TrimSuffix(name, storeSuffix) + "-" + hex.EncodeToString(sum[:])[:hashLength] + storeSuffix
}
