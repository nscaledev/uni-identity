# Replica readiness

`Checker` serves `/readyz` and combines shutdown, signing-key availability and read-cache health.
It returns a bare 503 on failure and logs the cause. The listener-ownership metric
`unikorn_server_ready` is separate from this probe.

## Read-cache failures

The server tracks each authorization-critical informer's list/watch independently. Quota and
Allocation watches supply response summaries; their list/watch failures do not gate readiness
because enforcement reads live. After a reported failure, the replica remains ready for 30
seconds to allow reconnection. If that failure episode persists, it becomes
unready. A successful list does not clear a failed watch: permission to list does not imply
permission to watch. Successful watch requests and individual events also do not clear it.

Recovery requires one watch stream to remain open without errors for 30 seconds. This works for
quiet collections without waiting for a change or bookmark. A stream closing before that interval
counts as a failure; normal longer closures, expired resource versions and local cancellation
allow routine reconnection. Failure state survives repeated short or error streams. All tracked
authorization-critical informers must recover before the replica is ready again. Shutdown
separately makes the replica unready.

This measures reported failures and connection stability, not the age of authorization data. It
does not detect a silently stalled stream or prove that queued changes reached the cache. A
Kubernetes outage or removal of shared list/watch permissions can make every replica unready.
Restoring connectivity or permissions permits recovery without restarting the pods. The readiness
probe withdraws Service endpoints after the kubelet's configured probe delay; it does not reject
requests already reaching a pod.

`Watches.NewInformer` uses controller-runtime's public informer factory hook and preserves the
standard client-go informer. It observes list/watch calls and error events because some watch
failures are retried internally without reaching the outer watch-error callback.

See [server composition](../server/README.md) and [authentication reads](../oauth2/README.md#readers).
