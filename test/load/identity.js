// k6 script for the identity load test; see README.md. One run drives one
// phase (PHASE), in an open model (arrival-rate executors), so a slow server
// cannot slow the offered load.
//
// MODE=fixed holds RATE req/s for DURATION seconds (the steady state, and each
// confirmation hold of the ceiling search). MODE=ceiling raises the rate in one
// stage from RATE to CEILING_MAX over RAMP_SECONDS and aborts at the first
// failure; the summary says when that failure started (ceiling.jq turns that
// into a rate). A failure is a non-200, a timeout, or k6 falling behind the
// schedule because it ran out of VUs: k6 drops those iterations silently, so a
// run that only counted non-200s would never see a server that is overloaded
// past the VU limit. A drop alone is not a failure: while k6 builds one more VU
// it drops every iteration that finds none free, far below the limit.
//
// Environment: BASE_URL, TOKENS (tokens.json), PHASE, MODE (fixed|ceiling),
// RATE (req/s; the fixed rate, or where the ramp starts), DURATION (seconds;
// fixed), CEILING_MAX (req/s; the ramp's top), SUMMARY_OUT.
import http from 'k6/http';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';
import { Counter, Rate, Trend } from 'k6/metrics';

const PHASE = __ENV.PHASE;
const RATE = parseInt(__ENV.RATE || '20');
const DURATION = parseInt(__ENV.DURATION || '60');
const CEILING = __ENV.MODE === 'ceiling';
const CEILING_MAX = parseInt(__ENV.CEILING_MAX || '2000');
const BASE_URL = __ENV.BASE_URL;

// The ramp's length, and the longest a request may take. A request that has
// not answered by REQUEST_TIMEOUT is a failure like any non-200.
const RAMP_SECONDS = 120;
const REQUEST_TIMEOUT_SECONDS = 5;
const REQUEST_TIMEOUT = `${REQUEST_TIMEOUT_SECONDS}s`;

// VUs: enough for every request to be in flight at once with each running to
// its timeout, plus 20%. At the default top of 2000 req/s that is 12000. k6
// starts a VU only when it needs one, so a healthy server uses few.
const TOP_RATE = CEILING ? CEILING_MAX : RATE;
const MAX_VUS = Math.ceil(TOP_RATE * REQUEST_TIMEOUT_SECONDS * 1.2);

// VUs built before the run. k6 builds one more VU at a time and drops every
// iteration that finds none free meanwhile, so a pool that must grow drops
// iterations on a healthy server. VUs needed are about rate x latency: 200
// cover 2000 req/s up to 100 ms.
const PREALLOCATED_VUS = 200;

// The ramp has fallen behind when it has started fewer iterations than were
// due by more than this share (and more than 2): the k6 dropped iterations that count.
const BEHIND_SHARE = 0.05;

if (CEILING && !(CEILING_MAX > RATE)) {
  throw new Error(`the ceiling ramp needs CEILING_MAX above RATE (RATE ${RATE}, CEILING_MAX ${CEILING_MAX})`);
}

const PASSPORT_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const PASSPORT_TYPE = 'urn:nscale:params:oauth:token-type:passport';

// Entries are the same shape in every phase: { token, orgId, orgs }.
const pool = new SharedArray('tokens', () => {
  const file = JSON.parse(open(__ENV.TOKENS));
  if (PHASE === 'service-account') {
    return file.serviceAccounts;
  }
  // The ACL-heavy phase uses users with many memberships.
  return PHASE === 'acl-heavy' ? file.auth0.filter((t) => t.orgs >= 5) : file.auth0;
});

// 5xx and 401 are counted separately from every non-200, so the gate names
// exactly what it checks. failStart is when each failed request began, in
// seconds since the scenario started: its minimum is the ceiling's first failure.
const serverErrors = new Rate('server_errors');
const unauthorized = new Counter('unauthorized');
const notOK = new Counter('not_ok');
const failStart = new Trend('fail_start_s');
// Counts iterations k6 should have started by now and had not, past
// BEHIND_SHARE; ramp only.
const behind = new Counter('behind_schedule');

function scenario() {
  const common = { timeUnit: '1s', preAllocatedVUs: Math.min(PREALLOCATED_VUS, MAX_VUS), maxVUs: MAX_VUS };
  if (!CEILING) {
    return { executor: 'constant-arrival-rate', rate: RATE, duration: `${DURATION}s`, ...common };
  }
  return {
    executor: 'ramping-arrival-rate',
    startRate: RATE,
    stages: [{ target: CEILING_MAX, duration: `${RAMP_SECONDS}s` }],
    ...common,
  };
}

function thresholds() {
  // Valid tokens: any 5xx, 401, timeout or other non-200 fails the run. In the
  // ceiling ramp the first non-200 or lag also stops it at once: a failure is
  // a failure, so there is no grace period at the start.
  const stop = [{ threshold: 'count==0', abortOnFail: true }];
  const gates = { server_errors: ['rate==0'], unauthorized: ['count==0'], not_ok: CEILING ? stop : ['count==0'] };
  if (CEILING) {
    gates.behind_schedule = stop;
  }
  return gates;
}

export const options = {
  scenarios: { [PHASE]: scenario() },
  thresholds: thresholds(),
  insecureSkipTLSVerify: true,
  summaryTrendStats: ['avg', 'min', 'p(95)', 'p(99)', 'max'],
};

// Iterations the ramp has scheduled by t seconds: the area under its rate line.
function scheduled(t) {
  return RATE * t + ((CEILING_MAX - RATE) * t * t) / (2 * RAMP_SECONDS);
}

// The time at which the ramp had scheduled n iterations (inverse of scheduled).
function timeOf(n) {
  const k = (CEILING_MAX - RATE) / RAMP_SECONDS;
  return (Math.sqrt(RATE * RATE + 2 * k * n) - RATE) / k;
}

function request(entry, tags) {
  const auth = { Authorization: `Bearer ${entry.token}` };
  const params = { tags, headers: auth, timeout: REQUEST_TIMEOUT };

  switch (PHASE) {
    case 'auth0-bearer':
      return http.get(`${BASE_URL}/api/v1/organizations`, params);
    case 'passport-exchange':
      // Form as built by pkg/middleware/openapi/remote (tokenExchangeForm).
      return http.post(`${BASE_URL}/oauth2/v2/token`, {
        grant_type: PASSPORT_GRANT,
        subject_token: entry.token,
        subject_token_type: ACCESS_TOKEN_TYPE,
        requested_token_type: PASSPORT_TYPE,
        x_organization_id: entry.orgId,
      }, { tags, timeout: REQUEST_TIMEOUT });
    case 'acl-heavy':
      return http.get(`${BASE_URL}/api/v1/organizations/${entry.orgId}/acl`, params);
    case 'service-account':
      // Userinfo runs the service account token check and nothing else: its
      // handler reads no Kubernetes objects (see README).
      return http.get(`${BASE_URL}/oauth2/v2/userinfo`, params);
    default:
      throw new Error(`unknown PHASE ${PHASE}`);
  }
}

export default function () {
  const entry = pool[exec.scenario.iterationInTest % pool.length];
  const tags = { phase: PHASE };

  const started = (Date.now() - exec.scenario.startTime) / 1000;
  if (CEILING) {
    // iterationInTest counts started iterations only, so the gap to the
    // schedule is the number dropped. The first one was due when the schedule
    // reached the count of iterations started so far.
    const due = scheduled(started);
    if (due - exec.scenario.iterationInTest > Math.max(2, BEHIND_SHARE * due)) {
      behind.add(1, tags);
      failStart.add(timeOf(exec.scenario.iterationInTest), tags);
    }
  }
  const res = request(entry, tags);

  serverErrors.add(res.status >= 500, tags);
  unauthorized.add(res.status === 401 ? 1 : 0, tags);
  notOK.add(res.status === 200 ? 0 : 1, tags);
  if (res.status !== 200) {
    failStart.add(started, tags);
  }
}

function value(data, name, stat) {
  const m = data.metrics[name];
  return m && m.values[stat] !== undefined ? m.values[stat] : 0;
}

export function handleSummary(data) {
  const requests = value(data, 'http_reqs', 'count');
  const failed = value(data, 'not_ok', 'count');
  const dropped = value(data, 'dropped_iterations', 'count');
  const summary = {
    phase: PHASE,
    mode: CEILING ? 'ceiling' : 'fixed',
    rate: RATE,
    durationSeconds: DURATION,
    tokensInPool: pool.length,
    requests,
    rate5xx: value(data, 'server_errors', 'rate'),
    count401: value(data, 'unauthorized', 'count'),
    countNotOK: failed,
    failureRate: requests > 0 ? failed / requests : 0,
    p95Ms: value(data, 'http_req_duration', 'p(95)'),
    p99Ms: value(data, 'http_req_duration', 'p(99)'),
    droppedIterations: dropped,
  };
  // Requests answered per second of the run: for a hold, compare it with rate.
  const runSeconds = data.state.testRunDurationMs / 1000;
  summary.deliveredRps = CEILING ? requests / runSeconds : requests / DURATION;

  if (CEILING) {
    // When the first failure started, in seconds into the ramp (ceiling.jq
    // turns it into a rate); null when nothing failed and the ramp reached its
    // top. A failing request or a lag has its own start time. Dropped
    // iterations are reported but do not count on their own.
    summary.ceilingMax = CEILING_MAX;
    summary.rampSeconds = RAMP_SECONDS;
    const times = [];
    if (failed > 0 || value(data, 'behind_schedule', 'count') > 0) {
      times.push(value(data, 'fail_start_s', 'min'));
    }
    summary.firstFailureAtSeconds = times.length > 0 ? Math.min(RAMP_SECONDS, ...times) : null;
  }

  const line = `${PHASE} (${summary.mode}): ${requests} requests, ${failed} failed, ${dropped} dropped, 5xx ${summary.rate5xx}, 401 ${summary.count401}, p95 ${summary.p95Ms.toFixed(1)} ms` +
    (CEILING && summary.firstFailureAtSeconds !== null ? `, first failure ${summary.firstFailureAtSeconds.toFixed(1)} s into the ramp` : '') + '\n';

  return { [__ENV.SUMMARY_OUT]: JSON.stringify(summary, null, 2), stdout: line };
}
