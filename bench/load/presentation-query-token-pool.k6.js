// Variant of presentation-query.k6.js for a target that enforces genuine
// `jti` replay protection on every request (ds-identity-hub-rs's
// `identity_hub_http::auth::verify_bearer_token` - a real, permanent
// security check, not a bootstrap artifact; see bench/README.md's "Why
// every request needs its own token"). A single fixed bearer token, reused
// across an entire k6 run the way EDC's leg does, would succeed exactly
// once and then fail every subsequent request with 401 (replay). Instead,
// this script reads a large pre-minted pool of distinct, genuinely valid
// tokens (one per line, produced by `verifier-token`'s `GET
// /mint-batch?n=<count>`) and hands each iteration, across every VU, a
// token no other iteration in the same run will ever use -
// `exec.scenario.iterationInTest` is a single counter shared across all VUs
// for this scenario, so indexing by it guarantees no two concurrent or
// sequential iterations ever pick the same token.
//
// TOKEN_POOL_FILE must hold at least as many tokens as this run will
// perform iterations (VUS * achievable_iterations_per_second * duration,
// with headroom) - bench-rust.sh sizes it from an empirical dry run before
// committing to the real measured run. Running out of tokens (more
// iterations than pool entries) would wrap around via modulo and start
// replaying - this is deliberately NOT silently tolerated: a run that
// exhausts its pool shows up as a burst of 401s at the tail of the run.
import http from 'k6/http';
import { check } from 'k6';
import exec from 'k6/execution';
import { SharedArray } from 'k6/data';

const TARGET_URL = __ENV.TARGET_URL;
const TOKEN_POOL_FILE = __ENV.TOKEN_POOL_FILE;
const SCOPE = __ENV.SCOPE;
const VUS = __ENV.VUS ? parseInt(__ENV.VUS, 10) : 20;
const DURATION = __ENV.DURATION || '30s';

const tokens = new SharedArray('tokens', function () {
  return open(TOKEN_POOL_FILE).split('\n').filter((l) => l.length > 0);
});

const BODY = JSON.stringify({
  '@context': ['https://w3id.org/dspace-dcp/v1.0/dcp.jsonld'],
  type: 'PresentationQueryMessage',
  scope: [SCOPE],
});

export const options = {
  scenarios: {
    presentation_query: {
      executor: 'constant-vus',
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<5000', 'p(99)<5000'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const idx = exec.scenario.iterationInTest % tokens.length;
  const token = tokens[idx];
  const res = http.post(TARGET_URL, BODY, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  });
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}
