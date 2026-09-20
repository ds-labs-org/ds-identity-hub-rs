// Shared k6 load driver for both targets in this benchmark - the exact
// same request body/shape is sent to whichever target TARGET_URL points at,
// since both eclipse-edc/IdentityHub and ds-identity-hub-rs implement the
// identical wire protocol (DCP's Presentation API, `POST
// .../presentations/query`). Adapted from
// dataspace/docs/benchmarks/2026-08-27-dcp-auth-overhead.md's own
// catalog-request.k6.js pattern (constant-vus executor, TARGET_URL/
// AUTH_HEADER env vars, a fixed bearer token minted once and reused for the
// whole run) - see bench/README.md for the full methodology.
import http from 'k6/http';
import { check } from 'k6';

const TARGET_URL = __ENV.TARGET_URL;
const AUTH_HEADER = __ENV.AUTH_HEADER; // "Bearer <token>"
const SCOPE = __ENV.SCOPE; // e.g. "org.eclipse.dspace.dcp.vc.type:MembershipCredential"
const VUS = __ENV.VUS ? parseInt(__ENV.VUS, 10) : 20;
const DURATION = __ENV.DURATION || '30s';

const BODY = JSON.stringify({
  '@context': ['https://w3id.org/dspace-dcp/v1.0/dcp.jsonld'],
  type: 'PresentationQueryMessage',
  scope: [SCOPE],
});

const headers = { 'Content-Type': 'application/json' };
if (AUTH_HEADER) {
  headers['Authorization'] = AUTH_HEADER;
}
const PARAMS = { headers };

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
  const res = http.post(TARGET_URL, BODY, PARAMS);
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}
