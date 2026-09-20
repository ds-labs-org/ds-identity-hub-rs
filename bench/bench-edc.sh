#!/usr/bin/env bash
# Runs the full EDC IdentityHub v0.18.0 benchmark leg: boots the seeded
# Credential Service (bench/edc-identity-hub/run-identityhub.sh) if it isn't
# already running, samples idle RSS/CPU, runs a short discarded warmup load,
# then the real measured k6 run with concurrent RSS/CPU sampling, and writes
# every artifact under bench/results/edc/. See bench/README.md for the full
# methodology and how this compares to bench-rust.sh's own leg.
#
# Usage: ./bench-edc.sh
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EDC_DIR="$BENCH_DIR/edc-identity-hub"
RESULTS_DIR="$BENCH_DIR/results/edc"
mkdir -p "$RESULTS_DIR"

SCOPE="org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read"
PRESENTATION_URL="http://localhost:9082/api/credentials/v1/participants/dcp-test-client/presentations/query"

VUS="${VUS:-20}"
DURATION="${DURATION:-30s}"
WARMUP_VUS="${WARMUP_VUS:-5}"
WARMUP_DURATION="${WARMUP_DURATION:-10s}"
IDLE_SAMPLE_SECS="${IDLE_SAMPLE_SECS:-10}"

STARTED_EDC=0
if ! ss -tln 2>/dev/null | grep -q ':9082 '; then
  echo "Starting EDC IdentityHub ..."
  (cd "$EDC_DIR" && nohup ./run-identityhub.sh > "$RESULTS_DIR/boot.log" 2>&1 &)
  STARTED_EDC=1
  for _ in $(seq 1 180); do
    ss -tln 2>/dev/null | grep -q ':9082 ' && break
    sleep 1
  done
fi
ss -tln 2>/dev/null | grep -q ':9082 ' || { echo "EDC IdentityHub never came up on :9082" >&2; exit 1; }

# Resolve the REAL java PID bound to the credentials-API socket - never `$!`
# after a wrapped background launch (see sample-rss-cpu.sh's own header
# comment and docs/benchmarks/2026-08-27-dcp-auth-overhead.md's account of
# this exact bug).
PID=$(ss -tlnp 2>/dev/null | awk '/:9082 /{print $0}' | grep -oP 'pid=\K[0-9]+' | head -1)
echo "EDC IdentityHub PID: $PID"
echo "$PID" > "$RESULTS_DIR/pid.txt"

# A freshly-started EDC IdentityHub can have port 9082 already bound while
# the seed extension's own prepare() (participant/STS-account creation) is
# still running - hitting /sts/token in that window returns a real HTTP 405,
# not a connection error, so the port-open check above can't detect it.
# Retry the first STS call until it genuinely succeeds instead of racing it.
mint_token() {
  local attempt
  for attempt in $(seq 1 30); do
    if TOKEN=$(python3 "$EDC_DIR/mint-token.py" --scope "$SCOPE" 2>/tmp/mint-token-err.txt); then
      echo "$TOKEN"
      return 0
    fi
    sleep 1
  done
  echo "mint-token.py never succeeded after 30 retries:" >&2
  cat /tmp/mint-token-err.txt >&2
  return 1
}

echo "Warmup: ${WARMUP_VUS} VUs for ${WARMUP_DURATION} (discarded) ..."
TOKEN=$(mint_token)
k6 run \
  -e TARGET_URL="$PRESENTATION_URL" \
  -e AUTH_HEADER="Bearer $TOKEN" \
  -e SCOPE="$SCOPE" \
  -e VUS="$WARMUP_VUS" \
  -e DURATION="$WARMUP_DURATION" \
  "$BENCH_DIR/load/presentation-query.k6.js" > "$RESULTS_DIR/warmup.stdout.txt" 2>&1 || true

# Idle baseline is sampled AFTER warmup (server has JIT-warmed/stabilized)
# but BEFORE the measured load window - per bench/README.md's methodology.
echo "Sampling idle RSS/CPU for ${IDLE_SAMPLE_SECS}s (post-warmup, pre-load) ..."
"$BENCH_DIR/sample-rss-cpu.sh" "$PID" "$IDLE_SAMPLE_SECS" "$RESULTS_DIR/idle-rss-cpu.csv"

echo "Measured run: ${VUS} VUs for ${DURATION}, sampling RSS/CPU concurrently ..."
TOKEN=$(mint_token)
DURATION_SECS=$(python3 -c "import re; s='$DURATION'; m=re.match(r'(\d+)s', s); print(int(m.group(1)) if m else 30)")
"$BENCH_DIR/sample-rss-cpu.sh" "$PID" "$((DURATION_SECS + 5))" "$RESULTS_DIR/load-rss-cpu.csv" &
SAMPLER_PID=$!
k6 run \
  -e TARGET_URL="$PRESENTATION_URL" \
  -e AUTH_HEADER="Bearer $TOKEN" \
  -e SCOPE="$SCOPE" \
  -e VUS="$VUS" \
  -e DURATION="$DURATION" \
  --summary-export "$RESULTS_DIR/load.summary.json" \
  "$BENCH_DIR/load/presentation-query.k6.js" | tee "$RESULTS_DIR/load.stdout.txt"
wait "$SAMPLER_PID" || true

echo "Done. Results in $RESULTS_DIR"
echo "NOTE: this script does not stop EDC IdentityHub - see bench/README.md's cleanup section."
