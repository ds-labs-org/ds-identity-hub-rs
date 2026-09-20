#!/usr/bin/env bash
# Runs the full ds-identity-hub-rs benchmark leg: boots a release-mode
# Credential Service, boots bench/verifier-token (which seeds one
# MembershipCredential and hosts a real did:web "verifier" identity for the
# whole run), samples idle RSS/CPU, runs a short discarded warmup load, then
# the real measured k6 run with concurrent RSS/CPU sampling, and writes
# every artifact under bench/results/rust/. See bench/README.md for the
# full methodology, and in particular "Why every request needs its own
# token" for why this script pre-mints large pools of distinct bearer
# tokens via verifier-token's `GET /mint-batch` rather than reusing one
# fixed token the way bench-edc.sh does - ds-identity-hub-rs enforces
# genuine `jti` replay protection (a real, permanent security feature, not
# a bootstrap artifact), so a single token would only ever succeed once.
#
# Usage: ./bench-rust.sh
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$BENCH_DIR/.." && pwd)"
RESULTS_DIR="$BENCH_DIR/results/rust"
mkdir -p "$RESULTS_DIR"

# Pre-minted token pools are large (hundreds of MB - hundreds of thousands
# of ~1.1KB JWTs) and are pure scratch, regenerated fresh every run - kept
# out of the repo entirely, in /tmp, not under bench/results/.
TOKEN_TMP_DIR="${TOKEN_TMP_DIR:-/tmp/ds-identity-hub-rs-bench-tokens}"
mkdir -p "$TOKEN_TMP_DIR"

RUST_PORT="${RUST_PORT:-18080}"
VERIFIER_PORT="${VERIFIER_PORT:-18091}"
SCOPE="org.eclipse.dspace.dcp.vc.type:MembershipCredential"
TARGET_DID="did:web:127.0.0.1%3A${RUST_PORT}:credential-service"
TARGET_BASE_URL="http://127.0.0.1:${RUST_PORT}"
PRESENTATION_URL="${TARGET_BASE_URL}/presentations/query"

VUS="${VUS:-20}"
DURATION="${DURATION:-30s}"
WARMUP_VUS="${WARMUP_VUS:-5}"
WARMUP_DURATION="${WARMUP_DURATION:-10s}"
IDLE_SAMPLE_SECS="${IDLE_SAMPLE_SECS:-10}"
# Pool sizes with generous headroom over the empirically observed genuine
# (non-replayed) throughput ceiling on this host (~9,000 req/s at 20 VUs
# with the full auth path - see bench/README.md) - sized per warmup/measured
# duration with a large safety margin, not tuned to exactly match observed
# throughput, since running out mid-run would silently start replaying
# (rejected 401s) at the tail of the run. Override via env if a different
# host's throughput needs a bigger pool.
WARMUP_POOL="${WARMUP_POOL:-50000}"
MEASURED_POOL="${MEASURED_POOL:-400000}"

echo "Building release binaries (no-op if already built) ..."
(cd "$REPO_ROOT" && cargo build --release -p identity-hub-http) 2>&1 | tail -5
(cd "$BENCH_DIR/verifier-token" && cargo build --release) 2>&1 | tail -5

echo "Starting ds-identity-hub-rs Credential Service on :${RUST_PORT} ..."
nohup "$REPO_ROOT/target/release/identity-hub" credential-service \
  --bind "0.0.0.0:${RUST_PORT}" --did-host "127.0.0.1:${RUST_PORT}" \
  > "$RESULTS_DIR/service.log" 2>&1 &
for _ in $(seq 1 60); do
  ss -tln 2>/dev/null | grep -q ":${RUST_PORT} " && break
  sleep 1
done
ss -tln 2>/dev/null | grep -q ":${RUST_PORT} " || { echo "identity-hub never came up on :${RUST_PORT}" >&2; exit 1; }
# Resolve the REAL binary PID bound to the socket, not `$!` (the wrapper
# shell's PID after `nohup ... &`) - same gotcha as bench-edc.sh, see
# sample-rss-cpu.sh's own header comment.
RUST_PID=$(ss -tlnp 2>/dev/null | awk "/:${RUST_PORT} /"'{print $0}' | grep -oP 'pid=\K[0-9]+' | head -1)
echo "identity-hub PID: $RUST_PID"
echo "$RUST_PID" > "$RESULTS_DIR/pid.txt"

echo "Starting verifier-token (seeds MembershipCredential, hosts verifier DID) on :${VERIFIER_PORT} ..."
nohup "$BENCH_DIR/verifier-token/target/release/verifier-token" \
  --target-base-url "$TARGET_BASE_URL" \
  --target-did "$TARGET_DID" \
  --scope "$SCOPE" \
  --credential-type MembershipCredential \
  --host "127.0.0.1:${VERIFIER_PORT}" \
  --bind "0.0.0.0:${VERIFIER_PORT}" \
  > "$RESULTS_DIR/verifier-token.log" 2>&1 &
for _ in $(seq 1 60); do
  grep -q "^ready:" "$RESULTS_DIR/verifier-token.log" 2>/dev/null && break
  sleep 1
done
grep -q "^ready:" "$RESULTS_DIR/verifier-token.log" 2>/dev/null || { echo "verifier-token never became ready" >&2; cat "$RESULTS_DIR/verifier-token.log" >&2; exit 1; }
VERIFIER_PID=$(ss -tlnp 2>/dev/null | awk "/:${VERIFIER_PORT} /"'{print $0}' | grep -oP 'pid=\K[0-9]+' | head -1)
echo "$VERIFIER_PID" > "$RESULTS_DIR/verifier-pid.txt"

echo "Minting ${WARMUP_POOL} distinct tokens for the warmup run ..."
WARMUP_TOKENS="$TOKEN_TMP_DIR/warmup-tokens.txt"
curl -s -m 300 "http://127.0.0.1:${VERIFIER_PORT}/mint-batch?n=${WARMUP_POOL}" -o "$WARMUP_TOKENS"
echo "  minted $(wc -l < "$WARMUP_TOKENS") tokens"

echo "Warmup: ${WARMUP_VUS} VUs for ${WARMUP_DURATION} (discarded) ..."
k6 run \
  -e TARGET_URL="$PRESENTATION_URL" \
  -e TOKEN_POOL_FILE="$WARMUP_TOKENS" \
  -e SCOPE="$SCOPE" \
  -e VUS="$WARMUP_VUS" \
  -e DURATION="$WARMUP_DURATION" \
  "$BENCH_DIR/load/presentation-query-token-pool.k6.js" > "$RESULTS_DIR/warmup.stdout.txt" 2>&1 || true
rm -f "$WARMUP_TOKENS"

# Idle baseline is sampled AFTER warmup (process has stabilized) but BEFORE
# the measured load window - per bench/README.md's methodology.
echo "Sampling idle RSS/CPU for ${IDLE_SAMPLE_SECS}s (post-warmup, pre-load) ..."
"$BENCH_DIR/sample-rss-cpu.sh" "$RUST_PID" "$IDLE_SAMPLE_SECS" "$RESULTS_DIR/idle-rss-cpu.csv"

echo "Minting ${MEASURED_POOL} distinct tokens for the measured run ..."
MEASURED_TOKENS="$TOKEN_TMP_DIR/measured-tokens.txt"
curl -s -m 300 "http://127.0.0.1:${VERIFIER_PORT}/mint-batch?n=${MEASURED_POOL}" -o "$MEASURED_TOKENS"
echo "  minted $(wc -l < "$MEASURED_TOKENS") tokens"

echo "Measured run: ${VUS} VUs for ${DURATION}, sampling RSS/CPU concurrently ..."
DURATION_SECS=$(python3 -c "import re; s='$DURATION'; m=re.match(r'(\d+)s', s); print(int(m.group(1)) if m else 30)")
# +20s buffer, not +5s: k6 parses the whole pre-minted token pool into a
# SharedArray once, up front, before sending its first request - measured
# at several seconds for a few-hundred-thousand-token pool - so the sampler
# needs enough runway to still be sampling once the *real* 30s load window
# (delayed by that parse time) actually finishes.
"$BENCH_DIR/sample-rss-cpu.sh" "$RUST_PID" "$((DURATION_SECS + 20))" "$RESULTS_DIR/load-rss-cpu.csv" &
SAMPLER_PID=$!
k6 run \
  -e TARGET_URL="$PRESENTATION_URL" \
  -e TOKEN_POOL_FILE="$MEASURED_TOKENS" \
  -e SCOPE="$SCOPE" \
  -e VUS="$VUS" \
  -e DURATION="$DURATION" \
  --summary-export "$RESULTS_DIR/load.summary.json" \
  "$BENCH_DIR/load/presentation-query-token-pool.k6.js" | tee "$RESULTS_DIR/load.stdout.txt"
wait "$SAMPLER_PID" || true
rm -f "$MEASURED_TOKENS"

echo "Done. Results in $RESULTS_DIR"
echo "Stopping identity-hub (PID $RUST_PID) and verifier-token (PID $VERIFIER_PID) ..."
kill "$RUST_PID" "$VERIFIER_PID" 2>/dev/null || true
