#!/usr/bin/env bash
# Adapted, near-verbatim, from the sibling ds-catalog-broker-rs repo's
# compliance/dcp-test-env/run-identityhub.sh (read-only reference for this
# benchmark - see bench/README.md). Only the IDENTITY_HUB_DIR default path
# was changed to point at this checkout's own vendor/identity-hub. This
# benchmark's own bearer tokens are minted independently (see
# bench/verifier-token/) - this script is used purely to boot a real,
# seeded eclipse-edc/IdentityHub v0.18.0 Credential Service to compare
# against, exactly as validated by the source repo's own validate.py.
#
# Builds (if needed) and runs eclipse-edc/IdentityHub's "identityhub"
# launcher (the holder/wallet + embedded STS + Presentation API side of
# DCP) with the dcp-test-env seed extension attached, seeding a
# "dcp-test-client" holder participant, a "verifier" participant (stands
# in for federated-catalog-rs's own DCP identity - see
# seed/src/IdentityHubSeedExtension.java's doc comment), and a real
# ES256-signed JWT-VC in the holder's credential store.
#
# Requires: dataspace/vendor/identity-hub already built at least once
# (`./gradlew :launcher:identityhub:run` from that directory) so its
# dependency jars exist under */build/libs and ~/.gradle/caches - this
# script captures a *running* instance's classpath rather than
# reinvoking Gradle, so it starts in ~2s instead of re-running the build
# tool. Run compliance/dcp-test-env/build-and-run.sh once first if you
# haven't built identity-hub/issuer-service yet.
#
# Ports (see README.md "Port map"):
#   9080 base, 9081 identity API, 9082 credentials/presentation API,
#   9083 DID hosting, 9084 STS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDENTITY_HUB_DIR="${IDENTITY_HUB_DIR:-$SCRIPT_DIR/../../../vendor/identity-hub}"
KEYS_DIR="$SCRIPT_DIR/keys"
SEED_DIR="$SCRIPT_DIR/seed"

mkdir -p "$KEYS_DIR"

NIMBUS_JAR=$(find ~/.gradle/caches -name 'nimbus-jose-jwt-*.jar' | head -1)
if [ -z "$NIMBUS_JAR" ]; then
  echo "Could not find nimbus-jose-jwt jar in ~/.gradle/caches - build identity-hub first." >&2
  exit 1
fi

mkdir -p "$SEED_DIR/out"
javac -cp "$NIMBUS_JAR" -d "$SEED_DIR/out" "$SEED_DIR/src/GenerateIssuerKey.java"

for key_id in issuer-key dcp-test-client-key verifier-key; do
  if [ ! -f "$KEYS_DIR/$key_id-private.jwk.json" ]; then
    java -cp "$NIMBUS_JAR:$SEED_DIR/out" GenerateIssuerKey "$KEYS_DIR" "$key_id"
  fi
done

# Capture identity-hub's launcher classpath by asking Gradle for it once
# (cheap: everything is already built, this is a no-op build check).
CLASSPATH_FILE="$SEED_DIR/idhub-classpath.txt"
if [ ! -f "$CLASSPATH_FILE" ]; then
  echo "First run: capturing identity-hub's classpath via a throwaway run (needed once per checkout)..." >&2
  (cd "$IDENTITY_HUB_DIR" && nohup ./gradlew :launcher:identityhub:run > /tmp/idhub-classpath-capture.log 2>&1 &)
  for _ in $(seq 1 120); do
    PID=$(pgrep -f "org.eclipse.edc.boot.system.runtime.BaseRuntime.*identityhub\|identityhub.*BaseRuntime" | head -1 || true)
    [ -n "$PID" ] && break
    sleep 1
  done
  PID=$(pgrep -f "launcher/identityhub/build/classes" | head -1)
  python3 -c "
with open('/proc/$PID/cmdline', 'rb') as f:
    args = f.read().split(b'\x00')
args = [a.decode() for a in args if a]
cp = args[args.index('-cp') + 1]
open('$CLASSPATH_FILE', 'w').write(cp)
"
  kill -9 "$PID" 2>/dev/null || true
fi
CP="$(cat "$CLASSPATH_FILE")"

mkdir -p "$SEED_DIR/out/META-INF/services"
javac -cp "$CP" -d "$SEED_DIR/out" "$SEED_DIR/src/IdentityHubSeedExtension.java"
printf 'IdentityHubSeedExtension\n' > "$SEED_DIR/out/META-INF/services/org.eclipse.edc.spi.system.ServiceExtension"
(cd "$SEED_DIR/out" && jar cf ../identityhub-seed.jar IdentityHubSeedExtension.class 'IdentityHubSeedExtension$SeedEnv.class' META-INF/services/org.eclipse.edc.spi.system.ServiceExtension)

export WEB_HTTP_PORT=9080 WEB_HTTP_PATH=/api \
  WEB_HTTP_IDENTITY_PORT=9081 WEB_HTTP_IDENTITY_PATH=/api/identity \
  WEB_HTTP_CREDENTIALS_PORT=9082 WEB_HTTP_CREDENTIALS_PATH=/api/credentials \
  WEB_HTTP_DID_PORT=9083 WEB_HTTP_DID_PATH=/ \
  WEB_HTTP_STS_PORT=9084 WEB_HTTP_STS_PATH=/sts \
  EDC_IAM_DID_WEB_USE_HTTPS=false \
  SEED_IDENTITYHUB_DID_HOST=localhost:9083 \
  SEED_ISSUER_DID_HOST=localhost:9093 \
  SEED_CREDENTIALS_BASE_URL=http://localhost:9082/api/credentials \
  SEED_KEYS_DIR="$KEYS_DIR" \
  SEED_INFO_FILE="$KEYS_DIR/seed-info.json"

echo "Starting seeded IdentityHub on :9080-9084 ..."
exec java -cp "$CP:$SEED_DIR/identityhub-seed.jar" org.eclipse.edc.boot.system.runtime.BaseRuntime
