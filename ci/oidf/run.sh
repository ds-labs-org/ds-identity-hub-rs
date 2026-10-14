#!/usr/bin/env bash
# Run the OpenID Foundation conformance suite's OID4VCI wallet test plan
# against this repo's Credential Service (the hub as an OID4VCI wallet).
#
# Expects a built target/release/identity-hub, Docker with compose, python3,
# and sudo (for /etc/hosts). Used by the oid4vci-conformance job in
# .github/workflows/ci.yml; runs the same way on a Linux workstation.
set -euo pipefail

SUITE_TAG="${SUITE_TAG:-release-v5.3.3}"
HUB_PORT=8090
CLIENT_ID="ds-identity-hub-ci"
OFFER_ENDPOINT="http://host.docker.internal:${HUB_PORT}/oid4vci/wallet/credential_offer"
# The suite always prompts for this Transaction Code in its pre-authorized
# code flow.
TX_CODE=123456
PLAN="oid4vci-1_0-wallet-test-plan[authorization_request_type=simple][client_auth_type=private_key_jwt][fapi_request_method=unsigned][sender_constrain=dpop][vci_authorization_code_flow_variant=issuer_initiated][vci_grant_type=pre_authorization_code][vci_credential_offer_variant=by_value][fapi_profile=vci][credential_format=sd_jwt_vc][vci_credential_encryption=plain][vci_credential_issuance_mode=immediate]:oid4vci-1_0-wallet-test-credential-issuance"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="${OIDF_WORK_DIR:-$REPO/target/oidf}"
SUITE="$WORK/conformance-suite"
export OIDF_CERT_DIR="$WORK/certs"
mkdir -p "$WORK" "$OIDF_CERT_DIR"

compose() {
    docker compose -p oidf -f "$SUITE/docker-compose-prebuilt.yml" -f "$HERE/docker-compose.override.yml" "$@"
}

echo "==> Fetching conformance suite $SUITE_TAG"
if [ ! -d "$SUITE" ]; then
    git clone --quiet --depth 1 --branch "$SUITE_TAG" https://gitlab.com/openid/conformance-suite.git "$SUITE"
fi

echo "==> Issuing a TLS certificate for localhost.emobix.co.uk"
cd "$OIDF_CERT_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=oidf-ci-root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost.emobix.co.uk" \
    -keyout server.key -out server.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
    -extfile server.ext -out server.crt 2>/dev/null
chmod 644 server.key
cd "$REPO"

grep -q "localhost.emobix.co.uk" /etc/hosts || echo "127.0.0.1 localhost.emobix.co.uk" | sudo tee -a /etc/hosts >/dev/null
grep -q "host.docker.internal" /etc/hosts || echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts >/dev/null

echo "==> Starting the conformance suite"
IMAGE_TAG="$SUITE_TAG" compose up -d

echo "==> Starting the hub as an OID4VCI wallet"
"$REPO/target/release/identity-hub" credential-service \
    --bind "0.0.0.0:${HUB_PORT}" \
    --did-host "host.docker.internal:${HUB_PORT}" \
    --allow-resolve-host localhost.emobix.co.uk \
    --oid4vci-client-id "$CLIENT_ID" \
    --oid4vci-offer-endpoint \
    --oid4vci-offer-tx-code "$TX_CODE" \
    --extra-root-cert "$OIDF_CERT_DIR/ca.crt" \
    > "$WORK/hub.log" 2>&1 &
HUB_PID=$!

cleanup() {
    status=$?
    kill "$HUB_PID" 2>/dev/null || true
    if [ "$status" -ne 0 ]; then
        echo "==> Hub log"; cat "$WORK/hub.log" || true
        echo "==> Suite server log (tail)"; compose logs --tail 300 server || true
    fi
    IMAGE_TAG="$SUITE_TAG" compose down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 60); do
    curl -fsS "http://127.0.0.1:${HUB_PORT}/credential-service/did.json" -o "$WORK/did.json" && break
    sleep 1
done
test -s "$WORK/did.json" || { echo "hub did not come up"; exit 1; }

python3 "$HERE/build-config.py" \
    "$SUITE/scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json" \
    "$WORK/did.json" "$CLIENT_ID" "$OFFER_ENDPOINT" "$WORK/wallet-config.json"

echo "==> Waiting for the suite to accept requests"
for _ in $(seq 1 120); do
    curl -ksf https://localhost.emobix.co.uk:8443/api/runner/available -o /dev/null && break
    sleep 2
done

echo "==> Running $PLAN"
python3 -m pip install --quiet -r "$SUITE/scripts/requirements.txt"
mkdir -p "$WORK/results"
# No CONFORMANCE_SERVER: the script then targets the local dev deployment
# (https://localhost.emobix.co.uk:8443/) without an API token.
python3 "$SUITE/scripts/run-test-plan.py" --verbose --export-dir "$WORK/results" \
    "$PLAN" "$WORK/wallet-config.json"
