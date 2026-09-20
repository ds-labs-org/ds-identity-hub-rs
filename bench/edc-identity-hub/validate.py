#!/usr/bin/env python3
"""Validates the dcp-test-env end to end: performs a real DCP
presentation-query round trip against the running, seeded IdentityHub +
Issuer Service (start both first via run-identityhub.sh and
run-issuer-service.sh), decodes the returned VerifiablePresentation, and
checks that it contains the seeded FederatedCatalogAccessCredential with
a genuinely-verifiable signature chain:

  1. holder's STS mints a self-issued token for the "verifier" identity,
     embedding a nested presentation-access-token (scoped).
  2. verifier's STS re-packages that nested token into a *new*
     self-issued token addressed back to the holder - this is DCP's
     "proof of original possession" step (see
     seed/src/IdentityHubSeedExtension.java's doc comment on why a
     "verifier" participant exists in this test environment at all).
  3. That re-packaged token is presented to the holder's Presentation
     API, which returns a signed VerifiablePresentation.
  4. This script decodes the VP and the VC(s) inside it (does not
     cryptographically verify the ES256 signatures itself - that's
     federated-catalog-rs's job, once its own DCP verifier exists) and
     checks the structural/content expectations: right holder/issuer
     DIDs, right credential type, right catalogAccess claim.

Does NOT require Rust or any federated-catalog-rs code - this only
validates the test environment itself, per the "prepare a test
environment ... to validate the DCP implementation" ask. It intentionally
stops short of ES256 signature verification (that's what the Rust DCP
verifier will do for real, against these exact same live services).

Usage: python3 validate.py
"""
import base64
import json
import sys
import urllib.request
import urllib.parse

SEED_INFO_PATH = "keys/seed-info.json"
STS_URL = "http://localhost:9084/sts/token"
PRESENTATION_URL = "http://localhost:9082/api/credentials/v1/participants/{}/presentations/query"
SCOPE = "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read"
EXPECTED_CREDENTIAL_TYPE = "FederatedCatalogAccessCredential"
EXPECTED_CATALOG_ACCESS = ["CAT0101", "CAT0102"]


def b64d(segment: str) -> bytes:
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def decode_jwt(token: str) -> tuple[dict, dict]:
    header_b64, payload_b64, _sig = token.split(".")
    return json.loads(b64d(header_b64)), json.loads(b64d(payload_b64))


def post_form(url: str, fields: dict) -> dict:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def post_json(url: str, body: dict, bearer: str) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                  headers={"Content-Type": "application/json", "Authorization": f"Bearer {bearer}"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> None:
    with open(SEED_INFO_PATH) as f:
        seed = json.load(f)

    print(f"holder DID:   {seed['holderDid']}")
    print(f"issuer DID:   {seed['issuerDid']}")
    print(f"verifier DID: {seed['verifierDid']}")

    # Step 1: holder mints an SI token addressed to the verifier.
    holder_sts = post_form(STS_URL, {
        "grant_type": "client_credentials",
        "client_id": seed["holderStsClientId"],
        "client_secret": seed["holderStsClientSecret"],
        "audience": seed["verifierDid"],
        "bearer_access_scope": SCOPE,
    })
    _, holder_payload = decode_jwt(holder_sts["access_token"])
    nested_token = holder_payload["token"]
    print("Step 1 OK: holder minted SI token with nested presentation-access-token")

    # Step 2: verifier re-packages the nested token via its own STS
    # (proof of original possession).
    verifier_sts = post_form(STS_URL, {
        "grant_type": "client_credentials",
        "client_id": seed["verifierStsClientId"],
        "client_secret": seed["verifierStsClientSecret"],
        "audience": seed["holderDid"],
        "token": nested_token,
    })
    repackaged_token = verifier_sts["access_token"]
    print("Step 2 OK: verifier re-packaged the token via its own STS")

    # Step 3: present the re-packaged token to the holder's Presentation
    # API, requesting the seeded credential's scope.
    query_url = PRESENTATION_URL.format(seed["holderParticipantId"])
    vp_response = post_json(query_url, {
        "@context": "https://w3id.org/dspace-dcp/v1.0/dcp.jsonld",
        "@type": "PresentationQueryMessage",
        "scope": [SCOPE],
    }, repackaged_token)
    print("Step 3 OK: presentation query returned", vp_response.get("type"))

    presentations = vp_response.get("presentation", [])
    if not presentations:
        fail("no presentation returned")

    vp_header, vp_payload = decode_jwt(presentations[0])
    if vp_payload.get("iss") != seed["holderDid"]:
        fail(f"VP issuer mismatch: {vp_payload.get('iss')} != {seed['holderDid']}")
    if not vp_header.get("kid", "").startswith(seed["holderDid"]):
        fail(f"VP kid does not reference holder DID: {vp_header.get('kid')}")

    vcs = vp_payload.get("vp", {}).get("verifiableCredential", [])
    if not vcs:
        fail("no verifiableCredential in VP")

    vc_header, vc_payload = decode_jwt(vcs[0])
    if vc_payload.get("iss") != seed["issuerDid"]:
        fail(f"VC issuer mismatch: {vc_payload.get('iss')} != {seed['issuerDid']}")
    if not vc_header.get("kid", "").startswith(seed["issuerDid"]):
        fail(f"VC kid does not reference issuer DID: {vc_header.get('kid')}")

    vc_body = vc_payload.get("vc", {})
    if EXPECTED_CREDENTIAL_TYPE not in vc_body.get("type", []):
        fail(f"credential type mismatch: {vc_body.get('type')}")

    subject = vc_body.get("credentialSubject", {})
    if subject.get("catalogAccess") != EXPECTED_CATALOG_ACCESS:
        fail(f"catalogAccess claim mismatch: {subject.get('catalogAccess')}")

    print("Step 4 OK: VP signed by holder DID, VC signed by issuer DID,")
    print(f"           credential type={EXPECTED_CREDENTIAL_TYPE},")
    print(f"           catalogAccess={subject.get('catalogAccess')}")
    print()
    print("dcp-test-env: full DCP presentation round trip validated "
          "(structure + DIDs; ES256 signature verification is Rust's job).")


if __name__ == "__main__":
    main()
