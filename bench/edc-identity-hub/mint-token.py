#!/usr/bin/env python3
"""Mints a single, ready-to-use bearer token for EDC IdentityHub's real
Presentation API (POST .../presentations/query), following exactly the same
two-step DCP proof-of-original-possession recipe this benchmark's sibling
dcp-test-env/validate.py already validates end to end (see that script's
own module doc comment for the full explanation of why two STS calls are
needed, not one):

  1. holder's STS mints a self-issued token addressed to the verifier,
     embedding a nested presentation-access-token scoped to SCOPE.
  2. verifier's STS re-packages that nested token into a *new* self-issued
     token addressed back to the holder - DCP's "proof of original
     possession" step.

Prints the final bearer token (no "Bearer " prefix) to stdout, nothing else,
so it can be captured directly: `TOKEN=$(python3 mint-token.py)`.

Run this immediately before each k6 invocation (warmup and measured run
alike) rather than once for the whole benchmark - see bench/README.md for
why token freshness matters here.

Usage: python3 mint-token.py [--scope SCOPE]
"""
import argparse
import json
import os
import urllib.request
import urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SEED_INFO_PATH = os.path.join(SCRIPT_DIR, "keys", "seed-info.json")
STS_URL = "http://localhost:9084/sts/token"
DEFAULT_SCOPE = "org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read"


def b64d(segment: str) -> bytes:
    import base64
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def decode_jwt_payload(token: str) -> dict:
    _header_b64, payload_b64, _sig = token.split(".")
    return json.loads(b64d(payload_b64))


def post_form(url: str, fields: dict) -> dict:
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", default=DEFAULT_SCOPE)
    args = parser.parse_args()

    with open(SEED_INFO_PATH) as f:
        seed = json.load(f)

    holder_sts = post_form(STS_URL, {
        "grant_type": "client_credentials",
        "client_id": seed["holderStsClientId"],
        "client_secret": seed["holderStsClientSecret"],
        "audience": seed["verifierDid"],
        "bearer_access_scope": args.scope,
    })
    nested_token = decode_jwt_payload(holder_sts["access_token"])["token"]

    verifier_sts = post_form(STS_URL, {
        "grant_type": "client_credentials",
        "client_id": seed["verifierStsClientId"],
        "client_secret": seed["verifierStsClientSecret"],
        "audience": seed["holderDid"],
        "token": nested_token,
    })
    print(verifier_sts["access_token"])


if __name__ == "__main__":
    main()
