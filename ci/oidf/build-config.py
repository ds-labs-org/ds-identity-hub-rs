#!/usr/bin/env python3
"""Build the OIDF wallet test plan config for the identity hub.

Usage: build-config.py <suite-template.json> <hub-did.json> <client-id> <offer-endpoint> <out.json>

Starts from the suite's own vci-wallet-test-config-plain.json and swaps in
what the suite needs to know about the wallet under test:

- client.client_id and client.jwks: the hub's DID key, with kid set to the
  DID URL the hub signs its key proofs and client assertions with.
- vci.credential_offer_endpoint: where the suite's browser delivers the offer.
- browser: a single task that only checks the browser landed on that
  endpoint; the hub answers with JSON, not a page to click through.

Everything else (credential.signing_jwk, server.jwks, timeouts) stays as the
suite ships it.
"""
import json
import sys

template_path, did_path, client_id, offer_endpoint, out_path = sys.argv[1:]

with open(template_path) as f:
    # The template carries a {vp-server-jwk.json} placeholder that
    # run-test-plan.py fills in later, so it is not valid JSON yet. Swap it
    # for a sentinel, parse, and put it back on the way out.
    raw = f.read().replace("{vp-server-jwk.json}", '"__VP_SERVER_JWK__"')
config = json.loads(raw)

with open(did_path) as f:
    did = json.load(f)
method = did["verificationMethod"][0]
jwk = dict(method["publicKeyJwk"])
jwk.update({"kid": method["id"], "use": "sig", "alg": "ES256"})

config["client"]["client_id"] = client_id
config["client"]["jwks"] = {"keys": [jwk]}
config["vci"]["credential_offer_endpoint"] = offer_endpoint
config["browser"] = [
    {
        "comment": "the hub redeems the offer while answering this request",
        "match": offer_endpoint + "*",
        "tasks": [{"task": "Offer delivered", "match": offer_endpoint + "*"}],
    }
]

out = json.dumps(config, indent=2).replace('"__VP_SERVER_JWK__"', "{vp-server-jwk.json}")
with open(out_path, "w") as f:
    f.write(out + "\n")
