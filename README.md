# Identity Hub

*(repo/product: `ds-identity-hub-rs`)*

A from-scratch Rust implementation of a **DCP Identity Hub**: a
[Decentralized Claims Protocol (DCP)](https://eclipse-dataspace-dcp.github.io/decentralized-claims-protocol/)
**Credential Service** implementing both DCP sub-protocols, plus a minimal
**Issuer Service** implementing one of them:

> "This section defines a protocol for storing and presenting Verifiable
> Credentials and other identity-related resources. The Verifiable
> Presentation Protocol covers the following aspects: Endpoints and message
> types for storing identity resources belonging to a Holder in a
> Credential Service; Endpoints and message types for resolving an
> identity Resource; Secure token exchange for restricting access to
> Credential Service endpoints."
> — [`verifiable.presentation.protocol.md`](https://github.com/eclipse-dataspace-dcp/decentralized-claims-protocol/blob/main/specifications/verifiable.presentation.protocol.md)

> "The Credential Issuance Protocol defines the endpoints and message types
> for requesting Verifiable Credentials from a Credential Issuer."
> — [`credential.issuance.protocol.md`](https://github.com/eclipse-dataspace-dcp/decentralized-claims-protocol/blob/main/specifications/credential.issuance.protocol.md)

It is the Rust-native counterpart to `vendor/identity-hub` (the vendored
Eclipse EDC IdentityHub Java reference tracked by the `dataspace` study
repo per ADR-0008), the same way
[`ds-catalog-broker-rs`](https://github.com/ds-labs-org/ds-catalog-broker-rs)
is a from-scratch Rust counterpart to Eclipse EDC's Federated Catalog
module.

## Role and serving surfaces

Two process modes, selected at startup (`identity-hub credential-service`
or `identity-hub issuer-service`):

- **Credential Service** — both DCP sub-protocols: the **Verifiable
  Presentation Protocol**'s Resolution API (`POST /presentations/query`,
  answering scope-based queries with real signed Verifiable Presentations)
  and the **Credential Issuance Protocol**'s Storage API (`POST
  /credentials`, accepting issued credentials) and Credential Offer API
  (`POST /offers`).
- **Issuer Service** — the Credential Issuance Protocol only: the
  Credential Request API (`POST /credentials`), Credential Request Status
  API (`GET /requests/<id>`), and Issuer Metadata API (`GET /metadata`),
  plus asynchronous delivery of issued credentials to a requester's own
  Credential Service.

Both modes also host a `did:web`-resolvable DID document
(`GET /<segment>/did.json`) and a minimal Secure Token Service (`POST
/sts/token`, an OAuth2 `client_credentials`-grant-shaped endpoint that
mints real ES256-signed Self-Issued ID Tokens).

### OpenID for Verifiable Credential Issuance (OID4VCI 1.0), side by side

Each mode also speaks
[OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
on the same port, next to DCP (Pre-Authorized Code flow, `jwt_vc_json`,
`jwt` key proofs):

- **Issuer Service = OID4VCI Credential Issuer** — `GET
  /.well-known/openid-credential-issuer`, `GET
  /.well-known/oauth-authorization-server` (it is its own Authorization
  Server), `POST /oid4vci/token`, `POST /oid4vci/nonce`, `POST
  /oid4vci/credential`, and `GET /oid4vci/offers/<id>` (offers by
  reference). It issues the same signed credential the DCP Credential
  Request API delivers.
- **Credential Service = OID4VCI Wallet** — `POST /oid4vci/wallet/offers`
  redeems an offer from any OID4VCI issuer and stores the credential in the
  same store the DCP Storage API writes to, so it is immediately
  presentable over DCP's `POST /presentations/query`.

Creating an offer (`POST /oid4vci/offers` on the Issuer Service) and asking
the wallet to redeem one are operator actions neither spec defines; both
require HTTP Basic auth with the configured STS client credentials. The
wallet keeps the DCP side's posture: outbound allow-list on every request,
and only credentials from a `--trusted-issuer-did`, genuinely signed and
bound to this Credential Service's own DID, are stored.

Against third-party issuers the wallet also uses DPoP when the issuer
advertises it and `private_key_jwt` client authentication when started with
`--oid4vci-client-id`. `--oid4vci-offer-endpoint` mounts the spec's
Credential Offer Endpoint (`GET /oid4vci/wallet/credential_offer`), off by
default. CI runs the OpenID Foundation conformance suite's OID4VCI wallet
test plan against it (`ci/oidf/run.sh`).

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for exactly what's implemented,
simplified, or out of scope, and for a real, date-stamped conformance run
against the official
[Eclipse Dataspace TCK for DCP](https://github.com/eclipse-dataspacetck/dcp-tck).

## Crates

- `identity-hub-core` — domain types: `did:web` service-identity
  construction, DCP's Verifiable Presentation Protocol / Credential
  Issuance Protocol wire-message shapes, OID4VCI 1.0 wire shapes and
  key-proof checks (`oid4vci`), an in-memory accepted-credential
  store, a DCP scope-to-credential-type matcher, and a minimal in-memory
  Secure Token Service. Built on
  [`ds-dcp-core-rs`](https://github.com/ds-labs-org/ds-dcp-core-rs)'s
  role-agnostic compact-JWS and `did:web` primitives — see
  `ARCHITECTURE.md`, "Provenance" for how that crate relates to
  `ds-catalog-broker-rs`.
- `identity-hub-http` — the `axum` HTTP surface for both process modes,
  the `identity-hub` binary, and the real `dcp-tck-runtime` conformance
  test (`tests/dcp_tck.rs`).

Reference material: the DCP specification
([`eclipse-dataspace-dcp/decentralized-claims-protocol`](https://github.com/eclipse-dataspace-dcp/decentralized-claims-protocol)),
its conformance suite
([`eclipse-dataspacetck/dcp-tck`](https://github.com/eclipse-dataspacetck/dcp-tck)),
and the real Java reference implementation
([`eclipse-edc/IdentityHub`](https://github.com/eclipse-edc/IdentityHub),
vendored read-only at `dataspace/vendor/identity-hub`). Study and research
behind this rewrite lives in the
[`dataspace`](https://labs.deepthought-solutions.net/Deepthought-Solutions/dataspace)
repo (`docs/spikes/`, `docs/adr/`, `authority/`).

## Layout

```
crates/
  identity-hub-core/       domain types (did:web identities, DCP wire
                            messages, credential store, scope matcher, STS)
  identity-hub-http/       HTTP surface, binary, and TCK conformance test
    src/
      config.rs             Mode/Config
      state.rs               shared application state
      auth.rs                 Self-Issued ID Token validation
      handlers.rs             all DCP HTTP routes, both modes
      oid4vci.rs              OID4VCI issuer + wallet routes
      main.rs                 CLI entry point
    tests/
      dcp_tck.rs              real dcp-tck-runtime conformance test
      dcp.tck.properties      TCK config bind-mounted into the container
```

## Building and testing

```bash
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                                                    # fast, no Docker
cargo test -p identity-hub-http --test dcp_tck -- --ignored --nocapture   # needs Docker
```

## Running it

```bash
# Credential Service (VPP + CIP). --trusted-issuer-did is required (may be
# repeated) - an empty allow-list trusts nobody, so the Storage API and
# Credential Offer API reject every write with 401 until at least one is
# given (2026-09-20 fix, HIGH; see Config::trusted_issuer_dids's doc comment):
cargo run -p identity-hub-http --bin identity-hub -- credential-service --did-host localhost:8080 --trusted-issuer-did did:web:some-issuer.example:issuer

# Minimal Issuer Service (CIP only):
cargo run -p identity-hub-http --bin identity-hub -- issuer-service --bind 0.0.0.0:8081 --did-host localhost:8081
```

OID4VCI round trip between the two. Start the Credential Service with
`--trusted-issuer-did did:web:localhost%3A8081:issuer-service` so it accepts
what that Issuer Service signs; `<id>:<secret>` is `--sts-client-id`/
`--sts-client-secret` (set real values outside local testing):

```bash
# 1. Issuer operator mints an offer (add "tx_code": true for a PIN).
curl -s -u <id>:<secret> -H 'content-type: application/json' \
  -d '{}' http://localhost:8081/oid4vci/offers
# 2. Hand its "offer_uri" (plus "tx_code" if any) to the wallet.
curl -s -u <id>:<secret> -H 'content-type: application/json' \
  -d '{"offer": "openid-credential-offer://?credential_offer_uri=..."}' \
  http://localhost:8080/oid4vci/wallet/offers
```

## License

Apache-2.0, matching upstream Eclipse EDC. See [LICENSE](LICENSE).
