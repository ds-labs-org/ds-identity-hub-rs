# Architecture

**Status:** Bootstrap, working end to end against the real TCK (see "DCP TCK
conformance snapshot" below). Not yet integrated with a live dataspace
control plane, a real key-management/HSM backend, or a persistent store.
**Date:** 2026-09-20 (real per-request authorization added to the Storage
API and Credential Offer API; see "What's simplified or stubbed" and "DCP
TCK conformance snapshot" below — 36 -> 22 real TCK failures, TDD'd and
re-measured, not assumed)

This file records the scope and design decisions behind this project's
bootstrap, why each was made, and an honest accounting of what actually
works versus what's stubbed or out of scope — a submodule-local
architecture record, following the same pattern
`ds-sql-dps-rs/ARCHITECTURE.md` and `ds-catalog-broker-rs`'s own docs use
across the `ds42.org` study's sibling product repos.

## What this project is

`ds-identity-hub-rs` is a from-scratch Rust implementation of a **DCP
Identity Hub** for the ds42.org dataspace study's "authority" membership
role: a **Credential Service** implementing the
[Decentralized Claims Protocol (DCP)](https://eclipse-dataspace-dcp.github.io/decentralized-claims-protocol/)'s
two sub-protocols — the **Verifiable Presentation Protocol (VPP)**, which
defines how a party stores and presents Verifiable Credentials, and the
**Credential Issuance Protocol (CIP)**, which defines how Verifiable
Credentials are requested, offered, and delivered — plus a minimal
**Issuer Service** implementing CIP only. It is the Rust-native counterpart
to `vendor/identity-hub` (the vendored Eclipse EDC IdentityHub Java
reference tracked in the `dataspace` repo per ADR-0008), the same way
`ds-catalog-broker-rs` is a from-scratch Rust counterpart to Eclipse EDC's
Federated Catalog module.

DCP's own specification defines four roles relevant here:

- **Credential Service** — stores a holder's Verifiable Credentials and
  answers Presentation API (VPP) queries from a Verifier; also the target
  of the Storage API (CIP) and Credential Offer API (CIP).
- **Issuer Service** — issues Verifiable Credentials on request (Credential
  Request API, CIP) and delivers them asynchronously via the target
  Credential Service's Storage API.
- **Verifier** — queries a Credential Service's Presentation API to obtain
  Verifiable Presentations. Not implemented by this project (out of scope —
  see "What's out of scope").
- **Secure Token Service (STS)** — mints Self-Issued ID Tokens. This
  bootstrap implements one minimal, in-memory STS per process, alongside
  whichever of the two roles above that process is playing.

The conformance suite this project is checked against is the real, official
[Eclipse Dataspace TCK for DCP](https://github.com/eclipse-dataspacetck/dcp-tck)
(`eclipsedataspacetck/dcp-tck-runtime` Docker image), which tests three
possible systems under test with different obligations:

| SUT | VPP | CIP |
|---|---|---|
| Credential Service | yes | yes |
| Issuer Service | no | yes |
| Verifier | yes | no |

This project's Credential Service mode is tested against the TCK's
`*.presentation.cs` and `*.issuance.cs` packages (both VPP and CIP
obligations); its Issuer Service mode is implemented but **not yet run
against the TCK's own `*.issuance.issuer` package** — see "What's out of
scope".

## Provenance: `ds-dcp-core-rs`

`identity-hub-core` depends on
[`ds-dcp-core-rs`](https://github.com/ds-labs-org/ds-dcp-core-rs) (pinned
by `rev`, not a floating branch — see `Cargo.toml`'s
`[workspace.dependencies]`) for role-agnostic DCP primitives: compact JWS
(ES256) signing/verification, `did:web` resolution, and the base
`PresentationQueryMessage`/`PresentationResponseMessage` shapes. That crate
was itself extracted from `ds-catalog-broker-rs`'s own `dcp-core` crate
(history preserved via `git subtree split`), where it served a DSP
crawler's **holder** role presenting credentials to a gated Catalog
Service. This project is `ds-dcp-core-rs`'s second real consumer, using the
exact same primitives from the **Credential Service/Issuer Service** side
of the same protocol instead of the holder side — the reason the crate was
made role-agnostic and pulled out of `ds-catalog-broker-rs` in the first
place.

**Why this project defines its own message types instead of relying on
`ds-dcp-core-rs` for everything** (`identity-hub-core/src/messages.rs`):
that crate's own `PresentationQueryMessage` is serialize-only (built for a
*client* to send, not a server to receive) and its
`PresentationResponseMessage` omits the DCP-spec-required `@context`/`type`
envelope fields — acceptable for `ds-catalog-broker-rs`'s own use (a
crawler that only ever sends the former and loosely parses the latter) but
not spec-conformant for a server whose output the real TCK schema-validates
byte-for-byte. `identity-hub-core::messages` defines the full VPP/CIP
message vocabulary field-for-field against the DCP specification's own
JSON schemas and examples (cross-checked against
`eclipse-dataspace-dcp/decentralized-claims-protocol`'s
`artifacts/src/main/resources/{presentation,issuance}/`, not guessed).

Similarly, `identity-hub-core::identity::ServiceIdentity` builds its own DID
documents rather than reusing `ds-dcp-core-rs::DcpKeyPair::did_document`,
because the latter omitted the `authentication`/`assertionMethod`/
`capabilityInvocation` verification-relationship arrays the DCP spec (and
the real TCK's `TestFixtures.assertVerificationRelationship`) requires — see
that module's doc comment for the full argument.

**2026-09-20 update:** `ds-dcp-core-rs` was bumped to commit `931c6719`
(from `d55b62d7`), which fixes exactly that gap — `DcpKeyPair::did_document`
now emits real `authentication`/`assertionMethod`/`capabilityInvocation`
arrays, backed by a genuine test
(`did_document_carries_verification_relationships`). This was re-evaluated
as a candidate to delete `ServiceIdentity`'s own hand-rolled
`did_document` and delegate to the upstream one, but it is **not** a clean,
equivalent swap, so the duplication stays:

- `DcpKeyPair::did_document`'s `@context` is just
  `["https://www.w3.org/ns/did/v1"]` — it never picked up the DCP JSON-LD
  context (`https://w3id.org/dspace-dcp/v1.0/dcp.jsonld`) that
  `ServiceIdentity::did_document` includes (`DID_CONTEXT`), which the DCP
  spec's own examples carry for a document with a
  `CredentialService`/`IssuerService` entry.
- `DcpKeyPair::did_document`'s `service` entries omit the `id` field
  (`ServiceIdentity::did_document` emits `"id": "<did>#<type>"` per entry);
  upstream's own consumer (`HolderIdentity` in `ds-catalog-broker-rs`'s
  lineage) never needed one, but this project's shape does.
- The signature also differs (`&[(String, String)]` vs. this crate's
  `&[(&str, &str)]`), a minor friction on top of the two shape gaps above.

Swapping in the upstream function as-is would silently drop the DCP
JSON-LD context and the per-service `id` from every DID document this
project serves — exactly the kind of TCK-scoped shape this bootstrap has
been careful to get byte-for-byte right (see "Why this project defines its
own message types" above for the same reasoning applied to messages
instead of DID documents). Since nothing here indicates the TCK's own
18-passing baseline currently depends on either field, this was not
re-verified against a live TCK run purely to prove a negative; the
existing `dcp_tck` conformance run (unchanged by this dependency bump —
see the snapshot below) is the standing evidence this hand-rolled path
still works. `ServiceIdentity::did_document` therefore stays as its own,
DCP-shape-complete implementation; only the verification-relationship
*values* it computes now agree with what upstream independently computes,
which is what made the fix worth pulling in at all — the two
implementations converging on the same `authentication`/`assertionMethod`/
`capabilityInvocation` values is itself evidence upstream's fix is
correct, cross-checked from a second, independent implementation.

## What's implemented (real, not stubbed)

- **`did:web` hosting**, for both a process's own Credential-Service/
  Issuer-Service identity and a second, synthetic identity used only by
  the embedded STS (see "The STS-party identity" below) — real ES256
  P-256 keys, real DID documents with correct verification-relationship
  arrays, genuinely resolvable over HTTP (`GET /<segment>/did.json`).
- **The Storage API** (`POST /credentials` on a Credential Service) — a
  real accept-and-store path: parses a `CredentialMessage`, stores every
  credential container in an in-memory, process-lifetime
  `InMemoryCredentialStore`. **Requires a valid Self-Issued ID Token**
  addressed to this service (`identity_hub_http::auth::verify_bearer_token`
  — the same function the Presentation API and the Issuer Service's
  Credential Request API already used), as of 2026-09-20 — see "What's
  simplified or stubbed" for exactly what that check does and does not
  cover.
- **The Presentation API's scope-based flow** (`POST
  /presentations/query`) — genuinely validates the incoming Self-Issued ID
  Token (JWS signature verified against the caller's resolved `did:web`
  document, audience checked against this service's own DID, expiry
  checked), rejects a request with both `scope` and `presentationDefinition`
  set or neither, returns `501 Not Implemented` for a well-formed
  `presentationDefinition` (unsupported, not silently ignored) and `400`
  for a malformed one, extracts the requested credential type(s) from
  `scope` via the DCP `org.eclipse.dspace.dcp.vc.type` scope alias (the
  same default regex the real TCK itself uses), looks up matching stored
  credentials, and returns a real, correctly-audienced, ES256-signed
  Verifiable Presentation wrapping them. Verified genuinely working against
  the real TCK — see "DCP TCK conformance snapshot".
- **The Credential Offer API** (`POST /offers` on a Credential Service) —
  accepts and logs a `CredentialOfferMessage`; does not yet trigger a
  holder-driven follow-up credential request (see "What's out of scope").
  **Requires a valid Self-Issued ID Token** addressed to this service, the
  same way the Storage API now does (see above and "What's simplified or
  stubbed").
- **The Credential Request API and asynchronous delivery** (`POST
  /credentials` on an Issuer Service) — validates the incoming Self-Issued
  ID Token, checks the requested credential id(s) against this bootstrap's
  one supported `CredentialObject` (`MembershipCredential`), responds `201
  Created` with a `Location` header, and — asynchronously, matching the
  spec's own described flow — resolves the requesting holder's `did:web`
  document, mints a real signed Verifiable Credential, and delivers it via
  a real HTTP `POST` to that holder's Storage API, authenticating with a
  fresh Self-Issued ID Token of its own (forwarding the client's original
  `token` claim per the spec, when present).
- **The Credential Request Status API** (`GET /requests/<id>`) and
  **Issuer Metadata API** (`GET /metadata`) on an Issuer Service — real,
  reflecting the in-memory request-tracking state above.
- **The embedded STS** (`POST /sts/token`) — a real OAuth2
  `client_credentials`-grant-shaped endpoint (one hardcoded client
  id/secret pair) that mints a genuinely ES256-signed Self-Issued ID Token,
  including the nested `token` (access-token) claim when
  `bearer_access_scope` is requested, per `base.protocol.md`.

### The STS-party identity

`identity_hub_core::sts`'s embedded STS mints tokens signed by a **second,
synthetic identity** this process also generates and hosts a `did:web`
document for (path segment `sts-party`) — never by the Credential/Issuer
Service's own identity. This matters for the real TCK run: the TCK, acting
as verifier, calls this STS to obtain the nested access-token half of the
Self-Issued ID Token it then constructs and signs *itself* with its own
generated key, addressed to this service. See that module's doc comment for
the full round-trip.

**A real networking gotcha, found and fixed by actually running the TCK**:
the TCK's own embedded callback server (hosting its self-generated
`verifier`/`issuer`/`thirdparty` DIDs) always binds container port 8083,
and it resolves *its own* hosted DIDs from inside the container over a real
HTTP round trip — including when checking a stored credential's issuer
proof. Since this crate's server runs natively (not containerized) and
must resolve those same DIDs to validate incoming Self-Issued ID Tokens,
`tests/dcp.tck.properties` uses `host.docker.internal` (not `localhost`)
for `dataspacetck.callback.address`, and `AppState::new` (`src/state.rs`)
configures its `reqwest::Client` with a static `host.docker.internal ->
127.0.0.1` DNS override so this process's own outbound resolution takes the
same hairpin path back through the TCK container's docker-published port.
Without this, every Self-Issued ID Token validation this service performs
fails with a DID-resolution error — not a subtle bug, but one only visible
by actually running the real container and reading the resulting
`ConnectException`/`error sending request` traces, which is exactly how it
was found (see `tests/dcp_tck.rs`'s module doc for the full account,
including the first (wrong) fixes tried along the way).

## What's simplified or stubbed

- **Real per-request authorization on the Storage API and Credential Offer
  API, added 2026-09-20 — but built on the same intentionally-partial
  Self-Issued ID Token validation as everywhere else (see the next
  bullet).** `storage_write` and `credential_offer`
  (`identity-hub-http/src/handlers.rs`) used to accept every well-formed
  message unconditionally, regardless of the `Authorization` header — a
  deliberate bootstrap trade-off, because the real TCK's own
  Credential-Service setup phase depends on the Storage API accepting its
  dynamically generated test credentials, and getting that wrong fails
  *every* Credential-Service test at setup before exercising anything else.
  Before changing this, that assumption was checked empirically rather than
  guessed: `storage_write` was temporarily instrumented to log every
  incoming `Authorization` header, the real TCK was run once, and the log
  showed every one of the TCK's own legitimate setup calls already carries
  a well-formed, correctly-audienced, resolvable-`did:web`-signed
  Self-Issued ID Token (only the two calls belonging to the
  `noAuthHeader`/`missingBearerPrefix` negative tests themselves lack one).
  So both endpoints now call `identity_hub_http::auth::verify_bearer_token`
  — the same function the Presentation API and Issuer Service's Credential
  Request API already used — and reject with `401` on failure, with no
  change needed to keep the TCK's own setup phase working. TDD'd:
  `tests/storage_offer_auth.rs` asserts each rejection case (missing
  header, no `"Bearer "` prefix, malformed token, expired, wrong audience,
  wrong signing key) red-then-green against both endpoints, independent of
  the TCK/Docker. Real, measured effect on TCK conformance: 14 of the 36
  previously-failing tests now pass — see "DCP TCK conformance snapshot".
- **Self-Issued ID Token validation is intentionally partial**
  (`identity-hub-http/src/auth.rs`): signature verification against the
  caller's resolved `did:web` document, audience match, and expiry are
  real; `iss == sub` equality, `nbf` leeway, the `capabilityInvocation`
  verification-relationship restriction on the signing key, and `jti`
  replay tracking are **not** checked. This gap is no longer specific to
  the Presentation API — now that the Storage/Offer APIs share the same
  `verify_bearer_token`, it applies there too (see "DCP TCK conformance
  snapshot"'s category 3).
- **No "trusted issuer" allow-list check.** `verify_bearer_token` accepts
  any `iss` whose `did:web` document resolves and whose key verifies the
  token's signature — there's no separate check that the issuing party is
  a *known/trusted* issuer (the DCP spec's own "Verify Trust" step, above
  and beyond signature verification). Invisible before 2026-09-20 (the
  Storage API accepted everything regardless of `iss`); now a real,
  distinct, TCK-caught gap (`cs_06_05_01_credentialMessage_untrustedIssuer`).
- **No message-content/business-logic validation on the Storage API or
  Credential Offer API**, independent of the wrapping Self-Issued ID Token:
  no schema/enum validation of the `CredentialMessage`/
  `CredentialOfferMessage` body itself (any `status` string is accepted;
  any body that merely deserializes is accepted), no check that a
  `CredentialMessage`'s `holderPid` matches a request this Issuer Service
  actually issued, no verification of a stored credential's own embedded
  proof, and no validation of a `CredentialOfferMessage`'s credential ids
  against a known catalog. Six TCK tests fail for exactly this reason — see
  "DCP TCK conformance snapshot"'s category 5.
- **Scope-based authorization is not enforced against a caller's own
  granted scope.** Once a Self-Issued ID Token validates, the Presentation
  API returns every stored credential matching the *requested* type,
  regardless of what the caller's own access token (`token` claim) was
  actually scoped to. A real scope-escalation attempt is not rejected.
- **No revocation status checking** (`StatusList2021`/
  `BitstringStatusList`) on presented or stored credentials.
- **No durable storage.** `InMemoryCredentialStore` and the Issuer
  Service's request-tracking map are both process-lifetime only.
- **The Issuer Service supports exactly one hardcoded `CredentialObject`**
  (`MembershipCredential`), not a configurable catalog.
- **Keys are generated fresh on every process start**, never persisted —
  safe for a self-hosted `did:web` identity (the document is served by the
  same process that signs with the key), matching `ds-dcp-core-rs`'s own
  `HolderIdentity` design; see that crate's doc comment for the full
  argument. Not a decision to reconsider without also reconsidering
  whether this hub needs a stable, persisted identity across restarts (a
  real deployment would).

## What's out of scope for this bootstrap

- **The Verifier role.** This project never queries anyone else's
  Presentation API; it only answers queries against its own store.
- **Running the TCK's `*.issuance.issuer` package** against this project's
  own Issuer Service mode. The Issuer Service's Credential Request API and
  asynchronous delivery path are implemented and spec-shaped (see above),
  but not yet checked against the real TCK the way the Credential Service
  mode is.
- **A holder-driven response to a Credential Offer.** `POST /offers`
  acknowledges an offer; nothing follows up with a `CredentialRequestMessage`
  in response.
- **Key rotation and revocation**, both described non-normatively by the
  spec (`credential.issuance.protocol.md`, "Key Rotation and Revocation").
- **Presentation Exchange `presentationDefinition` support** — genuinely
  rejected with `501 Not Implemented` rather than silently accepted or
  faked (see "What's implemented").
- **A live dataspace control plane, HSM, or persistent key/credential
  store.**

## DCP TCK conformance snapshot

**Run against a real, locally running `eclipsedataspacetck/dcp-tck-runtime:latest`
container — 2026-09-20**, after adding real per-request authorization to
the Storage API and Credential Offer API (see "What's simplified or
stubbed"). Not fabricated: `tests/dcp_tck.rs` boots this crate's real
Credential Service in-process and drives the actual, official TCK
container against it via `testcontainers`, exactly as it runs in CI.
Reproduced twice with an identical failure set before being written down
here (both before the change, to confirm the documented 36-failure
baseline still held, and after, to confirm the new 22-failure result is
stable).

Scoped to the Credential Service test packages
(`org.eclipse.dataspacetck.dcp.verification.presentation.cs` +
`....issuance.cs`), per the SUT matrix above:

| Test package | Total | Passed | Failed |
|---|---:|---:|---:|
| `presentation.cs` (VPP) | 23 | 16 | 7 |
| `issuance.cs` (CIP) | 31 | 16 | 15 |
| **Total** | **54** | **32** | **22** |

(The previous snapshot's per-package passed/failed split was stale — it
correctly totaled 18 passed / 36 failed but misattributed several
`issuance.cs` failures to `presentation.cs`; re-derived here directly from
the TCK's own stack traces, which name the failing test's class and
package unambiguously, rather than repeated. `presentation.cs`'s own
16/7 split is unchanged by this change — nothing here touches the
Presentation API.)

`tests/dcp_tck.rs`'s `EXPECTED_FAILURES` asserts the **exact** set of 22
failing test method names (not just the count) — a regression on any of the
32 currently-passing tests, or any new/different failure, fails that test;
so does the TCK reporting fewer than 22 failures without a matching update
here (a sign the claims above have gone stale). The 22 fall into five
categories, matching "What's simplified or stubbed" above (see
`EXPECTED_FAILURES`'s own comments for the full per-category test list):

1. **Self-Issued ID Token validation gaps on the Presentation API (6 of
   22)** — `iss != sub`, `nbf` in the future, a signing key without
   `capabilityInvocation`, `jti` replay, and a caller whose token itself
   isn't authorized.
2. **Scope-escalation enforcement (1 of 22)** —
   `cs_05_04_01_02_invalidScopeEscalationRequest`: scope-based
   authorization isn't checked against what the caller was actually
   granted.
3. **The same category-1 Self-Issued ID Token validation gaps, now also
   exercised against the Storage/Offer APIs (8 of 22)** — `iss != sub`,
   `nbf`, `jti` replay, and `iat` in the future, each on both
   `POST /credentials` and `POST /offers`, now that both real
   `verify_bearer_token` calls run there. Every other way a token can be
   wrong (missing entirely, no `"Bearer "` prefix, expired, wrong
   audience, wrong signing key, unknown `kid`, an unresolvable subject) is
   now correctly rejected — 14 tests moved from failing to passing in this
   category alone (see below).
4. **No "trusted issuer" allow-list check (1 of 22)** —
   `cs_06_05_01_credentialMessage_untrustedIssuer`: `verify_bearer_token`
   accepts any `iss` whose `did:web` resolves and whose signature verifies;
   the DCP spec's separate "is this issuer one we trust" check isn't
   implemented. Newly visible now that the endpoint checks tokens at all.
5. **Message-content/business-logic validation, unrelated to the token
   wrapper (6 of 22)** — a schema/enum-invalid `CredentialMessage` body, an
   invalid `status` value, an unverifiable embedded credential proof, an
   unknown `holderPid`, an empty `CredentialOfferMessage.credentials`
   array, and offered credential ids that don't match a known catalog. All
   six present a genuinely valid Self-Issued ID Token; this bootstrap
   simply doesn't validate the message body itself yet.

**What changed from the previous (36-failure) snapshot:** 14 tests moved
from failing to passing, all of them in category 3's shape above -
`cs_06_05_01_credentialMessage_{noAuthHeader,missingBearerPrefix,tokenExpired,incorrectAudience,tokenSignedWithWrongKey,unknownKid,unresolvableSubject}`
and the same seven `cs_06_06_01_credentialOfferMessage_*` cases. Nothing
regressed: every test that passed before still passes. The full
theoretical win this task described (30 of 36) wasn't reached, honestly -
9 of the still-failing tests are gaps this change was never going to close
(iss==sub/nbf/jti/iat, one newly-visible trusted-issuer gap, and six
message-content checks), because `verify_bearer_token` itself is
deliberately partial and the fix was "wire up the existing function", not
"complete Self-Issued ID Token validation" (that remains out of this
bootstrap's scope, tracked the same way it already was for the
Presentation API).

What's genuinely proven working by the **32 passing tests**: everything the
previous 18-passing snapshot proved (real `did:web` hosting and
Credential-Service-endpoint discovery, the Presentation API's scope-based
round trip, its own auth rejections, and the Storage/Offer APIs' original
"should accept" happy-path cases including idempotent re-delivery) plus,
new in this snapshot, the Storage API and Credential Offer API each
genuinely rejecting a request with no `Authorization` header, a token
missing the `"Bearer "` prefix, an expired token, a token addressed to the
wrong audience, a token signed with the wrong key, a token whose `kid`
resolves to no verification method, and a token whose `sub` doesn't
resolve — real, TDD'd, and TCK-confirmed, not assumed (see
`tests/storage_offer_auth.rs` for the same assertions made directly against
the HTTP layer, without a TCK/Docker dependency).

Run it yourself: `cargo test -p identity-hub-http --test dcp_tck --
--ignored --nocapture` (needs Docker). See `tests/dcp_tck.rs`'s module doc
comment for the full methodology and the networking gotcha its
configuration works around. For the HTTP-layer-only, no-Docker-needed
coverage of just the new authorization behavior, see
`cargo test -p identity-hub-http --test storage_offer_auth`.

## Continuous integration

`.github/workflows/ci.yml` runs two jobs on every push/PR to `main`:

- **`quality`** — `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` (which does not
  run `dcp_tck.rs`'s `#[ignore]`d test). No Docker needed.
- **`dcp-tck`** — the DCP TCK conformance test described above, on
  `ubuntu-latest` (Docker preinstalled). Gating, not `allow-failure`: an
  exact-match assertion against a documented, categorized failure set lets
  this catch a real regression the same way an all-green job would, without
  overclaiming conformance this bootstrap doesn't have.

Unlike `ds-sql-dps-rs`'s pinned `dps-tck-runtime:1.3.0`, this job pins
`dcp-tck-runtime:latest` — the exact version documented as available in
this task's own brief, with no numbered release tag published at the time
of writing. This is a real, accepted risk: an upstream image update could
shift `EXPECTED_FAILURES` without a corresponding change here, in which
case this job would (correctly) start failing until a maintainer re-runs
the TCK, reconciles the new failure set, and updates both this file and
`tests/dcp_tck.rs` together.

## Layout

```
ds-identity-hub-rs/
  crates/
    identity-hub-core/     Domain types: DID/service-identity construction,
                            VPP/CIP wire-message shapes, in-memory
                            credential store, scope-to-type matcher, the
                            embedded STS. Built on ds-dcp-core-rs.
    identity-hub-http/     axum HTTP surface (Credential Service + Issuer
                            Service modes) and the dcp-tck conformance test.
      src/
        config.rs          Mode/Config: which role, bind address, own
                            did:web host, STS credentials, scope pattern.
        state.rs           AppState: identity, STS-party identity, store,
                            reqwest client (host.docker.internal override).
        auth.rs             Self-Issued ID Token validation.
        handlers.rs         All HTTP routes for both modes.
        main.rs             CLI: `identity-hub credential-service|issuer-service`.
      tests/
        dcp_tck.rs             Real dcp-tck-runtime conformance test.
        dcp.tck.properties     TCK config, bind-mounted into the container.
        storage_offer_auth.rs  Storage/Offer API authorization rejection
                                cases (real HTTP, no Docker/TCK needed).
```

## Building and testing

```bash
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                                  # fast, no Docker
cargo test -p identity-hub-http --test dcp_tck -- --ignored --nocapture   # needs Docker
```

## Running it

```bash
# Credential Service (VPP + CIP), default port 8080:
cargo run -p identity-hub-http --bin identity-hub -- credential-service \
  --did-host localhost:8080

# Minimal Issuer Service (CIP only), a different port:
cargo run -p identity-hub-http --bin identity-hub -- issuer-service \
  --bind 0.0.0.0:8081 --did-host localhost:8081
```

`--did-host` is the `host[:port]` this service is externally reachable at —
embedded in its own `did:web` identity and advertised service endpoint (see
`Config`'s doc comment in `crates/identity-hub-http/src/config.rs`).
`--sts-client-id`/`--sts-client-secret` default to `tck-client`/
`tck-secret`; `--insecure-http` (plain HTTP `did:web` resolution) defaults
to `true`, matching this bootstrap's local/test-only scope.
