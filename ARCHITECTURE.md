# Architecture

**Status:** Bootstrap, working end to end against the real TCK, now at full
measured conformance on the Credential Service scope this project targets
(see "DCP TCK conformance snapshot" below). Not yet integrated with a live
dataspace control plane, a real key-management/HSM backend, or a persistent
store.
**Date:** 2026-09-20 (nine changes today: real per-request authorization
added to the Storage API and Credential Offer API; then `verify_bearer_token`
gained `iss == sub`, `nbf`, `capabilityInvocation`, and `jti`-replay checks;
then the Presentation API gained scope-escalation enforcement against the
caller's own nested access-token grant; then, separately from TCK
conformance, the Storage API's credential store and the Credential Offer
API's accepted-offer record were rebuilt on a Contreforts-backed semantic
RDF graph — see "Provenance: Contreforts"; then `verify_bearer_token`
additionally rejects an `iat` (issued-at) claim in the future; then the
Storage API and Credential Offer API gained a trusted-issuer allow-list
check (`Config::trusted_issuer_dids`); then the Storage API and Credential
Offer API gained real message-content/business-logic validation (required
`CredentialMessage` fields, a `status` allow-list, a known-`holderPid`
allow-list, genuine embedded-credential proof verification, and offer
`credentials`-array/catalog checks — see `identity_hub_http::validation`);
then the Presentation API's nested `token` claim (the actual
Verifiable-Presentation access token a caller forwards) gained genuine
authentication — signature verification against its own resolved `did:web`
issuer plus a binding check back to the outer envelope's own caller — closing
the DCP TCK's own last two documented gaps and reaching full, real 54/54
conformance; then, later the same day, an independent security audit of the
now-54/54 codebase found three real, TCK-invisible gaps in the model behind
that same nested-token check — a missing grant read as "no restriction"
rather than "no access" (CRITICAL), an authenticity check with no
accompanying authority check (CRITICAL), and this hub's own STS minting
nested tokens its own verifier could never accept (MEDIUM) — all three
fixed the same day; then, a tenth change, the same audit's remaining
outbound-request findings were fixed too: every outbound HTTP request this
process makes (DID resolution, issued-credential delivery, offer-catalog
metadata fetches) is now confined to an explicit, deny-by-default host
allow-list derived from this service's own configuration
(`identity_hub_http::outbound::OutboundPolicy`), and the shared `reqwest`
client now carries a connect and total request timeout where before it had
neither; then, an eleventh change the same day, the same audit's remaining
HIGH finding on the Storage API was fixed: `Config::trusted_issuer_dids`
shipping empty meant "no restriction" rather than "trust nobody", so a bare
`cargo run -- credential-service` accepted a `CredentialMessage` from any
party that could host a `did:web` document, and separately,
`validation::verify_credential_proofs` skipped proof verification entirely
for any credential `format` not containing `"jwt"` (including an empty
string), storing it unverified — combined, an open-write Storage API plus a
format-bypass signing oracle, since `handlers::build_presentation` later
copies a stored credential's payload verbatim into a Verifiable
Presentation signed with this service's own key. Both halves are now fixed:
`auth::check_trusted_issuer` denies every issuer when the allow-list is
empty (the TCK's own `dataspacetck.did.issuer` opt-in is unaffected — it
was never empty), and `verify_credential_proofs` rejects any format it
cannot verify outright instead of skipping it, while keeping both of the
real TCK's own JWT format labels (`VC1_0_JWT`, `vc11-sl2021/jwt`, read out
of `/app/tck-runtime.jar`, not guessed) accepted; see "What's simplified or
stubbed" and "DCP TCK conformance snapshot" below — 36 -> 22 -> 12 -> 11 ->
9 -> 8 -> 2 -> **0** real TCK failures across the first eight changes, each
TDD'd and re-measured, not assumed, and 54/54 reconfirmed unchanged after
the ninth, tenth, and eleventh)

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

**2026-09-20, second update (same day):** `ds-dcp-core-rs` was bumped again,
to commit `78ef8d0e` (from `931c6719`), to close a gap the *first* bump left
half-finished: `DcpKeyPair::did_document` had started emitting a real
`capabilityInvocation` array, but the `DidDocument` struct a *resolver*
deserializes an HTTP-fetched document into had no field for it at all — the
array was write-only, produced by every DID document this crate (and
`ServiceIdentity::did_document`, which independently emits the same shape)
builds, but never read back by anything resolving one. This is exactly what
this repo's own `verify_bearer_token` needed to implement the
`capabilityInvocation` check below (`base.protocol.md`'s "Validating
Self-Issued ID Tokens", step 3): given a caller's resolved DID document,
check that the key named by the JWS `kid` header is actually listed under
that document's `capabilityInvocation`, not merely present in
`verificationMethod`. Backfilled with a real, TDD'd fix upstream (RED:
confirmed a compile error referencing an unknown field before adding it) —
see `ds-dcp-core-rs`'s own commit for the three new tests. `#[serde(default)]`
on the new field keeps it backward compatible with any DID document that
omits it (DID Core treats the array as optional).

## Provenance: Contreforts

**2026-09-20:** the Storage API's credential store and the Credential
Offer API's accepted-offer record were rebuilt on
[Contreforts](https://github.com/contreforts-ai) — the same
SHACL-declared, SPARQL-addressable semantic configuration graph
`ds-sql-dps-rs` already vendors and wires up (see that project's own
`ARCHITECTURE.md`, "Contreforts coupling"), following its precedent
closely rather than inventing a new pattern for this project.

**What was reused, and what was minted fresh — same split
`ds-sql-dps-rs` made, for the same reason:** Contreforts' public org
(github.com/contreforts-ai) is an ERP/business-data-sync and RAG toolkit —
there is no DCP, VC, or Dataspace Protocol vocabulary anywhere in its
public code, and `ContrefortsConnector` (`pull`/`push`/`get`/
`fetch_content`, plus a Turtle `declaration_ttl()` self-description
validated by SHACL) is a generic adapter trait designed for wrapping a
business SaaS system, not a dataspace participant. What genuinely
transfers is the *pattern*: a physically separate, SHACL-declared,
SPARQL-addressable graph, reachable through a uniform connector interface,
isolated from anything else the process holds. This project reuses only
that interface/declaration *mechanism* — it mints its own entity kinds
(`ds-identity-hub-rs:stored-credential-batch`,
`ds-identity-hub-rs:accepted-offer`, in `crates/identity-hub-contreforts`)
and its own namespace (`https://ds42.org/ontologies/ds-identity-hub-rs#`,
`crates/identity-hub-contreforts/src/declaration.ttl`) rather than forcing
itself into Contreforts' business vocabulary, exactly as
`ds-sql-dps-rs/contreforts-connector` does for its own `data-offer` kind.

**Vendoring:** `vendor/contreforts-core` is a git submodule pinned to
commit `95a4940` (`95a49404a60024a5b432b17f7a7c299a3dac9c3f`, `develop`
branch HEAD at the time of vendoring) — no tag is published upstream, the
same situation `ds-sql-dps-rs` documented for the same submodule, and
(not a coincidence) the exact same commit that project already pinned:
both projects vendor the identical upstream snapshot, which is what makes
the two connectors directly comparable. It is a workspace member (root
`Cargo.toml`'s `members`) alongside this project's own crates, inheriting
`version`/`edition` via `.workspace = true` — that crate's own manifest
expects a superproject to supply these, per its own comment.

**RDF schema: what maps to real Verifiable Credentials vocabulary, and
what stays project-specific, and why:**

- `crates/identity-hub-graph` decomposes each accepted `CredentialMessage`
  batch into a `ds:CredentialBatch` node carrying the correlation/status
  fields that are wire fields of the Credential Issuance Protocol itself
  (`issuerPid`, `holderPid`, `status`, `rejectionReason`) — there is no
  W3C Verifiable Credentials term for "the DCP-level status of a delivery
  attempt", so these stay in this project's own `ds:` namespace
  (`https://ds42.org/ontologies/ds-identity-hub-rs#`), the same way
  `ds-sql-dps-rs/config-graph` keeps its own `ds:filePath`/`ds:order`
  alongside real DCAT/ODRL terms.
- Each stored `CredentialContainer` becomes a real
  `vc:VerifiableCredential` node (`https://www.w3.org/2018/credentials#`)
  — a genuine, correct use of the real vocabulary term, since that is
  exactly what the container holds. `credentialType`/`format`/`payload`
  stay in `ds:`, deliberately: this store never decodes or verifies the
  credential payload itself (an opaque JWS string for `format: "jwt"`, a
  JSON-LD document for others), so there is no decomposed `vc:issuer`/
  `vc:credentialSubject` to extract without parsing (and likely
  half-verifying) claims a storage layer has no business interpreting — see
  "Message-content/business-logic validation..." above: proof verification
  happens one layer up, in `identity_hub_http::validation`, *before* a
  batch ever reaches this store, so the store itself stays exactly this
  unopinionated. `payload` is stored as the literal
  JSON serialization of the original `serde_json::Value`, so it round-trips
  losslessly regardless of shape.
- An accepted `CredentialOfferMessage` becomes a
  `ds:AcceptedCredentialOffer` node. Its `issuer` field, unlike a
  container's un-decomposed payload, *is* a plain, already-decomposed
  string identifying the offering party — a genuine fit for the real
  `vc:issuer` term, used here instead of a `ds:` predicate. Each offered
  `CredentialObject` reference becomes a small child node recording its
  catalog id (`ds:credentialId`) and, when present, its credential type
  (`ds:credentialType`).
- `ds:order` (an explicit integer on every batch/offer node and every
  child credential/offered-credential node) exists for the same reason
  `ds-sql-dps-rs/config-graph`'s own `ds:order` does: a `credentials`
  array is an *ordered* JSON array, but plain RDF triples for a
  multi-valued property carry no order at all — see
  `crates/identity-hub-graph/src/vocab.rs`'s doc comment.
- Every batch/credential/offer *attribute* is stored as a plain RDF
  literal, never a minted IRI, because (unlike `config-graph`'s
  operator-configured `dataset_id`) the credential-type strings flowing
  through this store can be attacker-influenced — see
  `crates/identity-hub-graph/src/store.rs`'s module doc comment for the
  full reasoning and how `credentials_of_types` avoids building a SPARQL
  query from untrusted input.

**Not a durability upgrade:** `CredentialGraph::open_in_memory()` opens an
Oxigraph store with no on-disk backing, exactly mirroring
`ds-sql-dps-rs/config-graph::ConfigGraph::open_in_memory`'s own doc
comment ("there is no on-disk persistence requirement this small a config
warrants yet"). See "No durable storage, but real semantic structure now"
above for the full accounting of what changed and what didn't.

**What's unverified**, same caveat `ds-sql-dps-rs` recorded for its own
connector: how a connector actually gets wired into a *running*
Contreforts product is handled by `contreforts-product`, which is
private. `crates/identity-hub-http/src/main.rs` calls
`CredentialGraphConnector::pull(STORED_CREDENTIAL_KIND, ...)` once at
startup (Credential Service mode only) to prove the round trip compiles
and returns real data over the exact graph the Storage API writes into,
but nothing here has been run against an actual Contreforts deployment.

**Tests:** `crates/identity-hub-graph/src/store.rs`'s unit tests exercise
the SPARQL round trip directly (store a batch, query it back by type,
confirm a `REJECTED`-status batch's credential is excluded — mirroring
the original `InMemoryCredentialStore` unit test's own scenario byte for
byte), plus batch/offer field round-tripping, ordering, and arbitrary JSON
payload shapes. `crates/identity-hub-contreforts/tests/declaration_validates.rs`
checks `declaration.ttl` against Contreforts' own real SHACL meta-shapes,
identically to `ds-sql-dps-rs/contreforts-connector`'s own test. The
pre-existing `identity-hub-core::store` unit test and every
`identity-hub-http` HTTP-layer test
(`storage_offer_auth.rs`/`si_token_validation.rs`/
`presentation_scope_enforcement.rs`) and the real DCP TCK conformance test
(`dcp_tck.rs`) all pass unmodified against the new graph-backed store —
see "DCP TCK conformance snapshot" below, which is unchanged by this work
(same 43/54, same 11 failing test names).

## What's implemented (real, not stubbed)

- **`did:web` hosting**, for both a process's own Credential-Service/
  Issuer-Service identity and a second, synthetic identity used only by
  the embedded STS (see "The STS-party identity" below) — real ES256
  P-256 keys, real DID documents with correct verification-relationship
  arrays, genuinely resolvable over HTTP (`GET /<segment>/did.json`).
- **The Storage API** (`POST /credentials` on a Credential Service) — a
  real accept-and-store path: parses a `CredentialMessage`, stores every
  credential container as real RDF triples in `InMemoryCredentialStore`
  (in-memory, process-lifetime, now Contreforts-backed as of 2026-09-20 -
  see "Provenance: Contreforts"). **Requires a valid Self-Issued ID Token**
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
  same default regex the real TCK itself uses), **narrows that down to
  what the caller's own nested access token actually grants, with the
  nested token itself now genuinely authenticated** (scope-narrowing added
  2026-09-20; signature verification and confused-deputy binding added
  later the same day — see "What's simplified or stubbed" for the full
  history of both changes), looks up matching stored credentials, and
  returns a real, correctly-audienced, ES256-signed Verifiable Presentation
  wrapping them. Verified genuinely working against the real TCK — see
  "DCP TCK conformance snapshot".
- **The Credential Offer API** (`POST /offers` on a Credential Service) —
  accepts a `CredentialOfferMessage` and records it as a real, queryable
  RDF record (`identity_hub_graph::CredentialGraph::add_offer`, as of
  2026-09-20 - see "Provenance: Contreforts"); does not yet trigger a
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
  API, added 2026-09-20.** `storage_write` and `credential_offer`
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
  previously-failing tests moved to passing in this change — see "DCP TCK
  conformance snapshot".
- **Self-Issued ID Token validation, second reinforcement pass, also
  2026-09-20.** `verify_bearer_token` (`identity-hub-http/src/auth.rs`) now
  additionally checks, on top of the signature/audience/expiry it already
  verified: **`iss == sub` equality** (a Self-Issued ID Token must be about
  its own issuer); **`nbf`** (not-before), with a 30-second clock-skew
  leeway, rejecting a token that isn't valid yet when `nbf` is present;
  **the `capabilityInvocation` verification-relationship restriction** on
  the signing key — the resolved caller's `kid` must actually be listed
  under that DID document's own `capabilityInvocation` array, not merely
  present in `verificationMethod` (made implementable by the `ds-dcp-core-rs`
  bump described under "Provenance" above, which is the only reason this
  check wasn't already here); and **`jti` replay protection**, an in-memory
  `HashSet<String>` (`AppState::seen_jti`) scoped to this process's
  lifetime — sufficient for this bootstrap, not a claim of durable replay
  protection across restarts. TDD'd: `tests/si_token_validation.rs` asserts
  each of the four gaps red-then-green (a token with `sub != iss`, one with
  `nbf` an hour in the future, one signed with a key resolvable but absent
  from `capabilityInvocation`, and a jti reused across two calls — plus
  regression guards that a genuinely valid, capability-listed key and two
  calls with distinct jtis both still succeed), against the real HTTP layer
  with no TCK/Docker dependency, the same pattern `storage_offer_auth.rs`
  established. Real, measured effect: 10 more of the 22 tests failing after
  the first pass now pass — see "DCP TCK conformance snapshot".
- **Scope-escalation enforcement against the caller's own granted scope,
  added 2026-09-20 (third change today).** `presentation_query`
  (`identity-hub-http/src/handlers.rs`) used to look up stored credentials
  purely by the *requested* `scope` — any caller with a valid outer
  Self-Issued ID Token could read any credential type in the store just by
  naming it, regardless of what it was actually granted to read. It now
  also decodes the caller's nested `token` claim (the Verifiable-Presentation
  access token, per `base.protocol.md`) purely to read its own `scope`
  claim (`identity_hub_core::scope::split_scope_string` +
  `ScopeMatcher::credential_types` — the exact same matcher the requested
  `scope` already goes through) and intersects the two before looking
  anything up: a caller may request more than it was granted, but only
  ever receives what it was actually granted. At the time of this change, a
  missing *or unparseable* nested token both fell back to this bootstrap's
  pre-existing, unrestricted behavior — the unparseable case was a real,
  separate gap this change didn't fix (see "Nested-access-token
  authentication (confused-deputy fix)" below, which closed it later the
  same day: only a genuinely *absent* nested token keeps that permissive
  default now). TDD'd:
  `tests/presentation_scope_enforcement.rs` asserts the escalation case
  red-then-green (a token granted only `MembershipCredential` requesting
  both `MembershipCredential` and `SensitiveDataCredential` back must
  receive only the former, on an otherwise-successful response — the real
  TCK's own `verifyCredentials` asserts `2xx`, not a rejection), plus
  regression guards that a broad grant still returns everything requested
  and that a caller with no nested token at all keeps working exactly as
  before. Real, measured effect: closed exactly
  `cs_05_04_01_02_invalidScopeEscalationRequest`, the last test that gap's
  own name suggested but that the other two checks below don't touch (12
  -> 11) — see "DCP TCK conformance snapshot".
- **Nested-access-token authentication (confused-deputy fix), added
  2026-09-20 (eighth and final change today).** `verify_bearer_token` only
  ever validated the *outer* Self-Issued ID Token envelope; the nested
  `token` claim it carries (the actual Verifiable-Presentation access
  token, per `base.protocol.md`) had, since the third change today, its own
  `scope` claim read and enforced (see the scope-escalation bullet above)
  but its **signature was never verified**, and nothing bound it back to
  the outer envelope's own caller. Reading the real TCK's own source
  (`PresentationFlowSection4Test`/`PresentationFlowSection5Test` in
  `eclipse-dataspacetck/dcp-tck`) confirmed this was **one** gap with two
  remaining severities, both now closed by a new
  `auth::verify_nested_access_token` (`identity-hub-http/src/auth.rs`),
  called from `handlers::granted_credential_types`: it resolves the nested
  token's own `iss` DID document, verifies its JWS signature against the
  key named by its `kid` (the exact same `resolve_did`/`find_verifying_key`/
  `verify_jws_signature` primitives `verify_bearer_token` already uses for
  the outer envelope), checks it has not expired, and — the confused-deputy
  fix itself — checks its `aud` claim equals the outer envelope's own
  `iss`/`sub` (confirmed by decompiling `SecureTokenServerImpl.obtainReadToken`/
  `requestRemoteAccessToken`: the real TCK always mints a nested access
  token bound, via `aud`, to whichever party will actually present it).
  Any failure — undecodable, unverifiable, expired, or wrongly bound — now
  rejects the whole request outright (`401`), replacing the old
  best-effort scope read that silently fell back to unrestricted access on
  a decode failure. This closed both `cs_05_04_invalidTokenNotAuthorized`
  (a nested token that isn't even a real JWS — the literal `"faketoken"` —
  inside an otherwise-valid outer envelope) and
  `cs_04_03_03_idTokenInvalidIssuerSub` (a nested token genuinely valid and
  correctly signed, but minted for/bound to the *verifier*, forwarded by a
  different party — `thirdPartyDid` — presenting a perfectly valid outer
  envelope of its own; a scope-only check can't catch this, since the
  forwarded token's `scope` claim is itself completely genuine). TDD'd:
  `tests/nested_access_token_authentication.rs` asserts both cases
  red-then-green, plus regression guards that a nested token correctly
  bound to its own presenter still succeeds and an expired-but-otherwise-valid
  nested token is also rejected. At the time of this change, a bare outer
  envelope with no nested token at all kept this bootstrap's pre-existing,
  deliberately permissive default — **that default was itself a critical
  read-authorization bypass, closed the same day by an independent security
  audit; see the "Deny-by-default read authorization" bullet below, which
  supersedes this paragraph's own regression guard.** Fixing this also
  surfaced (and fixed) a latent gap in this crate's own *test* fixtures, not
  production code: `presentation_scope_enforcement.rs`'s nested-token helper
  had been minting tokens bound (`aud`) to the Credential Service's own DID
  rather than to the caller presenting them — harmless before this change
  (nothing checked `aud` on the nested token at all) but a false regression
  the moment the binding check went in; fixed by binding it to the caller's
  own DID, matching what the real TCK actually does. Real, measured effect
  on TCK conformance: closed exactly `cs_04_03_03_idTokenInvalidIssuerSub`
  and `cs_05_04_invalidTokenNotAuthorized` (2 -> **0**), confirmed against
  the real TCK, reproduced identically three times (54/54 `SUCCESSFUL` every
  run), with zero regressions on the other 52 previously-passing tests —
  see "DCP TCK conformance snapshot".
- **Deny-by-default read authorization plus issuer authority, added
  2026-09-20 (ninth change, later the same day, closing an independent
  security audit's Findings 1, 2, and 9).** The bullet above closed the DCP
  TCK's own two nested-token gaps, but a separate, same-day independent
  security audit found the model behind it still had two CRITICAL holes and
  one MEDIUM one, none of them TCK-visible (no TCK case exercises them):
  - **Finding 1 (CRITICAL) — a missing grant was more powerful than a real
    one.** `handlers::granted_credential_types` returned `Ok(None)` for a
    bare outer envelope with no nested `token` claim at all, and
    `presentation_query` read `None` as "no restriction", handing back
    every stored credential of the requested type. This was the
    "deliberately permissive default" the bullet above (and this file's
    earlier revisions) documented as intentional — it was not; it was the
    bypass. Fixed by dropping the `Option` entirely:
    `granted_credential_types` now returns `Result<Vec<String>, AuthError>`,
    empty when there is no grant, and `presentation_query` always
    intersects the requested types against it rather than special-casing
    "no grant" as "no restriction". A missing grant now returns a normal
    `200` carrying a Verifiable Presentation with an empty
    `verifiableCredential` array — disclosing nothing, not refusing the
    request outright — matching the model the pre-existing
    scope-escalation path already used.
  - **Finding 2 (CRITICAL) — authenticity was checked, authority never
    was.** `auth::verify_nested_access_token` proved a nested token was
    genuinely signed by whoever its own `iss` claimed to be, but never asked
    whether that `iss` had any standing to grant reads of *this* service's
    credentials. An attacker hosting their own well-formed `did:web`
    document could mint `{iss: sub: aud: <own did>, scope: <anything>}`,
    sign it with their own key, and be handed back whatever they typed.
    Fixed by a new `authoritative_issuer` parameter: the nested token's
    `iss` must equal it or the request is rejected
    (`AuthError::NestedTokenIssuerNotAuthoritative`, mapped to `401` like
    every other `AuthError`), checked *before* `resolve_did` so an
    attacker-named DID is never fetched at all for a token that could never
    have been authoritative. The call site
    (`handlers::granted_credential_types`) passes `state.sts_party.own_did()`
    — the one identity this process's own STS ever signs access tokens
    with, and in this bootstrap the only party with any standing to grant
    reads from its own store. The pre-existing `aud`-binding check against
    the outer envelope's own `sub` stays, unchanged and un-subsumed: it
    catches a token our own STS genuinely minted (so the issuer check
    passes) but bound to the verifier and forwarded by a third party —
    exactly `cs_04_03_03_idTokenInvalidIssuerSub` above, which the issuer
    check alone would not catch.
  - **Finding 9 (MEDIUM) — this hub's own STS minted tokens its own
    verifier always rejected.** `sts::issue_token` bound the nested access
    token's `aud` to `req.audience` unconditionally — correct for the DCP
    hand-off the TCK exercises (the audience is the verifier that will
    receive and re-present the nested grant), but wrong for the direct case
    (a caller asking for a token to present straight back to this
    Credential Service): there, the outer envelope's own `sub` is always
    `signer.own_did()` (the STS's own party), so the nested `aud`
    (`req.audience`, forced by `verify_bearer_token` to be this service's
    own DID) could never match it. The one legitimate, direct-use path was
    a guaranteed `401` — which is exactly why Finding 1's bypass was
    load-bearing rather than theoretical: presenting no grant at all was
    the only way to get a presentation back. Fixed by deriving the nested
    `aud` from whether `req.audience` equals the service's own DID
    (`StsTokenRequest::own_service_did`, newly threaded through from
    `handlers::sts_token`): if so, the presenter is the STS party itself
    (`aud = signer.own_did()`); otherwise, unchanged
    (`aud = req.audience`). The outer envelope's own `aud` stays
    `req.audience` in both cases.

  TDD'd: `tests/nested_token_authorization.rs` (new) asserts all three
  findings red-then-green against the real HTTP layer — a bare envelope
  discloses nothing, an untrusted self-signed nested token is rejected, and
  a token genuinely obtained from this hub's own `/sts/token` is accepted
  end-to-end by its own `/presentations/query` and correctly scoped to what
  it was granted — plus inverted regression assertions in
  `nested_access_token_authentication.rs` and
  `presentation_scope_enforcement.rs` (both previously asserted the
  bypass itself as a "keeps working" guard) and three new/updated unit
  tests in `identity-hub-core/src/sts.rs` covering both the direct and
  hand-off `aud`-derivation branches. TCK-safety was confirmed, not
  assumed, by decompiling `dcp-tck-runtime`:
  `SecureTokenServerImpl.obtainReadToken` sources every nested access token
  from this hub's own `/sts/token`, so every TCK nested token's `iss` is
  `sts_party` (the issuer check cannot regress it), and no TCK presentation
  test presents a bare envelope expecting a successful, non-empty
  disclosure (deny-by-default cannot regress it either). Real, measured
  effect on TCK conformance: **54/54, unchanged**, confirmed against the
  real TCK, reproduced identically three times — see "DCP TCK conformance
  snapshot"; this fix closed three audit findings the TCK itself never
  exercised, not TCK regressions.
  Explicitly out of scope for this change (a separate audit finding, not
  widened into this one): the STS still authenticates every caller with one
  hardcoded `client_id`/`client_secret` pair
  (`Config::sts_client_id`/`sts_client_secret`), so anyone holding those
  credentials can still mint a grant for any scope.
- **Outbound request confinement plus timeouts, added 2026-09-20 (tenth
  change, closing the same independent security audit's Findings 4, 5, and
  6).** Every outbound HTTP request this process makes is a `did:web`
  resolution or a delivery whose *destination* is, at least in part, chosen
  by the party being served rather than this service's own configuration:
  `auth::verify_bearer_token` must resolve a caller's own `iss` before it
  can check anything about it; `handlers::try_deliver_issued_credential`
  reads its delivery destination straight out of the requester's own DID
  document; `validation::verify_credential_proofs` resolves a credential's
  own embedded `iss`; `validation::validate_offer_credentials` resolves an
  offering issuer's DID and then its catalog endpoint. Before this change
  none of the five were checked against anything at all, so any caller
  could turn this process into an open proxy against a host of its choosing
  (Findings 4 and 5, both HIGH), and none of them had a timeout, so a
  destination that accepted a connection and then said nothing pinned the
  handling task open indefinitely (Finding 6, MEDIUM).
  - **The mechanism.** A new `identity_hub_http::outbound::OutboundPolicy`
    (`crates/identity-hub-http/src/outbound.rs`) is a deny-by-default host
    allow-list: `check_url` parses a destination, rejects any scheme but
    `http`/`https`, and requires a **case-insensitive exact match on the
    URL's host component — the port is ignored, and there is no wildcard,
    suffix, or CIDR matching**; `check_did` runs the same check against
    whatever URL `dcp_core::did_web_to_url` says a `did:web` DID resolves
    to, without an extra parse path that could disagree with it.
    Host-granularity (not host:port) is deliberate, not a looser fallback:
    this crate's own test suite spawns stand-in DID servers on ephemeral
    loopback ports, and the real TCK's own published port varies between
    runs — host:port matching would reject those legitimate destinations
    right along with a real one.
  - **Where the allow-list comes from — a single source of truth.**
    `AppState::new` (`src/state.rs`) builds the one `OutboundPolicy` this
    process ever consults, from exactly: the host part of `config.did_host`
    (this service must resolve, and be resolved as, itself); `127.0.0.1`
    (the exact host `AppState::new` itself hosts `sts_party` at — see "The
    STS-party identity" above — so this process can resolve its own
    STS-party DID); `host.docker.internal`, pulled from the very same
    `HOST_DOCKER_INTERNAL` constant the pre-existing static `reqwest` DNS
    override already uses, so the two can never drift apart (see "A real
    networking gotcha" below); and any operator-supplied extras from the
    new `Config::allowed_outbound_hosts` (empty by default), wired to a new
    repeatable `--allow-resolve-host` CLI flag.
  - **Every enforcement point, checked before the network call.** All five
    call sites above now take a `&OutboundPolicy` parameter and check it
    immediately before their own `resolve_did`/`GET`/`POST` — mirroring
    where Finding 2's authoritative-issuer check already sat relative to
    its own `resolve_did`. `try_deliver_issued_credential` checks *twice*:
    the holder's own DID before resolving it, and the resolved
    `CredentialService` `serviceEndpoint` URL before the delivery `POST`.
    `verify_bearer_token` and `verify_nested_access_token` map a rejection
    through a new `AuthError::OutboundDestinationNotAllowed`, handled by
    the same generic `auth_error_response` (`401`) every other `AuthError`
    already uses — no new response path. `verify_credential_proofs` and
    `validate_offer_credentials` map theirs to their existing
    `ValidationError::UnverifiableProof`/`CatalogUnavailable` variants,
    likewise with no new response path.
  - **Timeouts.** `AppState::new`'s `reqwest::Client::builder()` now sets
    `.connect_timeout(2s)` and `.timeout(5s total)` (named consts in
    `src/state.rs`) — the one shared client every outbound call in this
    process uses, so this covers DID resolution, the offer-catalog metadata
    fetch, and credential delivery all at once. 5 seconds is far above
    anything the real TCK actually needs (all of its traffic is loopback,
    sub-millisecond); if a legitimate destination ever needs more, the fix
    is to raise this value, not to remove the timeout.
  - **The residual limitation, stated plainly.** `127.0.0.1` stays
    allow-listed because `AppState::new` currently hosts the synthetic
    `sts_party` identity there — so, in this bootstrap, an attacker-chosen
    `iss` pointing at some *other* loopback service on the same host is
    still technically reachable if one happens to be listening. This is not
    fixed by this change, and isn't being claimed as fixed: a real
    deployment gives `sts_party` a routable, non-loopback `did_host` (see
    "The STS-party identity" above) and drops `127.0.0.1` from the
    allow-list entirely — this bootstrap's own STS-party placement is the
    thing keeping it there, exactly the same shape of trade-off "A real
    networking gotcha" above documents for `host.docker.internal`.
  - **TCK-safety was verified by running the real TCK repeatedly while
    building this, not just once at the end** — the actual regression risk
    this change carries is disagreeing with the TCK's own real resolution
    pattern (`host.docker.internal` pinned to `127.0.0.1` by the
    pre-existing DNS override) or with this crate's own test suite's
    ephemeral-port DID servers, and both are exactly why host-only (not
    host:port) matching was load-bearing rather than a simplification.

  TDD'd: `tests/outbound_request_confinement.rs` (new) asserts all three
  findings red-then-green against the real HTTP layer — an unauthenticated
  caller's own attacker-chosen `iss` never reaches a probe listener on an
  unconfigured host even though the request is still correctly rejected; a
  requester's own DID document naming an unconfigured `CredentialService`
  endpoint never receives the delivery POST, and the request still reaches
  `REJECTED`; and a black hole on an *allow-listed* host (so the host check
  alone can't pass this one vacuously) is given up on well within the
  test's 20-second budget. `cargo test --workspace` stayed fully green
  throughout, including every test file that spawns a stand-in DID server
  on an ephemeral loopback port
  (`nested_token_authorization`/`nested_access_token_authentication`/
  `si_token_validation`/`storage_offer_auth`/`trusted_issuer_allowlist`/
  `presentation_scope_enforcement`/`message_content_validation`). Real,
  measured effect on TCK conformance: **54/54, unchanged**, confirmed
  against the real TCK, reproduced identically three times — see "DCP TCK
  conformance snapshot"; like the ninth change, this fix closed real,
  TCK-invisible gaps, not TCK regressions.
- **Storage API deny-by-default posture plus a closed credential-format
  set, added 2026-09-20 (eleventh change, closing the same independent
  security audit's remaining HIGH finding).** Two independent halves of one
  signing-oracle gap, both on the Storage API (`POST /credentials`), each
  TCK-invisible because the TCK's own SUT configuration never exercised the
  unconfigured/unsupported-format case in the first place.
  - **Half (a): the shipped default trusted nobody by mistake in the other
    direction.** `auth::check_trusted_issuer` (see "Trusted-issuer
    allow-list check" above) read an *empty* `Config::trusted_issuer_dids`
    as "no restriction is configured" rather than "no issuer is trusted" —
    so a bare `cargo run -- credential-service`, with no
    `--trusted-issuer-did` at all, accepted a `CredentialMessage` from any
    party that could host a `did:web` document and self-sign a genuine
    Self-Issued ID Token: no configuration, no relationship, no prior
    request. Fixed by collapsing the whole function to "`iss` must be an
    element of `trusted_issuer_dids`", with an empty list trivially
    matching nothing (`AuthError::NoTrustedIssuerConfigured`, mapped to the
    same `401` every `AuthError` already gets). The opt-in mechanism this
    replaces a permissive default with is **unchanged**:
    `Config::trusted_issuer_dids` / `Config::with_trusted_issuer_dids` /
    the repeatable `--trusted-issuer-did` CLI flag — the real TCK's own SUT
    configuration (`dataspacetck.did.issuer`, wired in
    `tests/dcp.tck.properties`/`tests/dcp_tck.rs`) was never empty, so this
    fix tightens only the *unconfigured* default, not the TCK's own
    correctly-scoped configuration. A new `tracing::warn!` at startup
    (`main.rs`) tells an operator who forgot the flag entirely that every
    Storage/Offer write will be rejected, without refusing to boot.
    `Config::known_holder_pids` is explicitly **out of scope** for this fix
    and keeps its own permissive empty-means-unrestricted default (see
    `validation::check_known_holder_pid`'s doc comment) — this bootstrap
    still has no Credential-Request-tracking state to populate it from (see
    "A holder-driven response to a Credential Offer" below), and widening
    this fix to cover it too would have been a different, undiscussed
    change, not a surgical one.
  - **Half (b): a `format` this service cannot verify was stored anyway.**
    `validation::verify_credential_proofs` verified a container's own
    embedded proof only when its `format` contained the substring `"jwt"`;
    every other value (`"ldp_vc"`, an empty string, anything) skipped the
    check entirely and was stored unverified. Combined with
    `handlers::build_presentation`, which copies a stored credential's
    `payload` verbatim into a Verifiable Presentation signed with *this
    service's own key*, that turned the Storage API into a signing oracle
    for arbitrary attacker-supplied JSON — no different in effect from
    Finding 2's missing-authority gap fixed earlier the same day, just on
    the write path instead of the read path. Fixed by replacing the skip
    with a closed set: a `format` (trimmed, lowercased) containing `"jwt"`
    takes the existing verification path unchanged; anything else is
    rejected outright with a new `ValidationError::UnsupportedCredentialFormat`
    (`400`, via the existing `validation_error_response` — a message-content
    defect, not an auth one), carrying the format as received, *before* its
    `payload` is inspected at all. The whole `CredentialMessage` is still
    rejected on the first failing container (no partial acceptance,
    unchanged from before). The substring match is deliberate, not a
    loosening: the real `eclipsedataspacetck/dcp-tck-runtime:latest`'s own
    `CredentialFormat` enum (read out of `/app/tck-runtime.jar`, not
    guessed) has exactly `VC1_0_JWT` (`vc11-sl2021/jwt`) and `VC2_0_JOSE`
    (`vc20-bssl/jwt`), and only `VC1_0_JWT` is used by the two
    Credential-Service test packages this bootstrap runs — so both
    `"VC1_0_JWT"` and `"vc11-sl2021/jwt"` stay on the accepted path
    alongside this bootstrap's own Issuer Service's `"jwt"` label
    (`handlers::try_deliver_issued_credential`); narrowing to the literal
    string `"jwt"` would have silently regressed the TCK.
    `identity_hub_graph`'s store itself stays format-agnostic (its own
    `"ldp_vc"` unit test is untouched) — this is an HTTP-layer intake rule
    only, and nothing can reach the store through the Storage API with an
    unverifiable format any more.

  TDD'd: `tests/storage_write_default_posture.rs` (new) asserts both halves
  red-then-green, independently of each other (the format tests configure
  an explicit trusted issuer, so they stay red for the format bug alone,
  not carried by fix (a)) — including one test that spawns the **real
  `identity-hub` binary** with no flags beyond `--bind`, so the shipped CLI
  default is pinned, not a library-level stand-in for it — plus two
  compatibility guards (an explicitly configured trusted issuer is still
  accepted; both of the TCK's own JWT format labels are still accepted).
  Fallout in three existing fixture files that booted `Config::for_test`
  with an empty trusted-issuer allow-list and expected `200` on
  `/credentials`/`/offers` (`storage_offer_auth.rs`, `si_token_validation.rs`,
  `message_content_validation.rs`) was updated to opt in explicitly,
  spawning the caller identity first and booting the service trusting that
  identity's own DID — `trusted_issuer_allowlist.rs`/`dcp_tck.rs`/
  `outbound_request_confinement.rs`/the nested-token and
  presentation-scope files needed no change (verified, not assumed — see
  each file's own module doc comment for why). `cargo test --workspace`
  stayed fully green throughout. Real, measured effect on TCK conformance:
  **54/54, unchanged**, confirmed against the real TCK, reproduced
  identically three times — see "DCP TCK conformance snapshot"; like the
  ninth and tenth changes, this fix closed real, TCK-invisible gaps, not
  TCK regressions.
- **Trusted-issuer allow-list check, added 2026-09-20 (sixth change
  today).** `verify_bearer_token` accepting any `iss` whose `did:web`
  document resolves and whose key verifies the token's signature (and is
  capability-listed) is signature verification, not trust — the DCP spec's
  own separate "Verify Trust" step needs a check that the issuing party is
  actually a *known* issuer, which was missing until now. Investigated by
  decompiling the real TCK's own `CredentialIssuanceTest`/
  `AbstractCredentialIssuanceTest`/`BaseAssembly`
  (`eclipsedataspacetck/dcp-tck-runtime:latest`), not guessed from the test
  name: `cs_06_05_01_credentialMessage_untrustedIssuer` signs a genuinely
  valid outer envelope (`iss == sub == thirdPartyDid`, a real, resolvable
  `did:web` with its own real `capabilityInvocation`) and still expects a
  `4xx`, purely because `thirdPartyDid` isn't the DID the TCK's own SUT
  configuration convention already names as "the issuer"
  (`dataspacetck.did.issuer`, `BaseAssembly::parseDid`/`getIssuerDid`). Fixed
  by adding `Config::trusted_issuer_dids` (an explicit allow-list of caller
  DIDs; empty means no restriction, this bootstrap's permissive default —
  **superseded 2026-09-20, eleventh change: an empty allow-list now denies
  every issuer instead, see that entry below; the opt-in mechanism
  described in the rest of this bullet is unchanged**) and
  a new `auth::check_trusted_issuer`, called by `storage_write` and
  `credential_offer` right after `verify_bearer_token`'s envelope checks
  pass — deliberately *not* folded into `verify_bearer_token` itself, since
  that function is shared by the Presentation API and the Issuer Service's
  Credential Request API too, whose legitimate callers are holders/verifiers
  rather than "the issuer", so one allow-list can't apply to all of them.
  `tests/dcp.tck.properties` now pins `dataspacetck.did.issuer` explicitly
  (matching the value `BaseAssembly` would derive anyway, for a documented,
  predictable pin rather than an implicit default) and `tests/dcp_tck.rs`
  wires the identical value into `Config::trusted_issuer_dids`. TDD'd:
  `tests/trusted_issuer_allowlist.rs` asserts an untrusted-but-otherwise-
  valid caller is rejected and a trusted one is accepted, for both
  endpoints, red-then-green, against the real HTTP layer with no TCK/Docker
  dependency. Real, measured effect: closed exactly
  `cs_06_05_01_credentialMessage_untrustedIssuer` (9 -> 8), confirmed
  against the real TCK, reproduced identically twice, with zero regressions
  on the other 45 tests.
- **`iat` (issued-at) in the future check, added 2026-09-20 (fourth change
  today).** `verify_bearer_token` (`identity-hub-http/src/auth.rs`) now
  also rejects a token whose `iat` claim is in the future, using the same
  clock-skew leeway (`NBF_LEEWAY_SECS`) the existing `nbf` check already
  used — a real, distinct gap from the four checks the second change added
  (which were `iss == sub`, `nbf`, `capabilityInvocation`, and `jti` replay
  specifically, per that change's own scope; `iat` was never one of them).
  The TCK probes `iat` only on the Storage/Offer APIs, not the Presentation
  API, so this was visible only there. TDD'd:
  `tests/si_token_validation.rs` asserts the rejection red-then-green
  (`storage_write_rejects_token_with_iat_in_the_future`), plus a regression
  guard that an `iat` a few seconds ahead of this process's own clock (well
  within the leeway) is still accepted
  (`storage_write_accepts_a_token_with_iat_within_clock_skew_leeway`).
  Real, measured effect on TCK conformance: closed exactly
  `cs_06_05_01_credentialMessage_iatInFuture` and
  `cs_06_06_01_credentialOfferMessage_iatInFuture` (11 -> 9), confirmed
  against the real TCK, reproduced identically twice, with zero regressions
  on the other 45 tests (the 43 previously passing plus these 2).
- **Message-content/business-logic validation on the Storage API and
  Credential Offer API, added 2026-09-20 (seventh change today).** Before
  this, `storage_write`/`credential_offer` validated only the wrapping
  Self-Issued ID Token envelope and issuer — the message *body* itself was
  accepted unconditionally once those passed: any `status` string, any
  `holderPid`, an unverified embedded credential proof, an empty or
  catalog-mismatched offer. Investigated by decompiling the real TCK's own
  `CredentialIssuanceTest`/`CredentialOfferTest` and their shared
  `org.eclipse.dataspacetck.dcp.system.cs` model classes
  (`eclipsedataspacetck/dcp-tck-runtime:latest`), not guessed from test
  names alone — see `identity_hub_http::validation`'s own module doc
  comment for the full per-check reasoning. Four independent fixes, all in
  the new `identity-hub-http/src/validation.rs`:
  - `CredentialMessage`'s `@context`/`type`/`issuerPid`/`holderPid`/`status`
    are now all required fields (`identity-hub-core/src/messages.rs`: no
    permissive `#[serde(default)]`, `holder_pid` no longer
    `Option<String>`) — a message missing any of them now fails to
    deserialize, which axum's `Json` extractor already turns into a `400`;
    no separate validation code needed for this specific gap. Closes
    `cs_06_05_01_credentialMessage_invalidBody`.
  - `validation::validate_status` rejects a `status` outside `{"ISSUED",
    "REJECTED"}` — the same two values the real TCK's own, decompiled
    `org.eclipse.dataspacetck.dcp.system.cs.CredentialMessage.validate()`
    checks against. Closes `cs_06_05_01_credentialMessage_invalidStatus`.
  - `validation::check_known_holder_pid`, checked against the new
    `Config::known_holder_pids` (empty means no restriction, this
    bootstrap's permissive default — deliberately unchanged by the
    eleventh change below, which is scoped to `trusted_issuer_dids` and
    credential format only; see that entry's note on `known_holder_pids`),
    rejects a `holderPid` this service wasn't configured to expect. Wired in
    `tests/dcp.tck.properties`/`tests/dcp_tck.rs` to the TCK's own fixed
    `dataspacetck.credentials.correlation.id` (`BaseAssembly::getHolderPid`,
    decompiled to confirm). This bootstrap's Credential Service mode
    doesn't yet track outstanding Credential Requests of its own (see "A
    holder-driven response to a Credential Offer" below) — a real
    deployment would populate this allow-list from that state as requests
    come in, not from a fixed config value. Closes
    `cs_06_05_credentialMessage_unknownHolderPid`.
  - `validation::verify_credential_proofs` genuinely verifies every
    JWT-format embedded credential's own JWS proof: resolves the
    credential's own `iss` claim's `did:web` document, finds the
    verification method named by the JWS `kid` header, and checks the
    signature — reusing `crate::auth::verify_bearer_token`'s own
    primitives (`dcp_core::{resolve_did, find_verifying_key,
    verify_jws_signature}`), not a reimplementation. A non-JWT-format
    container is left opaque and unverified, matching
    `identity_hub_graph::store`'s own stance on non-JWT payloads. Closes
    `cs_06_05_02_credentialMessage_unverifiableProof`. **Superseded
    2026-09-20, eleventh change: leaving a non-JWT-format container
    "opaque and unverified" turned out to mean *stored and later
    resigned* by `handlers::build_presentation` — a signing oracle, not a
    scope boundary. See that entry below; a format this service cannot
    verify is now rejected outright instead of skipped.**
  - `validation::validate_offer_credentials` rejects an empty
    `CredentialOfferMessage.credentials` array outright, and — for a
    *sparse* (id-only, no `credentialType`) entry specifically — resolves
    the offering issuer's own `IssuerService` DID-document entry and
    fetches its real Issuer Metadata API (`GET <endpoint>/metadata`,
    `identity_hub_core::messages::IssuerMetadata` now also `Deserialize`)
    to check the id against that issuer's own catalog; a *full* entry
    (`credentialType` present) is self-describing and needs no catalog
    lookup at all — confirmed, not guessed, by the TCK's own
    always-passing default offer using an unregistered random id but
    always carrying a `credentialType`, while only the id-only "sparse"
    variants are checked against a catalog (one with real, known ids,
    expecting `2xx`; one with random ids, expecting `4xx`). Closes
    `cs_06_06_01_credentialOfferMessage_emptyCredentials` and
    `cs_06_06_01_credentialOfferMessage_sparse_randomIds_expect400`.

  TDD'd: `tests/message_content_validation.rs` asserts all six red-then-green
  (plus regression guards for each: recognized statuses, a known
  `holderPid`, a genuinely verifiable proof, a full offer entry needing no
  catalog, and a sparse offer whose ids the catalog does recognize) against
  the real HTTP layer, no TCK/Docker dependency. Real, measured effect:
  closed exactly the six tests named above (8 -> 2), confirmed against the
  real TCK, reproduced identically twice, with zero regressions on the
  other 46 previously-passing tests. (Scope-based authorization against a
  caller's own granted scope was part of "No nested-access-token
  authentication" above until an earlier change today closed it — see
  "Scope-escalation enforcement" above; that gap is unrelated to, and
  unchanged by, this one.)
- **No revocation status checking** (`StatusList2021`/
  `BitstringStatusList`) on presented or stored credentials.
- **No durable storage, but real semantic structure now (2026-09-20).**
  `InMemoryCredentialStore` (Storage API) and the accepted-offer record
  (Credential Offer API) are no longer a bare `Vec`/no-structure blob: a
  stored credential batch and an accepted offer are now real RDF triples in
  an embedded Oxigraph store (`identity-hub-graph`), addressed by blank
  node, queryable via SPARQL, and reachable through Contreforts' generic
  connector interface (`identity-hub-contreforts`) - see "Provenance:
  Contreforts" below for the full design. This is **not** a durability
  upgrade, and is not meant to be read as one: the graph is opened with
  `Store::new()` (Oxigraph's in-memory backend), never persisted to disk,
  and still lives and dies with the process - exactly like the Issuer
  Service's own request-tracking `HashMap`, which this change does not
  touch. The value added is a native semantic runtime layer (real triples,
  IRI addressing, SPARQL queryability, a genuine connector-interface
  round trip), not persistence across restarts. This mirrors
  `ds-sql-dps-rs/config-graph`'s own precedent and its own doc comment's
  reasoning almost verbatim: "there is no on-disk persistence requirement
  this small a config warrants yet" - the same call, made for the same
  reason, on a second project in this study.
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
container — 2026-09-20, final result: full conformance, 54/54.** Eight
changes today, in order: real per-request authorization added to the
Storage API and Credential Offer API; `verify_bearer_token` gaining
`iss == sub`/`nbf`/`capabilityInvocation`/`jti`-replay checks;
scope-escalation enforcement added to `presentation_query` against the
caller's own nested access-token grant; the Storage API's credential store
and Credential Offer API's accepted-offer record rebuilt on a
Contreforts-backed semantic RDF graph (orthogonal to TCK conformance — see
"Provenance: Contreforts"); an `iat`-in-the-future check added to
`verify_bearer_token`; a trusted-issuer allow-list check added to the
Storage API and Credential Offer API; real message-content/business-logic
validation added to both; and finally, genuine authentication of the
nested `token` claim itself (signature verification plus a confused-deputy
binding check), closing the last two gaps (see "What's simplified or
stubbed" for the full account of each). Not fabricated: `tests/dcp_tck.rs`
boots this crate's real Credential Service in-process and drives the
actual, official TCK container against it via `testcontainers`, exactly as
it runs in CI. The 0-failure result was reproduced identically **three**
times in a row (54/54 `SUCCESSFUL`, byte-identical test sets, zero
failures every run) before being written down here.

Scoped to the Credential Service test packages
(`org.eclipse.dataspacetck.dcp.verification.presentation.cs` +
`....issuance.cs`), per the SUT matrix above:

| Test package | Total | Passed | Failed |
|---|---:|---:|---:|
| `presentation.cs` (VPP) | 23 | 23 | 0 |
| `issuance.cs` (CIP) | 31 | 31 | 0 |
| **Total** | **54** | **54** | **0** |

**Reconfirmed unchanged after a ninth, later change the same day** (see
"What's simplified or stubbed"'s "Deny-by-default read authorization plus
issuer authority" bullet): an independent security audit found three
gaps in the model behind the eighth change's nested-token authentication
that no TCK test exercises (a missing grant read as unrestricted access, a
self-signed token from a non-authoritative issuer, and this hub's own STS
minting tokens its own verifier rejected). Fixing them was re-run against
the same real TCK container and reproduced the identical 54/54 result
three more times — the security fix closed real, TCK-invisible gaps, not
TCK regressions, and did not change this table.

**Reconfirmed unchanged again after a tenth, later change the same day**
(see "What's simplified or stubbed"'s "Outbound request confinement plus
timeouts" bullet): the same independent security audit's remaining
findings — pre-auth SSRF via unvalidated `did:web` resolution, a second
SSRF via an unvalidated issued-credential delivery endpoint, and no timeout
on any outbound call — were fixed by a deny-by-default host allow-list
(`identity_hub_http::outbound::OutboundPolicy`) plus a connect/total
timeout on the shared `reqwest` client, none of which any TCK test
exercises either. This was the highest-regression-risk change of the two
security-audit passes, since the fix's entire mechanism sits directly on
top of the real TCK's own `host.docker.internal`-pinned resolution path
(see "A real networking gotcha" above) — so the real TCK was re-run
repeatedly while building it, not just once at the end. Reproduced the
identical 54/54 result three times after landing; did not change this
table either.

**Reconfirmed unchanged again after an eleventh, later change the same
day** (see "What's simplified or stubbed"'s "Storage API deny-by-default
posture plus a closed credential-format set" bullet): the same independent
security audit's remaining HIGH finding — an empty `trusted_issuer_dids`
meaning "trust everyone" instead of "trust nobody", and a non-`"jwt"`
credential `format` skipping proof verification entirely and being stored
unverified (a signing oracle via `handlers::build_presentation`) — was
fixed without touching the real TCK's own explicit SUT configuration
(`dataspacetck.did.issuer` was never empty, and every format label the TCK
puts on the wire contains `"jwt"`, confirmed from `/app/tck-runtime.jar`,
not guessed). Reproduced the identical 54/54 result three times after
landing; did not change this table either.

`tests/dcp_tck.rs`'s `dcp_tck_reports_full_credential_service_conformance`
now asserts the TCK's own reported failure set is genuinely empty — not a
count check, an assertion against the actual set of failing test method
names the TCK's own stack traces name, which happens to be empty. Before
the eighth change, this test asserted an **exact set** of 2 known
failing test names (`EXPECTED_FAILURES`, now retired — see that test's own
doc comment for why keeping an always-empty constant around would serve no
purpose): `cs_04_03_03_idTokenInvalidIssuerSub` and
`cs_05_04_invalidTokenNotAuthorized`, both closed by this change.

**What closed the last two failures — one gap, two severities: nested-access-token
authentication.** The nested `token` claim (the actual
Verifiable-Presentation access token a caller forwards inside its outer
Self-Issued ID Token, per `base.protocol.md`) already had its `scope` claim
read and enforced (closing `cs_05_04_01_02_invalidScopeEscalationRequest` in
an earlier change today), but its signature was never verified, and nothing
bound it back to the outer envelope's own caller. Confirmed by reading
`PresentationFlowSection4Test`/`PresentationFlowSection5Test` and
`SecureTokenServerImpl` in `eclipse-dataspacetck/dcp-tck`, not guessed from
test names: `idTokenInvalidIssuerSub`'s outer envelope is perfectly valid
(`iss == sub == thirdPartyDid`, genuinely signed, correctly audienced), but
the nested access token it forwards was minted bound (`aud`) to the
*verifier*'s DID, not `thirdPartyDid` — a confused-deputy forward a
scope-only check can't catch, since the forwarded token's `scope` claim is
itself genuine. `invalidTokenNotAuthorized`'s nested token, the literal
`"faketoken"`, isn't a JWS at all — this bootstrap's old scope check simply
couldn't decode it and fell back to *no* restriction, rather than rejecting
the request. Fixed by a new `auth::verify_nested_access_token`
(`identity-hub-http/src/auth.rs`): it resolves the nested token's own `iss`
DID, verifies its JWS signature (the same primitives `verify_bearer_token`
already uses for the outer envelope), checks it hasn't expired, and checks
its `aud` claim equals the outer envelope's own caller — any failure now
rejects the whole request outright. See "What's simplified or stubbed"
("Nested-access-token authentication (confused-deputy fix)") for the full
account, including a latent test-fixture gap this surfaced and fixed in
`presentation_scope_enforcement.rs`.

What's genuinely proven working by the **54 passing tests**: everything
every previous snapshot proved (real `did:web` hosting and
Credential-Service-endpoint discovery, the Storage/Offer APIs'
authorization rejections for every *shape*-level token defect, all four
endpoints' `iss == sub`/`nbf`/`iat`/`capabilityInvocation`/`jti`-replay
checks, the trusted-issuer allow-list, and the Storage/Offer APIs' full
message-content/business-logic validation) plus, new in this snapshot: the
Presentation API genuinely authenticating a caller's nested access token —
rejecting a forwarded (confused-deputy) grant and an undecodable one alike
— rather than trusting or best-effort-reading it. Real, TDD'd, and
TCK-confirmed, not assumed: see `tests/nested_access_token_authentication.rs`
for the same two closing assertions made directly against the HTTP layer,
without a TCK/Docker dependency, alongside regression guards that a
correctly-bound nested token, an expired one, and a bare envelope with no
nested token at all all behave exactly as they should.

Run it yourself: `cargo test -p identity-hub-http --test dcp_tck --
--ignored --nocapture` (needs Docker). See `tests/dcp_tck.rs`'s module doc
comment for the full methodology and the networking gotcha its
configuration works around. For the HTTP-layer-only, no-Docker-needed
coverage of the authorization behavior, see
`cargo test -p identity-hub-http --test storage_offer_auth` (per-request
authorization itself), `cargo test -p identity-hub-http --test
si_token_validation` (the outer-envelope token-content checks, including
`iat`), `cargo test -p identity-hub-http --test
presentation_scope_enforcement` (the scope-escalation check), `cargo test
-p identity-hub-http --test trusted_issuer_allowlist` (the trusted-issuer
allow-list check), `cargo test -p identity-hub-http --test
message_content_validation` (the message-content/business-logic checks),
`cargo test -p identity-hub-http --test
nested_access_token_authentication` (the nested-token authentication
check), `cargo test -p identity-hub-http --test nested_token_authorization`
(the deny-by-default read authorization plus issuer-authority checks),
`cargo test -p identity-hub-http --test outbound_request_confinement` (the
outbound host allow-list plus timeout checks), and `cargo test -p
identity-hub-http --test storage_write_default_posture` (the Storage API's
deny-by-default trusted-issuer posture plus the closed credential-format
set, including a real-binary-spawn regression guard).

## Continuous integration

`.github/workflows/ci.yml` runs two jobs on every push/PR to `main`:

- **`quality`** — `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace` (which does not
  run `dcp_tck.rs`'s `#[ignore]`d test). No Docker needed.
- **`dcp-tck`** — the DCP TCK conformance test described above, on
  `ubuntu-latest` (Docker preinstalled). Gating, not `allow-failure`: as of
  2026-09-20 it asserts genuine full conformance (the TCK's own reported
  failure set is empty) on the Credential Service scope this project
  targets, so any real regression fails the job the same way it would fail
  an all-green expectation anywhere else — no categorized-failure-set
  bookkeeping is needed anymore now that there is nothing left to
  categorize (see "DCP TCK conformance snapshot").

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
                            VPP/CIP wire-message shapes, the
                            Contreforts-backed credential store's public
                            surface (InMemoryCredentialStore, wrapping
                            identity-hub-graph), scope-to-type matcher, the
                            embedded STS. Built on ds-dcp-core-rs.
    identity-hub-graph/    Embedded Oxigraph RDF store: accepted credential
                            batches and accepted credential offers as real,
                            SPARQL-addressable triples. Own domain types
                            (CredentialBatch/CredentialEntry/AcceptedOffer),
                            independent of identity-hub-core - see
                            "Provenance: Contreforts" above.
      src/
        vocab.rs            Namespace IRIs: real W3C Verifiable Credentials
                            terms plus this project's own ds: predicates.
        model.rs            Plain input/output domain structs.
        store.rs             CredentialGraph: open_in_memory, add_batch/
                            batches/batch, add_offer/offers/offer,
                            credentials_of_types.
    identity-hub-contreforts/
                            Implements contreforts_core::ContrefortsConnector
                            for identity-hub-graph's CredentialGraph, with
                            its own minted EntityKinds and declaration.ttl.
      src/
        lib.rs               CredentialGraphConnector.
        declaration.ttl      Self-description, SHACL-validated.
      tests/
        declaration_validates.rs   Validates declaration.ttl against
                            Contreforts' own real SHACL meta-shapes.
    identity-hub-http/     axum HTTP surface (Credential Service + Issuer
                            Service modes) and the dcp-tck conformance test.
      src/
        config.rs          Mode/Config: which role, bind address, own
                            did:web host, STS credentials, scope pattern,
                            trusted-issuer allow-list, known-holder-pid
                            allow-list, operator-supplied extra outbound
                            hosts.
        state.rs           AppState: identity, STS-party identity, store,
                            reqwest client (host.docker.internal override,
                            connect/total timeouts), the derived
                            OutboundPolicy.
        auth.rs             Self-Issued ID Token validation, plus the
                            separate trusted-issuer allow-list check.
        outbound.rs          OutboundPolicy: deny-by-default outbound-host
                            allow-list (host-only match, no wildcard/CIDR)
                            checked before every DID resolution/delivery/
                            catalog-fetch call.
        validation.rs        Message-content/business-logic validation:
                            CredentialMessage status allow-list, known-
                            holderPid check, embedded-credential proof
                            verification, CredentialOfferMessage
                            non-empty/catalog checks.
        handlers.rs         All HTTP routes for both modes.
        main.rs             CLI: `identity-hub credential-service|issuer-service`;
                            also runs the one-off Contreforts round-trip
                            proof at startup (Credential Service mode).
      tests/
        dcp_tck.rs               Real dcp-tck-runtime conformance test.
        dcp.tck.properties       TCK config, bind-mounted into the container.
        storage_offer_auth.rs    Storage/Offer API authorization rejection
                                  cases (real HTTP, no Docker/TCK needed).
        si_token_validation.rs   iss==sub/nbf/capabilityInvocation/jti-replay
                                  checks (real HTTP, no Docker/TCK needed).
        presentation_scope_enforcement.rs
                                  Scope-escalation enforcement against the
                                  caller's own granted scope (real HTTP, no
                                  Docker/TCK needed).
        trusted_issuer_allowlist.rs
                                  Trusted-issuer allow-list check on the
                                  Storage/Offer APIs (real HTTP, no
                                  Docker/TCK needed).
        message_content_validation.rs
                                  Message-content/business-logic checks on
                                  the Storage/Offer APIs (real HTTP, no
                                  Docker/TCK needed).
        nested_access_token_authentication.rs
                                  Nested access-token authentication
                                  (signature + confused-deputy binding
                                  check) on the Presentation API (real
                                  HTTP, no Docker/TCK needed).
        nested_token_authorization.rs
                                  Deny-by-default read authorization plus
                                  issuer-authority checks on the
                                  Presentation API (2026-09-20 security
                                  audit Findings 1, 2, 9 — real HTTP, no
                                  Docker/TCK needed).
        outbound_request_confinement.rs
                                  Outbound host allow-list plus timeout
                                  checks (2026-09-20 security audit
                                  Findings 4, 5, 6 — real HTTP, no
                                  Docker/TCK needed).
        storage_write_default_posture.rs
                                  Storage API deny-by-default trusted-issuer
                                  posture plus the closed credential-format
                                  set, including a real-binary-spawn
                                  regression guard (2026-09-20 security
                                  audit, remaining HIGH finding — real HTTP,
                                  no Docker/TCK needed).
  vendor/
    contreforts-core/      Git submodule (contreforts-ai/contreforts-core),
                            pinned to commit 95a4940 - the same commit
                            ds-sql-dps-rs vendors. Provides the
                            ContrefortsConnector trait and, via its nested
                            declaration/ crate, the SHACL meta-shape
                            validator identity-hub-contreforts's test uses.
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
# Credential Service (VPP + CIP), default port 8080. --trusted-issuer-did is
# required (may be repeated) - an empty allow-list trusts nobody, so the
# Storage API and Credential Offer API reject every write with 401 until at
# least one is given (2026-09-20 fix, HIGH - see "What's simplified or
# stubbed"'s "Storage API deny-by-default posture" entry):
cargo run -p identity-hub-http --bin identity-hub -- credential-service \
  --did-host localhost:8080 --trusted-issuer-did did:web:some-issuer.example:issuer

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
`--trusted-issuer-did` (repeatable) populates `Config::trusted_issuer_dids`
for a Credential Service's Storage/Offer APIs; omitted, it defaults to
empty, which (2026-09-20 fix, HIGH) means **no issuer is trusted** - the
Storage API and Credential Offer API reject every write with `401` until at
least one is given - see that field's doc comment. `--known-holder-pid`
(repeatable) populates `Config::known_holder_pids` for the Storage API's
`holderPid` check; that one is unrelated and stays empty-by-default
permissive on purpose (out of scope for the 2026-09-20 fix - this bootstrap
has no Credential-Request-tracking state to populate it from yet) - see
that field's doc comment.
