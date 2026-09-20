# DCP Credential Service benchmark: eclipse-edc/IdentityHub vs. ds-identity-hub-rs

A real, reproducible performance comparison of two DCP (Decentralized Claims
Protocol) Credential Service implementations on the **same endpoint**
(`POST .../presentations/query`, the Presentation API - the core
Credential-Service operation both implement), one process under load at a
time on the same otherwise-idle host:

1. **EDC IdentityHub** - Eclipse EDC's real IdentityHub, v0.18.0, vendored
   at `dataspace/vendor/identity-hub` (Java).
2. **ds-identity-hub-rs** - this repository's own Rust implementation (this
   benchmark's target commit: see `bench/results/rust/pinned-commit.txt`),
   which reached 54/54 real DCP TCK conformance the same day this benchmark
   was run - see `../ARCHITECTURE.md`'s "DCP TCK conformance snapshot".

Load shape follows `dataspace/docs/benchmarks/2026-08-27-dcp-auth-overhead.md`'s
own house methodology: k6 `constant-vus` executor, 20 VUs, 30s measured
duration, a 5-VU/10s warmup discarded first, one target process under load at
a time (never concurrently), RSS/CPU sampled at 1-second resolution
throughout. See `bench/results/environment.txt` for the exact host
(`nproc`/`CLK_TCK`/tool versions) both legs ran on.

## Directory layout

```
bench/
  README.md                    this file
  sample-rss-cpu.sh            1-second RSS/CPU sampler, copied verbatim
                                from ds-catalog-broker-rs/compliance/harvest-bench/
  load/
    presentation-query.k6.js             EDC leg: one fixed bearer token
                                          reused for the whole k6 run
    presentation-query-token-pool.k6.js  Rust leg: reads a pre-minted pool
                                          of distinct tokens, one per
                                          iteration - see "Why every request
                                          needs its own token" below
  edc-identity-hub/            EDC-specific setup, adapted from the sibling
                                ds-catalog-broker-rs repo's dcp-test-env
                                (read-only reference - see below)
    run-identityhub.sh         builds (once) and runs a seeded IdentityHub
    seed/                      the seed ServiceExtension + key generator
    mint-token.py               mints one EDC bearer token (fixed-token
                                recipe - see validate.py's own account)
    validate.py                 copied verbatim from dcp-test-env, used
                                once to confirm this checkout's own seeded
                                instance really works end to end before
                                building anything else around it
  verifier-token/               Rust leg's own bench-only helper crate (its
                                own Cargo workspace - see its Cargo.toml's
                                own comment for why) - see "Why a whole
                                extra process" below
  bench-edc.sh                  orchestrates the whole EDC leg end to end
  bench-rust.sh                 orchestrates the whole Rust leg end to end
  results/
    environment.txt             shared host/tool-version record
    edc/                        EDC leg's raw results (see below)
    rust/                       Rust leg's raw results (see below)
```

Each `results/<target>/` directory holds: `pinned-commit.txt`, `pid.txt`,
`idle-rss-cpu.csv` (post-warmup, pre-load baseline), `load-rss-cpu.csv`
(sampled concurrently with the measured k6 run), `warmup.stdout.txt`,
`load.stdout.txt`, and `load.summary.json` (k6's `--summary-export`).

## The EDC side - real, working infrastructure reused, not modified

`ds-catalog-broker-rs/compliance/dcp-test-env` (a sibling repo) already has a
real, previously-validated EDC IdentityHub launch+seed setup: a seed
`ServiceExtension` that creates a `dcp-test-client` (holder) participant, a
`verifier` participant (needed for DCP's proof-of-original-possession - see
that repo's own README for the full "why a third participant" explanation),
and a real ES256-signed `FederatedCatalogAccessCredential` in the holder's
store. **That directory is read-only reference for this benchmark** - never
modified - but its scripts were copied and lightly adapted (only the
`IDENTITY_HUB_DIR` default path) into `bench/edc-identity-hub/` here, per
this project's own working conventions.

Only `run-identityhub.sh` is needed - the separate Issuer Service
(`run-issuer-service.sh` in the source repo) is **not** required for this
benchmark: the seeded credential's issuer DID is only ever referenced inside
the credential's own `iss` claim, never re-resolved by a presentation query
(no signature verification happens server-side on a stored credential's own
payload - see `identity_hub_core::store`'s doc comment on the Rust side for
the same design choice), and both the holder and verifier participants
DCP's proof-of-original-possession needs live in the *same* IdentityHub
instance. This was confirmed empirically, not assumed: `validate.py` (copied
verbatim from the source repo, run once against this checkout's own freshly
seeded instance) passed end to end with only `run-identityhub.sh` running.

`mint-token.py` mints one bearer token, following the exact same two-step
recipe `validate.py` already validates (see that script's own module doc
comment): the holder's STS mints a self-issued token addressed to the
verifier, embedding a nested presentation-access-token; the verifier's STS
re-packages that nested token into a new self-issued token addressed back to
the holder. `bench-edc.sh` mints one fresh token before the warmup run and
another before the measured run (comfortably inside the token's TTL either
way) and reuses it as a fixed `Authorization: Bearer` header for that whole
k6 invocation - safe because this test environment's IdentityHub has `jti`
replay validation disabled (documented in dcp-test-env's own README), so
one caller re-presenting the same token thousands of times in a row is
accepted every time.

Ports: 9080 base, 9081 identity API, 9082 credentials/presentation API
(what this benchmark targets), 9083 DID hosting, 9084 STS.

## The Rust side

`ds-identity-hub-rs` boots in Credential Service mode:

```
cargo run --release -p identity-hub-http --bin identity-hub -- \
  credential-service --bind 0.0.0.0:18080 --did-host 127.0.0.1:18080
```

Its Presentation API is `POST /presentations/query`; its own embedded STS is
`POST /sts/token` (default client id/secret `tck-client`/`tck-secret`).

### Why a whole extra process (`bench/verifier-token/`), not just a curl one-liner

`identity_hub_http::auth::verify_bearer_token` requires the outer Self-Issued
ID Token's `iss`/`sub` to be a `did:web` DID this process can itself resolve
over HTTP. The target's own embedded STS only ever signs as its own
`sts_party` identity - there is no way to make it sign as an arbitrary
external caller the way EDC's dcp-test-env pre-seeds a whole second
participant for. So `bench/verifier-token` is a small standalone Rust binary
(its own Cargo workspace - see its `Cargo.toml`'s own comment for why it
isn't a member of the root workspace) that generates and *hosts* its own
real `did:web` "issuer" and "verifier" identities and plays the same DCP
choreography externally, over real HTTP, against the real running server -
exactly the recipe
`crates/identity-hub-http/tests/nested_access_token_authentication.rs`'s own
`presentation_query_accepts_a_nested_token_bound_to_its_own_presenter`
regression guard proves the target accepts:

1. At startup: seeds one `MembershipCredential` into the target's Storage
   API (`POST /credentials`), signed by its own "issuer" identity, using a
   Self-Issued ID Token minted by the *target's own* STS (audience = the
   target's own DID - accepted under the target's permissive default empty
   `trusted_issuer_dids`/`known_holder_pids` allow-lists).
2. `GET /mint`: fetches a nested Verifiable-Presentation access token from
   the target's STS (bound to this process's own "verifier" DID), then
   wraps it in a fresh outer Self-Issued ID Token signed by that same
   "verifier" key.
3. `GET /mint-batch?n=<count>`: the same recipe, but mints `count` distinct
   tokens in one call (parallelized across every core) - see "Why every
   request needs its own token" below for why this exists at all.

This process must keep running for the *entire* k6 load test window
(warmup and measured run alike): the target resolves the caller's `did:web`
document on every single `/presentations/query` call (no caching - see
`../ARCHITECTURE.md`), so the "verifier" identity's DID document must stay
resolvable throughout.

### Why every request needs its own token (and EDC's leg doesn't)

`ds-identity-hub-rs`'s `verify_bearer_token` enforces genuine `jti` replay
protection, permanently, on every request - a real security feature this
project just finished closing the last DCP TCK gaps for (see
`../ARCHITECTURE.md`'s "DCP TCK conformance snapshot"), not a bootstrap
artifact and not configurable off. EDC's dcp-test-env, by contrast, runs
with `edc.iam.accesstoken.jti.validation` disabled (its own documented
setting). This was discovered empirically, the hard way: an early version of
this benchmark reused one fixed bearer token for the whole Rust k6 run (the
same pattern that works for EDC) and got **100% `401` failures** - every
request after the very first was rejected as a replay, at very high apparent
throughput (~100,000-120,000/s) because the rejection happens only *after*
paying the real cost of resolving the caller's DID and verifying its
signature.

So the Rust leg cannot reuse one token per run. Instead, `bench-rust.sh`
pre-mints a large pool of distinct, genuinely valid tokens via
`verifier-token`'s `GET /mint-batch?n=<count>` before each k6 phase (sized
with headroom over the empirically observed ~7,000-9,000 req/s genuine,
non-replayed ceiling on this host - see the results below), writes them to
a scratch file, and `bench/load/presentation-query-token-pool.k6.js` reads
that file into a k6 `SharedArray` and indexes it by
`exec.scenario.iterationInTest` - a single counter shared across every VU
for the whole run, guaranteeing no two iterations, concurrent or not, ever
reuse the same token. Token pool files are pure scratch (hundreds of MB) and
are written to `/tmp`, never committed.

**A second real gotcha this surfaced**: `PresentationQueryMessage`'s wire
field is `type` (`identity_hub_core::messages`, cross-checked against the
DCP spec's own JSON examples), not `@type` - an early version of both k6
scripts used `@type` (copied from an unrelated DSP benchmark script's
`CatalogRequestMessage` shape) and got a `422` from Rust every time. EDC
tolerated the wrong field name silently (its JSON-LD-based deserialization
doesn't strictly require it), which is exactly why this went unnoticed until
the Rust leg was wired up - both k6 scripts were fixed to use the
spec-correct `type` field before any numbers below were recorded.

### Credential type/scope: NOT the same on both sides, reported honestly

EDC's side is seeded (by dcp-test-env's own, unmodified seed extension) with
a `FederatedCatalogAccessCredential`, scope
`org.eclipse.dspace.dcp.vc.type:FederatedCatalogAccessCredential:read`.
Rust's side is seeded with a `MembershipCredential`, scope
`org.eclipse.dspace.dcp.vc.type:MembershipCredential` - `MembershipCredential`
is `ds-identity-hub-rs`'s own established convention (its Issuer Service's
one hardcoded `CredentialObject`, and the type its own test suite -
`nested_access_token_authentication.rs`, `presentation_scope_enforcement.rs`
- already uses throughout). Both are a single stored credential of one type,
returned as one `verifiableCredential` entry inside one Verifiable
Presentation JWT - structurally equivalent server-side work (one scope
lookup, one JWS-signed VP built over exactly one wrapped credential) even
though the type name and issuing choreography differ. This is a real,
acknowledged mismatch, not a hidden one: rewriting either side's seed data to
match the other was judged not worth the extra risk this benchmark's time
budget didn't need to take on, given the per-request server-side work is
equivalent either way.

## Reproducing this end to end

```bash
# EDC leg (boots a fresh seeded IdentityHub if one isn't already listening
# on :9082 - first run needs a real Gradle build, budget several minutes):
./bench-edc.sh
kill $(cat results/edc/pid.txt)   # stop EDC before running the Rust leg

# Rust leg (builds identity-hub + verifier-token in release mode if needed,
# self-contained - stops both processes itself when done):
./bench-rust.sh
```

Both scripts are idempotent-ish and safe to re-run; neither runs while the
other target is under load (run them sequentially, as above, to keep the
"one process under load at a time" methodology this benchmark reports
against). Override `VUS`/`DURATION`/`WARMUP_VUS`/`WARMUP_DURATION` via env
vars to change the load shape; `bench-rust.sh` additionally takes
`WARMUP_POOL`/`MEASURED_POOL` to resize its pre-minted token pools if a
different host's throughput needs more headroom (a pool exhausted mid-run
would show up as a burst of `401`s at the tail of the run - it is not
silently tolerated).

## Results

See `docs/benchmarks/` in the main `dataspace` repository for the full
written report (metrics table, latency percentiles, honesty caveats). The
raw, point-in-time artifacts this benchmark actually produced are committed
under `results/edc/` and `results/rust/` in this directory.

## Cleanup

Both scripts stop what they started (`bench-rust.sh` kills both `identity-hub`
and `verifier-token` at the end; `bench-edc.sh` deliberately does **not**
stop EDC IdentityHub itself - kill it manually via `results/edc/pid.txt`
before running the Rust leg, or once you're done reproducing this). Verify
with `ss -tlnp | grep -E ':(908[0-4]|18080|18091) '` and `pgrep -af
'BaseRuntime|identity-hub|verifier-token'` that nothing is left listening.
