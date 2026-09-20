//! TDD coverage for the 2026-09-20 independent security audit's
//! unbounded-growth finding (MEDIUM), HTTP-state half: two of the three
//! attacker-reachable structures in this process that grow for the lifetime
//! of the process and are never capped or evicted. (The third, the
//! credential graph, is pinned by
//! `../../identity-hub-graph/tests/bounded_graph_growth.rs` and
//! `../../identity-hub-core/tests/bounded_credential_store.rs`.)
//!
//! **(1) `AppState::seen_jti`** (`state.rs`, inserted by
//! `auth::verify_bearer_token`): one `String` per distinct `jti` claim ever
//! seen, in a `HashSet` that is never evicted, capped, or expired. The `jti`
//! is an arbitrary caller-chosen string, and - this is what makes it a
//! finding rather than a capacity note - it is recorded *before* any
//! authorization decision is reached: the replay check is the last step of
//! `verify_bearer_token`, and `check_trusted_issuer` (the deny-by-default
//! step added for the audit's Storage API HIGH) only runs afterwards. A
//! caller that is rejected `401` on every single request therefore still
//! grows this set by one entry per request, forever. The test below is
//! written that way deliberately: every request it makes is refused, and
//! the set still grows unboundedly.
//!
//! **(2) `AppState::requests`** (`state.rs`, inserted by
//! `handlers::credential_request`): one `RequestRecord` per accepted
//! Credential Request on the Issuer Service, keyed by a freshly minted
//! UUID, never removed - plus one `tokio::spawn`ed delivery task per
//! request, with no ceiling on how many run at once.
//!
//! ## Why the tests assert a *cap* rather than exhaust memory
//!
//! A literal "insert until the process dies" test is neither fast nor
//! deterministic, and proves nothing a bound-assertion doesn't. Each test
//! below therefore drives a few dozen operations past the cap this finding's
//! spec requires and asserts the structure stayed at or below it. Today
//! nothing evicts anything, so each ends up holding every entry it was ever
//! given: red by exactly the margin of the overshoot. The caps are declared
//! locally here because no such constant exists in the source yet - the fix
//! is expected to introduce `identity_hub_http::state::MAX_SEEN_JTI` and
//! `identity_hub_http::state::MAX_TRACKED_REQUESTS` with these same values
//! (a cap *smaller* than these still satisfies every assertion here; a
//! larger one does not).
//!
//! ## What must not regress
//!
//! Eviction may not weaken the protection each structure exists to provide
//! for *current* traffic, so both unbounded-growth tests below carry their
//! own guard in the same test (cheaper than a second multi-thousand-request
//! loop): the most recently seen `jti` must still be caught as a replay, and
//! the most recently accepted Credential Request must still be retrievable
//! through `GET /requests/<id>`. Two further low-volume tests pin that
//! ordinary traffic - anything the real `eclipsedataspacetck/dcp-tck-runtime`
//! run produces, which is a few hundred tokens and a few dozen requests
//! across all 54 test cases - never evicts anything at all. Those four are
//! the reason the caps are set generously rather than tightly.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// The maximum number of `jti` values this process may remember at once.
/// Generous on purpose: it has to comfortably outlast the replay window of
/// every token in flight at once (this bootstrap mints 5-minute tokens) and
/// to never be reached by a real TCK run, while still being a fixed ceiling
/// an attacker cannot push past. See this file's module doc comment.
const MAX_SEEN_JTI: usize = 4096;

/// The maximum number of Credential Request records the Issuer Service may
/// track at once. Same reasoning as [`MAX_SEEN_JTI`]; smaller because a
/// request record is a multi-field struct rather than one short string, and
/// because the Credential Request Status API is only ever polled about
/// recent requests.
const MAX_TRACKED_REQUESTS: usize = 2048;

/// How far past each cap the tests below push. Small: the point is to cross
/// the boundary and observe what happens at it, not to stress the process.
const OVERSHOOT: usize = 64;

/// Boots this crate's real Credential Service in-process, with no trusted
/// issuer configured - so every request below is refused `401` and the
/// `seen_jti` growth the first test measures is growth caused by a caller
/// this service explicitly does not trust.
async fn spawn_credential_service() -> (Arc<AppState>, String) {
    spawn(Mode::CredentialService).await
}

/// Boots this crate's real Issuer Service in-process. The Credential
/// Request API deliberately has no trusted-caller allow-list of its own
/// (any party may ask an issuer for a credential), which is what makes its
/// request table the more exposed of the two structures here.
async fn spawn_issuer_service() -> (Arc<AppState>, String) {
    spawn(Mode::IssuerService).await
}

async fn spawn(mode: Mode) -> (Arc<AppState>, String) {
    let config = Config::for_test(mode, SocketAddr::from(([127, 0, 0, 1], 0)), "localhost:0");
    let (state, router) = identity_hub_http::build(config);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the service under test");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("service under test");
    });
    (state, format!("http://{addr}"))
}

/// The same stand-in `did:web` server the rest of this suite uses: a real,
/// resolvable identity with a real `capabilityInvocation` key, so every
/// token below is genuinely valid and nothing is ever rejected on a
/// malformed envelope.
async fn spawn_caller_identity(path_segment: &str) -> ServiceIdentity {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the stand-in DID server");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), path_segment);
    let doc = identity.did_document(&[]);
    let route = format!("/{path_segment}/did.json");
    let app = Router::new().route(
        &route,
        get(move || {
            let doc = doc.clone();
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("stand-in caller DID server");
    });
    identity
}

/// A genuinely valid Self-Issued ID Token with a fresh, unique `jti` -
/// correctly self-signed, `iss == sub`, addressed to `aud`, unexpired.
fn bearer_token(caller: &ServiceIdentity, aud: &str) -> String {
    let now = dcp_core::now_secs();
    dcp_core::sign_jws(
        &json!({
            "iss": caller.own_did(),
            "sub": caller.own_did(),
            "aud": aud,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
        &caller.key_pair.signing_key(),
        caller.own_key_id(),
    )
}

/// A well-formed `CredentialMessage` body. Its contents are irrelevant to
/// what this file measures - the request never gets past authorization -
/// but it must deserialize, or axum rejects it `422` before
/// `verify_bearer_token` (and therefore the `jti` record) is ever reached.
fn credential_message_body() -> Value {
    json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialMessage",
        "issuerPid": "issuer-pid-1",
        "holderPid": "holder-pid-1",
        "status": "ISSUED",
        "credentials": [],
    })
}

/// A well-formed `CredentialRequestMessage` asking for the one credential
/// this bootstrap's Issuer Service supports (`AppState::supported_credential`),
/// so the request is accepted, recorded, and answered `201 Created`.
fn credential_request_body(holder_pid: &str) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialRequestMessage",
        "holderPid": holder_pid,
        "credentials": [{"id": "membership-credential"}],
    })
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    bearer: &str,
    body: &Value,
) -> reqwest::Response {
    client
        .post(url)
        .header("Authorization", format!("Bearer {bearer}"))
        .json(body)
        .send()
        .await
        .expect("request completes")
}

// ---- (1) the replay-protection set ----

/// The headline case for `seen_jti`: a caller this service refuses on every
/// single request still writes one permanent entry into the process's
/// replay-protection set per request, because the `jti` is recorded inside
/// `verify_bearer_token` and the trusted-issuer decision that rejects the
/// caller only happens afterwards. Nothing ever removes an entry, so the set
/// is a remotely-driven, unbounded allocation reachable without any
/// authorization whatsoever.
///
/// Red at the time of writing: after `MAX_SEEN_JTI + OVERSHOOT` refused
/// requests the set holds all `MAX_SEEN_JTI + OVERSHOOT` of them.
///
/// The second assertion is the guard the fix has to respect: evicting the
/// *oldest* entries is fine, but the most recently seen token must still be
/// caught as a replay - the whole point of the set.
#[tokio::test]
async fn seen_jti_set_does_not_grow_without_bound() {
    let stranger = spawn_caller_identity("stranger").await;
    let (state, base) = spawn_credential_service().await;
    let client = reqwest::Client::new();
    let url = format!("{base}/credentials");
    let audience = "did:web:localhost%3A0:credential-service";
    let body = credential_message_body();

    let mut last_token = String::new();
    for _ in 0..(MAX_SEEN_JTI + OVERSHOOT) {
        last_token = bearer_token(&stranger, audience);
        let response = post(&client, &url, &last_token, &body).await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "this caller is deliberately untrusted - every request here is refused, which is \
             exactly what makes the growth it still causes a finding"
        );
    }

    let remembered = state.seen_jti.lock().expect("seen_jti lock poisoned").len();
    assert!(
        remembered <= MAX_SEEN_JTI,
        "the replay-protection set must be bounded: after {} refused requests it holds {} jti \
         values, one per request, with nothing evicting them - an unauthenticated caller can \
         grow this process's memory without limit one HTTP request at a time (2026-09-20 \
         independent security audit, MEDIUM)",
        MAX_SEEN_JTI + OVERSHOOT,
        remembered
    );

    // Whatever the bound is, it may not cost the set its actual job for
    // current traffic: the token used moments ago must still be a known
    // replay. Green before and after - a fix that evicts oldest-first keeps
    // it that way; one that clears the whole set on overflow does not.
    let replay = post(&client, &url, &last_token, &body).await;
    let status = replay.status();
    let message = replay.text().await.expect("response body is readable");
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        message.contains("replay"),
        "the most recently seen jti must still be rejected as a replay, not silently forgotten \
         by whatever bounds the set; got: {message}"
    );
}

/// The low-volume guard: ordinary traffic - everything a real
/// `eclipsedataspacetck/dcp-tck-runtime` run produces - must be entirely
/// unaffected, with every `jti` it presents still remembered. Green before
/// and after; this is what makes the cap a safety valve rather than a
/// behaviour change.
#[tokio::test]
async fn low_volume_traffic_keeps_every_jti() {
    let stranger = spawn_caller_identity("stranger").await;
    let (state, base) = spawn_credential_service().await;
    let client = reqwest::Client::new();
    let url = format!("{base}/credentials");
    let audience = "did:web:localhost%3A0:credential-service";
    let body = credential_message_body();

    let mut tokens = Vec::new();
    for _ in 0..32 {
        let token = bearer_token(&stranger, audience);
        post(&client, &url, &token, &body).await;
        tokens.push(token);
    }

    assert_eq!(
        state.seen_jti.lock().expect("seen_jti lock poisoned").len(),
        32,
        "nothing may be evicted at ordinary volumes"
    );
    // Including the very first one, which is the one an over-eager bound
    // would drop first.
    let replay = post(&client, &url, &tokens[0], &body).await;
    let message = replay.text().await.expect("response body is readable");
    assert!(
        message.contains("replay"),
        "the oldest jti of a normal-sized run must still be caught as a replay; got: {message}"
    );
}

// ---- (2) the Issuer Service's request table ----

/// The headline case for `AppState::requests`: every accepted Credential
/// Request leaves a `RequestRecord` in the Issuer Service's table forever
/// (and spawns an unbounded delivery task alongside it). The Credential
/// Request API has no trusted-caller allow-list of its own - any party able
/// to host a `did:web` document can ask an issuer for a credential, which is
/// the correct protocol behaviour and precisely why the table behind it
/// needs a ceiling.
///
/// Red at the time of writing: the table holds every one of the
/// `MAX_TRACKED_REQUESTS + OVERSHOOT` records.
///
/// The second assertion is the guard: the Credential Request Status API must
/// still answer for the request that was just accepted, so eviction has to
/// be oldest-first rather than "drop whatever, we are full".
#[tokio::test]
async fn tracked_credential_requests_do_not_grow_without_bound() {
    let holder = spawn_caller_identity("holder").await;
    let (state, base) = spawn_issuer_service().await;
    let client = reqwest::Client::new();
    let url = format!("{base}/credentials");
    let audience = "did:web:localhost%3A0:issuer-service";

    let mut last_location = String::new();
    for i in 0..(MAX_TRACKED_REQUESTS + OVERSHOOT) {
        let token = bearer_token(&holder, audience);
        let response = post(
            &client,
            &url,
            &token,
            &credential_request_body(&format!("holder-pid-{i}")),
        )
        .await;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::CREATED,
            "a Credential Request from any resolvable party is accepted by design - the finding \
             is what the acceptance leaves behind, not the acceptance itself"
        );
        last_location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("an accepted Credential Request carries a Location header")
            .to_string();
    }

    let tracked = state.requests.lock().expect("requests lock poisoned").len();
    assert!(
        tracked <= MAX_TRACKED_REQUESTS,
        "the Issuer Service's request table must be bounded: after {} accepted Credential \
         Requests it holds {} records, one per request, none of which is ever removed - a \
         lightly-authenticated caller can grow this process's memory without limit (2026-09-20 \
         independent security audit, MEDIUM)",
        MAX_TRACKED_REQUESTS + OVERSHOOT,
        tracked
    );

    // The status of the request accepted moments ago must still be
    // retrievable: a bound that drops the newest record breaks the
    // Credential Request Status API for exactly the requests anyone is
    // actually polling. Green before and after.
    let status_response = client
        .get(format!("{base}{last_location}"))
        .send()
        .await
        .expect("status request completes");
    assert_eq!(
        status_response.status(),
        reqwest::StatusCode::OK,
        "the most recently accepted Credential Request must still be tracked ({last_location})"
    );
}

/// The low-volume guard for the request table, mirroring
/// [`low_volume_traffic_keeps_every_jti`]: a handful of Credential Requests -
/// the scale the real TCK's issuance test package works at - must all stay
/// individually retrievable. Green before and after.
#[tokio::test]
async fn low_volume_credential_requests_are_all_still_tracked() {
    let holder = spawn_caller_identity("holder").await;
    let (state, base) = spawn_issuer_service().await;
    let client = reqwest::Client::new();
    let url = format!("{base}/credentials");
    let audience = "did:web:localhost%3A0:issuer-service";

    let mut locations = Vec::new();
    for i in 0..16 {
        let token = bearer_token(&holder, audience);
        let response = post(
            &client,
            &url,
            &token,
            &credential_request_body(&format!("holder-pid-{i}")),
        )
        .await;
        locations.push(
            response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .expect("an accepted Credential Request carries a Location header")
                .to_string(),
        );
    }

    assert_eq!(
        state.requests.lock().expect("requests lock poisoned").len(),
        16,
        "nothing may be evicted at ordinary volumes"
    );
    // Deduplicated on purpose: every request must have been given its own
    // record, not overwritten one shared slot.
    assert_eq!(
        locations.iter().collect::<HashSet<_>>().len(),
        16,
        "each Credential Request gets its own id"
    );
    for location in &locations {
        let response = client
            .get(format!("{base}{location}"))
            .send()
            .await
            .expect("status request completes");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "every request of a normal-sized run stays retrievable ({location})"
        );
    }
}
