//! TDD coverage for real per-request authorization on the **Storage API**
//! (`POST /credentials` on a Credential Service) and the **Credential
//! Offer API** (`POST /offers`) - see `../../ARCHITECTURE.md`, "What's
//! simplified or stubbed" and `crate::auth` (`verify_bearer_token`), which
//! these two endpoints now reuse rather than duplicate.
//!
//! Written and run *before* `storage_write`/`credential_offer` validated
//! anything (red: every rejection case below returned `200 OK` against the
//! then-unauthenticated handlers), then again after wiring in
//! `verify_bearer_token` (green). See `../../ARCHITECTURE.md`'s
//! "Provenance"/"DCP TCK conformance snapshot" sections for the real,
//! measured TCK-level effect of this change - this file only proves the
//! HTTP-layer behavior in isolation, with real (not mocked) `did:web`
//! resolution and real ES256 signatures, but no TCK/Docker dependency.
//!
//! Each test boots two real, independent HTTP servers on ephemeral loopback
//! ports: this crate's own Credential Service (the system under test) and a
//! tiny stand-in server hosting one synthetic caller identity's `did:web`
//! document, so `verify_bearer_token`'s DID resolution is a genuine HTTP
//! round trip, not a mock.
//!
//! Since the 2026-09-20 fix for the "open write" default posture
//! (`../../ARCHITECTURE.md`, "What's simplified or stubbed";
//! `storage_write_default_posture.rs`), an empty `trusted_issuer_dids`
//! means *no* issuer is trusted, not "no restriction configured" - so
//! `spawn_credential_service` now takes the allow-list to boot with
//! explicitly. Every rejection case below still passes an empty list: each
//! one fails inside `verify_bearer_token` itself (missing/malformed
//! header, expired token, wrong audience, bad signature), which runs
//! *before* `check_trusted_issuer` is ever reached, so this file's
//! rejection coverage is unaffected by that change. Only the two "genuinely
//! valid token" regression guards - which must still get `200 OK` - spawn
//! the caller identity first (this file's version of
//! `trusted_issuer_allowlist.rs`'s ordering) and boot the service trusting
//! that caller's DID.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// Boots this crate's real Credential Service (the system under test) on an
/// ephemeral loopback port, with `trusted_issuer_dids` configured as given.
/// Returns its shared state (so a test can inspect `store.all()` to confirm
/// a rejected write never landed) and the base URL to send requests to.
async fn spawn_credential_service(trusted_issuer_dids: Vec<String>) -> (Arc<AppState>, String) {
    let config = Config::for_test(
        Mode::CredentialService,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        // Never resolved by any test here - no test exercises this
        // service's *own* DID document, only the caller-authorization path.
        "localhost:0",
    )
    .with_trusted_issuer_dids(trusted_issuer_dids);
    let (state, router) = identity_hub_http::build(config);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the credential service under test");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("credential service under test");
    });
    (state, format!("http://{addr}"))
}

/// Boots a tiny, real HTTP server hosting exactly one synthetic caller
/// identity's `did:web` document - a stand-in for a real counterparty (an
/// Issuer, delivering a credential, or a Credential Issuer sending an
/// offer, in the real DCP flow) whose Self-Issued ID Token
/// `verify_bearer_token` must resolve for real. The identity's own DID
/// necessarily embeds the port, so it's built only after the listener is
/// already bound.
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

/// Signs `payload` as `caller`, producing a compact JWS exactly like a real
/// Self-Issued ID Token - reusing `dcp_core::sign_jws`, the same function
/// `identity_hub_http::handlers` itself signs with.
fn sign(caller: &ServiceIdentity, payload: Value) -> String {
    dcp_core::sign_jws(
        &payload,
        &caller.key_pair.signing_key(),
        caller.own_key_id(),
    )
}

fn valid_payload(caller: &ServiceIdentity, aud: &str) -> Value {
    let now = dcp_core::now_secs();
    json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": aud,
        "iat": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    })
}

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

fn credential_offer_body(issuer_did: &str) -> Value {
    json!({
        "issuer": issuer_did,
        // A full (non-sparse) CredentialObject - this file exercises
        // authorization, not `crate::validation`'s own content checks (see
        // message_content_validation.rs for those), so a self-describing
        // entry avoids this fixture depending on a resolvable catalog.
        "credentials": [
            {"id": "test-credential", "type": "CredentialObject", "credentialType": "MembershipCredential"}
        ],
    })
}

async fn post(url: &str, bearer: Option<&str>, body: &Value) -> reqwest::Result<reqwest::Response> {
    let client = reqwest::Client::new();
    let mut request = client.post(url).json(body);
    if let Some(token) = bearer {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    request.send().await
}

/// Same as [`post`], but sets the raw `Authorization` header value verbatim
/// (no `"Bearer "` prefix added) - for the "missing bearer prefix" and "no
/// header at all" cases.
async fn post_raw_auth(
    url: &str,
    raw_auth: Option<&str>,
    body: &Value,
) -> reqwest::Result<reqwest::Response> {
    let client = reqwest::Client::new();
    let mut request = client.post(url).json(body);
    if let Some(value) = raw_auth {
        request = request.header("Authorization", value);
    }
    request.send().await
}

// ---- Storage API (`POST /credentials`) ----

#[tokio::test]
async fn storage_write_rejects_missing_auth_header() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let response = post_raw_auth(
        &format!("{base}/credentials"),
        None,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        state.store.all().is_empty(),
        "an unauthenticated write must never reach the store"
    );
}

#[tokio::test]
async fn storage_write_rejects_token_missing_bearer_prefix() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let token = sign(
        &caller,
        valid_payload(&caller, "did:web:localhost%3A0:credential-service"),
    );
    // The raw JWT, deliberately with no "Bearer " prefix.
    let response = post_raw_auth(
        &format!("{base}/credentials"),
        Some(&token),
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_rejects_malformed_token() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let response = post(
        &format!("{base}/credentials"),
        Some("not-a-real-jws-at-all"),
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_rejects_expired_token() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let now = dcp_core::now_secs();
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": "did:web:localhost%3A0:credential-service",
        "iat": now - 1000,
        "exp": now - 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        Some(&token),
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_rejects_wrong_audience() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let token = sign(
        &caller,
        valid_payload(&caller, "did:web:someone-else%3A9999:not-this-service"),
    );
    let response = post(
        &format!("{base}/credentials"),
        Some(&token),
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_rejects_invalid_signature() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    // A completely different identity's key, but claiming to be `caller`
    // (same `iss`/`kid`) - the DID resolves to `caller`'s *real* public
    // key, which will not verify a signature made with this other key.
    let wrong_key_holder = ServiceIdentity::new("attacker-host:1", "attacker");
    let mut payload = valid_payload(&caller, "did:web:localhost%3A0:credential-service");
    let unsigned_header_kid = caller.own_key_id().to_string();
    payload["iss"] = json!(caller.own_did());
    let token = dcp_core::sign_jws(
        &payload,
        &wrong_key_holder.key_pair.signing_key(),
        &unsigned_header_kid,
    );
    let response = post(
        &format!("{base}/credentials"),
        Some(&token),
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_accepts_a_genuinely_valid_token() {
    // Regression guard: real authorization must not break the legitimate
    // flow the real dcp-tck's own Credential-Service setup phase depends
    // on (see ../../ARCHITECTURE.md's "What's simplified or stubbed").
    // Caller identity spawned first so the service can be booted trusting
    // its DID explicitly - see this file's module doc comment.
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = sign(
        &caller,
        valid_payload(&caller, "did:web:localhost%3A0:credential-service"),
    );
    let response = post(
        &format!("{base}/credentials"),
        Some(&token),
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(state.store.all().len(), 1);
}

// ---- Credential Offer API (`POST /offers`) ----

#[tokio::test]
async fn credential_offer_rejects_missing_auth_header() {
    let (_state, base) = spawn_credential_service(Vec::new()).await;
    let response = post_raw_auth(
        &format!("{base}/offers"),
        None,
        &credential_offer_body("did:web:localhost%3A0:issuer"),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_offer_rejects_token_missing_bearer_prefix() {
    let (_state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let token = sign(
        &caller,
        valid_payload(&caller, "did:web:localhost%3A0:credential-service"),
    );
    let response = post_raw_auth(
        &format!("{base}/offers"),
        Some(&token),
        &credential_offer_body(caller.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_offer_rejects_malformed_token() {
    let (_state, base) = spawn_credential_service(Vec::new()).await;
    let response = post(
        &format!("{base}/offers"),
        Some("garbage.not.jws"),
        &credential_offer_body("did:web:localhost%3A0:issuer"),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_offer_rejects_expired_token() {
    let (_state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let now = dcp_core::now_secs();
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": "did:web:localhost%3A0:credential-service",
        "iat": now - 1000,
        "exp": now - 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/offers"),
        Some(&token),
        &credential_offer_body(caller.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_offer_rejects_wrong_audience() {
    let (_state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let token = sign(
        &caller,
        valid_payload(&caller, "did:web:someone-else%3A9999:not-this-service"),
    );
    let response = post(
        &format!("{base}/offers"),
        Some(&token),
        &credential_offer_body(caller.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_offer_rejects_invalid_signature() {
    let (_state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let wrong_key_holder = ServiceIdentity::new("attacker-host:1", "attacker");
    let payload = valid_payload(&caller, "did:web:localhost%3A0:credential-service");
    let token = dcp_core::sign_jws(
        &payload,
        &wrong_key_holder.key_pair.signing_key(),
        caller.own_key_id(),
    );
    let response = post(
        &format!("{base}/offers"),
        Some(&token),
        &credential_offer_body(caller.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_offer_accepts_a_genuinely_valid_token() {
    // Caller identity spawned first so the service can be booted trusting
    // its DID explicitly - see this file's module doc comment.
    let caller = spawn_caller_identity("issuer").await;
    let (_state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = sign(
        &caller,
        valid_payload(&caller, "did:web:localhost%3A0:credential-service"),
    );
    let response = post(
        &format!("{base}/offers"),
        Some(&token),
        &credential_offer_body(caller.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}
