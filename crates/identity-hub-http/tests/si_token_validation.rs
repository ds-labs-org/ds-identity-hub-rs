//! TDD coverage for the four Self-Issued ID Token validation checks
//! `crate::auth::verify_bearer_token` did not previously implement (see
//! `../../ARCHITECTURE.md`, "Self-Issued ID Token validation is
//! intentionally partial"): `iss == sub` equality, `nbf` (not-before)
//! leeway, the `capabilityInvocation` verification-relationship
//! restriction on the signing key, and `jti` replay protection.
//!
//! Written and run *before* any of the four checks existed: every
//! rejection case below returned `200 OK` against the then-partial
//! `verify_bearer_token` (confirmed red), then again after adding each
//! check (green). Follows the exact same real-HTTP-round-trip pattern
//! `storage_offer_auth.rs` established (real `did:web` resolution, real
//! ES256 signatures, no TCK/Docker dependency) - see that file's module
//! doc comment for the full rationale, unchanged here.
//!
//! Since the 2026-09-20 fix for the "open write" default posture
//! (`../../ARCHITECTURE.md`, "What's simplified or stubbed";
//! `storage_write_default_posture.rs`), an empty `trusted_issuer_dids`
//! means *no* issuer is trusted - so `spawn_credential_service` now takes
//! the allow-list to boot with explicitly. The rejection cases below still
//! pass an empty list (each fails inside `verify_bearer_token` itself,
//! before `check_trusted_issuer` is ever reached); the "accepts"/regression
//! guards spawn the caller identity first and boot the service trusting
//! that caller's DID (`storage_offer_auth.rs`'s ordering).

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
/// ephemeral loopback port - identical to `storage_offer_auth.rs`'s helper
/// of the same shape.
async fn spawn_credential_service(trusted_issuer_dids: Vec<String>) -> (Arc<AppState>, String) {
    let config = Config::for_test(
        Mode::CredentialService,
        SocketAddr::from(([127, 0, 0, 1], 0)),
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
/// identity's `did:web` document, optionally rewriting the served document
/// (`doc_transform`) before serving it - used to build a document whose
/// `capabilityInvocation` array deliberately omits the signing key, which
/// `ServiceIdentity::did_document` itself never does.
async fn spawn_caller_identity_with_doc(
    path_segment: &str,
    doc_transform: impl FnOnce(Value) -> Value,
) -> ServiceIdentity {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the stand-in DID server");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), path_segment);
    let doc = doc_transform(identity.did_document(&[]));
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

async fn spawn_caller_identity(path_segment: &str) -> ServiceIdentity {
    spawn_caller_identity_with_doc(path_segment, |doc| doc).await
}

fn sign(caller: &ServiceIdentity, payload: Value) -> String {
    dcp_core::sign_jws(
        &payload,
        &caller.key_pair.signing_key(),
        caller.own_key_id(),
    )
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

async fn post(url: &str, bearer: &str, body: &Value) -> reqwest::Result<reqwest::Response> {
    reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {bearer}"))
        .json(body)
        .send()
        .await
}

const AUD: &str = "did:web:localhost%3A0:credential-service";

// ---- iss == sub ----

#[tokio::test]
async fn storage_write_rejects_token_whose_sub_does_not_match_iss() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let now = dcp_core::now_secs();
    // A well-formed, correctly-signed, correctly-audienced token - the only
    // thing wrong with it is that `sub` names someone other than the actual
    // signer (`iss`). Per base.protocol.md, a Self-Issued ID Token's `sub`
    // must equal its own `iss`; this must be rejected even though the
    // signature itself is completely valid.
    let payload = json!({
        "iss": caller.own_did(),
        "sub": "did:web:someone-else%3A1:not-the-caller",
        "aud": AUD,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        state.store.all().is_empty(),
        "a token with sub != iss must never reach the store"
    );
}

#[tokio::test]
async fn storage_write_rejects_token_with_no_sub_claim_at_all() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let now = dcp_core::now_secs();
    let payload = json!({
        "iss": caller.own_did(),
        "aud": AUD,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

// ---- nbf ----

#[tokio::test]
async fn storage_write_rejects_token_not_yet_valid() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let now = dcp_core::now_secs();
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": AUD,
        "iat": now,
        "nbf": now + 3600, // an hour in the future
        "exp": now + 7200,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

// ---- iat ----

#[tokio::test]
async fn storage_write_rejects_token_with_iat_in_the_future() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    let caller = spawn_caller_identity("issuer").await;
    let now = dcp_core::now_secs();
    // Otherwise entirely well-formed (iss==sub, nbf valid, not expired) -
    // the only thing wrong is `iat` claiming the token was issued an hour
    // from now, which a correctly-clocked signer could never produce.
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": AUD,
        "iat": now + 3600, // an hour in the future
        "nbf": now,
        "exp": now + 7200,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        state.store.all().is_empty(),
        "a token with iat in the future must never reach the store"
    );
}

#[tokio::test]
async fn storage_write_accepts_a_token_with_iat_within_clock_skew_leeway() {
    // Regression guard: the same clock-skew leeway nbf already tolerates
    // must also apply to iat, so an ordinary, legitimately-clocked caller a
    // few seconds ahead of this process is not rejected.
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let now = dcp_core::now_secs();
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": AUD,
        "iat": now + 5,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(state.store.all().len(), 1);
}

// ---- capabilityInvocation ----

#[tokio::test]
async fn storage_write_rejects_a_key_not_listed_under_capability_invocation() {
    let (state, base) = spawn_credential_service(Vec::new()).await;
    // A caller whose DID document has a real, otherwise-valid
    // verificationMethod (the signature genuinely verifies against it), but
    // that key is deliberately absent from capabilityInvocation - the DCP
    // spec's own restriction on which key may sign a Self-Issued ID Token
    // (base.protocol.md, "Validating Self-Issued ID Tokens", step 3).
    let caller = spawn_caller_identity_with_doc("issuer", |mut doc| {
        doc["capabilityInvocation"] = json!([]);
        doc
    })
    .await;
    let now = dcp_core::now_secs();
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": AUD,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_accepts_a_key_that_is_listed_under_capability_invocation() {
    // Regression guard: ServiceIdentity::did_document always lists its own
    // key under capabilityInvocation, so the ordinary, legitimate path must
    // keep working once this check exists.
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let now = dcp_core::now_secs();
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": AUD,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = sign(&caller, payload);
    let response = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(state.store.all().len(), 1);
}

// ---- jti replay ----

#[tokio::test]
async fn storage_write_rejects_a_reused_jti() {
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let now = dcp_core::now_secs();
    let jti = uuid::Uuid::new_v4().to_string();
    let payload = json!({
        "iss": caller.own_did(),
        "sub": caller.own_did(),
        "aud": AUD,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": jti,
    });
    let token = sign(&caller, payload);

    let first = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("first request completes");
    assert_eq!(
        first.status(),
        reqwest::StatusCode::OK,
        "the first use of a fresh jti must be accepted"
    );

    // Replay the exact same token (same jti) a second time.
    let second = post(
        &format!("{base}/credentials"),
        &token,
        &credential_message_body(),
    )
    .await
    .expect("second request completes");
    assert_eq!(
        second.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "reusing the same jti must be rejected"
    );
    assert_eq!(
        state.store.all().len(),
        1,
        "the replayed call must not have written a second time"
    );
}

#[tokio::test]
async fn storage_write_accepts_two_calls_with_distinct_jtis() {
    // Regression guard: jti tracking must key on the jti value itself, not
    // reject a second call from the same caller outright.
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let now = dcp_core::now_secs();
    let make_token = || {
        sign(
            &caller,
            json!({
                "iss": caller.own_did(),
                "sub": caller.own_did(),
                "aud": AUD,
                "iat": now,
                "nbf": now,
                "exp": now + 300,
                "jti": uuid::Uuid::new_v4().to_string(),
            }),
        )
    };

    let first = post(
        &format!("{base}/credentials"),
        &make_token(),
        &credential_message_body(),
    )
    .await
    .expect("first request completes");
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let second = post(
        &format!("{base}/credentials"),
        &make_token(),
        &credential_message_body(),
    )
    .await
    .expect("second request completes");
    assert_eq!(second.status(), reqwest::StatusCode::OK);
    assert_eq!(state.store.all().len(), 2);
}
