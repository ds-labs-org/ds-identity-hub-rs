//! TDD coverage for the trusted-issuer allow-list check on the **Storage
//! API** (`POST /credentials`) and the **Credential Offer API**
//! (`POST /offers`) - see `../../ARCHITECTURE.md`, "What's simplified or
//! stubbed" ("No 'trusted issuer' allow-list check") and
//! `crate::auth::check_trusted_issuer`.
//!
//! Before this check existed, `verify_bearer_token` accepted any caller
//! whose Self-Issued ID Token was otherwise perfectly valid (correctly
//! self-signed, `iss == sub`, real `capabilityInvocation`) regardless of
//! *who* that caller was - so a real, resolvable, but otherwise-unrelated
//! third party could deliver a `CredentialMessage`/`CredentialOfferMessage`
//! exactly as if it were the issuer this service actually expected one
//! from. This is a distinct step from signature verification (DCP's own
//! "Verify Trust" step) - see the real TCK's own
//! `CredentialIssuanceTest.cs_06_05_01_credentialMessage_untrustedIssuer`
//! (decompiled from `eclipsedataspacetck/dcp-tck-runtime:latest`, not
//! guessed from the name): it signs a perfectly valid outer envelope
//! (`iss == sub == thirdPartyDid`, a real, resolvable `did:web` with its own
//! genuine `capabilityInvocation`) and expects a `4xx` anyway, purely
//! because `thirdPartyDid` is not the DID the Credential Service was
//! configured to trust as its issuer (`this.issuerDid`, injected via the
//! TCK's own `dataspacetck.did.issuer` SUT-configuration property -
//! `BaseAssembly::parseDid`/`getIssuerDid`).
//!
//! Written and run *before* `Config::trusted_issuer_dids` was enforced
//! anywhere (red: `storage_write_rejects_a_token_from_an_untrusted_issuer`
//! got back `200 OK`), then again after wiring
//! `auth::check_trusted_issuer` into `storage_write`/`credential_offer`
//! (green). Same real-HTTP, real-ES256, no-TCK/Docker-dependency harness
//! `storage_offer_auth.rs` established.

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
/// An empty allow-list reproduces `storage_offer_auth.rs`'s permissive
/// default (no restriction configured) - this file only ever passes a
/// non-empty list, to exercise the allow-list itself.
async fn spawn_credential_service_trusting(
    trusted_issuer_dids: Vec<String>,
) -> (Arc<AppState>, String) {
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

/// Same stand-in `did:web` server `storage_offer_auth.rs` uses - a distinct
/// call per identity, since the allow-list must distinguish two otherwise
/// equally well-formed callers by DID alone.
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
        "issuerPid": "issuer-pid-1",
        "holderPid": "holder-pid-1",
        "status": "ISSUED",
        "credentials": [],
    })
}

fn credential_offer_body(issuer_did: &str) -> Value {
    json!({
        "issuer": issuer_did,
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

// ---- Storage API (`POST /credentials`) ----

#[tokio::test]
async fn storage_write_rejects_a_token_from_an_untrusted_issuer() {
    let trusted = spawn_caller_identity("issuer").await;
    let untrusted = spawn_caller_identity("third-party").await;
    let (state, base) =
        spawn_credential_service_trusting(vec![trusted.own_did().to_string()]).await;
    let token = sign(
        &untrusted,
        valid_payload(&untrusted, "did:web:localhost%3A0:credential-service"),
    );
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
        "a write from an untrusted issuer must never reach the store, even with an otherwise-genuine token"
    );
}

#[tokio::test]
async fn storage_write_accepts_a_token_from_a_trusted_issuer() {
    let trusted = spawn_caller_identity("issuer").await;
    let (state, base) =
        spawn_credential_service_trusting(vec![trusted.own_did().to_string()]).await;
    let token = sign(
        &trusted,
        valid_payload(&trusted, "did:web:localhost%3A0:credential-service"),
    );
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

// ---- Credential Offer API (`POST /offers`) ----

#[tokio::test]
async fn credential_offer_rejects_a_token_from_an_untrusted_issuer() {
    let trusted = spawn_caller_identity("issuer").await;
    let untrusted = spawn_caller_identity("third-party").await;
    let (_state, base) =
        spawn_credential_service_trusting(vec![trusted.own_did().to_string()]).await;
    let token = sign(
        &untrusted,
        valid_payload(&untrusted, "did:web:localhost%3A0:credential-service"),
    );
    let response = post(
        &format!("{base}/offers"),
        &token,
        &credential_offer_body(untrusted.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_offer_accepts_a_token_from_a_trusted_issuer() {
    let trusted = spawn_caller_identity("issuer").await;
    let (_state, base) =
        spawn_credential_service_trusting(vec![trusted.own_did().to_string()]).await;
    let token = sign(
        &trusted,
        valid_payload(&trusted, "did:web:localhost%3A0:credential-service"),
    );
    let response = post(
        &format!("{base}/offers"),
        &token,
        &credential_offer_body(trusted.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}
