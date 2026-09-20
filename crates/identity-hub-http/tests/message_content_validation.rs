//! TDD coverage for message-content/business-logic validation on the
//! **Storage API** (`POST /credentials`) and the **Credential Offer API**
//! (`POST /offers`) - see `../../ARCHITECTURE.md`'s "What's simplified or
//! stubbed" ("No message-content/business-logic validation...") and
//! `crate::validation`. Six independent gaps, each unrelated to the
//! wrapping Self-Issued ID Token - a genuinely valid, genuinely trusted
//! token is presented in every case below, exactly like the real TCK's own
//! `cs_06_05_01_credentialMessage_invalidBody`/`_invalidStatus`/
//! `cs_06_05_credentialMessage_unknownHolderPid`/
//! `cs_06_05_02_credentialMessage_unverifiableProof`/
//! `cs_06_06_01_credentialOfferMessage_emptyCredentials`/
//! `_sparse_randomIds_expect400` (decompiled from the real
//! `eclipsedataspacetck/dcp-tck-runtime:latest`, not guessed from names
//! alone - see `crate::validation`'s own module doc comment).
//!
//! Written and run *before* any of these checks existed (red: every
//! rejection case below returned `200 OK`), then again after adding each
//! (green). Same real-HTTP, real-ES256, no-TCK/Docker-dependency harness
//! `storage_offer_auth.rs`/`trusted_issuer_allowlist.rs` established.
//!
//! Since the 2026-09-20 fix for the "open write" default posture
//! (`../../ARCHITECTURE.md`, "What's simplified or stubbed";
//! `storage_write_default_posture.rs`), an empty `trusted_issuer_dids`
//! means *no* issuer is trusted, and `check_trusted_issuer` runs (on both
//! `storage_write` and `credential_offer`) before any of the
//! message-content checks this file is actually about ever get a chance to
//! run. So every fixture below now spawns its caller/issuer identity
//! *first* and boots the service explicitly trusting that identity's DID
//! (`storage_offer_auth.rs`'s ordering) - configuring an issuer here is not
//! this file's own subject, it is what makes the Storage/Offer APIs
//! reachable at all so the six content checks can be exercised.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::{CredentialObject, IssuerMetadata};
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const AUD: &str = "did:web:localhost%3A0:credential-service";
const KNOWN_HOLDER_PID: &str = "known-holder-pid";

/// Boots this crate's real Credential Service (the system under test),
/// configured to expect [`KNOWN_HOLDER_PID`] on the Storage API (see
/// `Config::known_holder_pids`) and to trust `trusted_issuer_dids` (see
/// `Config::trusted_issuer_dids`) - since the 2026-09-20 default-posture
/// fix, every caller this file exercises must be explicitly trusted or
/// `check_trusted_issuer` rejects it before any message-content check
/// below ever runs.
async fn spawn_credential_service(trusted_issuer_dids: Vec<String>) -> (Arc<AppState>, String) {
    let config = Config::for_test(
        Mode::CredentialService,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        "localhost:0",
    )
    .with_known_holder_pids(vec![KNOWN_HOLDER_PID.to_string()])
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

/// Same stand-in `did:web` server `storage_offer_auth.rs` uses.
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

/// A stand-in Credential Issuer that hosts both its own `did:web` document
/// (with an `IssuerService` entry) and a real Issuer Metadata API
/// (`GET /metadata`) advertising `known_ids` - what
/// `validate_offer_credentials` resolves a sparse offer's ids against.
async fn spawn_issuer_identity_with_catalog(
    path_segment: &str,
    known_ids: &[&str],
) -> ServiceIdentity {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral loopback port for the stand-in issuer server");
    let addr = listener
        .local_addr()
        .expect("bound listener has a local address");
    let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), path_segment);
    let base_url = format!("http://127.0.0.1:{}", addr.port());
    let doc = identity.did_document(&[("IssuerService", &base_url)]);
    let metadata = IssuerMetadata::new(
        identity.own_did().to_string(),
        known_ids
            .iter()
            .map(|id| CredentialObject {
                context: None,
                id: id.to_string(),
                object_type: "CredentialObject".to_string(),
                credential_type: Some("MembershipCredential".to_string()),
                binding_methods: None,
                credential_schema: None,
                profile: None,
                issuance_policy: None,
                offer_reason: None,
            })
            .collect(),
    );
    let did_route = format!("/{path_segment}/did.json");
    let app = Router::new()
        .route(
            &did_route,
            get(move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/metadata",
            get(move || {
                let metadata = metadata.clone();
                async move { Json(metadata) }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("stand-in issuer server");
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

fn bearer_token(caller: &ServiceIdentity) -> String {
    let now = dcp_core::now_secs();
    sign(
        caller,
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
}

/// A genuinely verifiable JWT-format credential container: signed by
/// `issuer` itself, resolvable and verifiable against `issuer`'s own
/// real `did:web` document.
fn genuine_credential_container(
    credential_type: &str,
    issuer: &ServiceIdentity,
    subject_did: &str,
) -> Value {
    let now = dcp_core::now_secs();
    let vc_payload = json!({
        "iss": issuer.own_did(),
        "sub": subject_did,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", credential_type],
            "credentialSubject": {"id": subject_did},
        },
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let jws = sign(issuer, vc_payload);
    json!({"credentialType": credential_type, "format": "jwt", "payload": jws})
}

/// A forged JWT-format credential container: its payload claims `iss` is
/// `claimed_issuer`, but the signature was produced by a completely
/// different party's key, under a `kid` naming a verification method
/// `claimed_issuer`'s own real DID document never actually lists - mirrors
/// the real TCK's own `cs_06_05_02_credentialMessage_unverifiableProof`
/// (a credential forwarded by a third party, signed with a key that isn't
/// really the claimed issuer's).
fn forged_credential_container(
    credential_type: &str,
    claimed_issuer: &ServiceIdentity,
    actual_signer: &ServiceIdentity,
    subject_did: &str,
) -> Value {
    let now = dcp_core::now_secs();
    let vc_payload = json!({
        "iss": claimed_issuer.own_did(),
        "sub": subject_did,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", credential_type],
            "credentialSubject": {"id": subject_did},
        },
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let bogus_kid = format!("{}#not-a-real-key", claimed_issuer.own_did());
    let jws = dcp_core::sign_jws(
        &vc_payload,
        &actual_signer.key_pair.signing_key(),
        &bogus_kid,
    );
    json!({"credentialType": credential_type, "format": "jwt", "payload": jws})
}

fn credential_message_body(holder_pid: &str, status: &str, credentials: Vec<Value>) -> Value {
    json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialMessage",
        "issuerPid": "issuer-pid-1",
        "holderPid": holder_pid,
        "status": status,
        "credentials": credentials,
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

// ---- 1. CredentialMessage schema presence (@context/type/issuerPid/holderPid/status) ----

#[tokio::test]
async fn storage_write_rejects_a_credential_message_missing_a_required_field() {
    let caller = spawn_caller_identity("issuer").await;
    let (_state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    for missing in ["@context", "type", "issuerPid", "holderPid", "status"] {
        let mut body = credential_message_body(KNOWN_HOLDER_PID, "ISSUED", vec![]);
        body.as_object_mut().unwrap().remove(missing);
        let response = post(&format!("{base}/credentials"), &token, &body)
            .await
            .expect("request completes");
        assert!(
            response.status().is_client_error(),
            "expected a 4xx for a CredentialMessage missing '{missing}' but got {}",
            response.status()
        );
    }
}

// ---- 2. status enum validation ----

#[tokio::test]
async fn storage_write_rejects_an_invalid_status_value() {
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    let body = credential_message_body(KNOWN_HOLDER_PID, "INVALID_STATUS", vec![]);
    let response = post(&format!("{base}/credentials"), &token, &body)
        .await
        .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_accepts_the_recognized_status_values() {
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    for status in ["ISSUED", "REJECTED"] {
        let token = bearer_token(&caller);
        let body = credential_message_body(KNOWN_HOLDER_PID, status, vec![]);
        let response = post(&format!("{base}/credentials"), &token, &body)
            .await
            .expect("request completes");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
    assert_eq!(state.store.all().len(), 2);
}

// ---- 3. known holderPid ----

#[tokio::test]
async fn storage_write_rejects_an_unknown_holder_pid() {
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    let body = credential_message_body("some-other-holder-pid", "ISSUED", vec![]);
    let response = post(&format!("{base}/credentials"), &token, &body)
        .await
        .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_accepts_a_known_holder_pid() {
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    let body = credential_message_body(KNOWN_HOLDER_PID, "ISSUED", vec![]);
    let response = post(&format!("{base}/credentials"), &token, &body)
        .await
        .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(state.store.all().len(), 1);
}

// ---- 4. embedded credential proof verification ----

#[tokio::test]
async fn storage_write_rejects_a_credential_with_an_unverifiable_proof() {
    let caller = spawn_caller_identity("issuer").await;
    let attacker = spawn_caller_identity("attacker").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    let forged = forged_credential_container(
        "MembershipCredential",
        &caller,
        &attacker,
        "did:web:localhost%3A0:holder",
    );
    let body = credential_message_body(KNOWN_HOLDER_PID, "ISSUED", vec![forged]);
    let response = post(&format!("{base}/credentials"), &token, &body)
        .await
        .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(state.store.all().is_empty());
}

#[tokio::test]
async fn storage_write_accepts_credentials_with_genuinely_verifiable_proofs() {
    let caller = spawn_caller_identity("issuer").await;
    let (state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    let genuine = genuine_credential_container(
        "MembershipCredential",
        &caller,
        "did:web:localhost%3A0:holder",
    );
    let body = credential_message_body(KNOWN_HOLDER_PID, "ISSUED", vec![genuine]);
    let response = post(&format!("{base}/credentials"), &token, &body)
        .await
        .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(state.store.all().len(), 1);
}

// ---- 5. Credential Offer API: non-empty credentials ----

fn full_offer_body(issuer_did: &str) -> Value {
    json!({
        "issuer": issuer_did,
        "credentials": [
            {"id": uuid::Uuid::new_v4().to_string(), "type": "CredentialObject", "credentialType": "MembershipCredential"}
        ],
    })
}

fn empty_offer_body(issuer_did: &str) -> Value {
    json!({
        "issuer": issuer_did,
        "credentials": [],
    })
}

fn sparse_offer_body(issuer_did: &str, ids: &[&str]) -> Value {
    json!({
        "issuer": issuer_did,
        "credentials": ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>(),
    })
}

#[tokio::test]
async fn credential_offer_rejects_an_empty_credentials_array() {
    let caller = spawn_caller_identity("issuer").await;
    let (_state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    let response = post(
        &format!("{base}/offers"),
        &token,
        &empty_offer_body(caller.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn credential_offer_accepts_a_full_credential_object_without_a_catalog_lookup() {
    // Regression guard: a full (non-sparse) CredentialObject is
    // self-describing and must not require - or be rejected for lacking -
    // a resolvable catalog, even when its id is made up.
    let caller = spawn_caller_identity("issuer").await;
    let (_state, base) = spawn_credential_service(vec![caller.own_did().to_string()]).await;
    let token = bearer_token(&caller);
    let response = post(
        &format!("{base}/offers"),
        &token,
        &full_offer_body(caller.own_did()),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

// ---- 6. Credential Offer API: sparse ids checked against the issuer's own catalog ----

#[tokio::test]
async fn credential_offer_rejects_a_sparse_offer_with_unrecognized_ids() {
    let issuer = spawn_issuer_identity_with_catalog("issuer", &["real-credential-id"]).await;
    let (_state, base) = spawn_credential_service(vec![issuer.own_did().to_string()]).await;
    let token = bearer_token(&issuer);
    let response = post(
        &format!("{base}/offers"),
        &token,
        &sparse_offer_body(issuer.own_did(), &["totally-unknown-id"]),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn credential_offer_accepts_a_sparse_offer_with_catalog_known_ids() {
    let issuer = spawn_issuer_identity_with_catalog("issuer", &["real-credential-id"]).await;
    let (_state, base) = spawn_credential_service(vec![issuer.own_did().to_string()]).await;
    let token = bearer_token(&issuer);
    let response = post(
        &format!("{base}/offers"),
        &token,
        &sparse_offer_body(issuer.own_did(), &["real-credential-id"]),
    )
    .await
    .expect("request completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}
