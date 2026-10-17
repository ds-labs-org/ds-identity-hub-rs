//! 2026-10-16 project audit, finding E2 (HIGH): the Storage API checked
//! that the *deliverer* is a trusted issuer and that each credential's own
//! signature verifies, but not what the credential says. A trusted issuer
//! could store a VC signed by an untrusted DID, already expired, or bound
//! to somebody else, and the Presentation API then handed out every stored
//! credential of the requested type, expired ones and duplicates included.
//!
//! Now each delivered credential must come from a trusted issuer, be bound
//! to this Credential Service's own DID and be inside its validity window;
//! and a presentation leaves out expired credentials and repeats.
//!
//! Real HTTP on loopback: the parties host genuine `did:web` documents and
//! sign genuine ES256 tokens and credentials.

use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use dcp_core::{decode_jws_unverified, now_secs, sign_jws};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::CredentialContainer;
use identity_hub_core::store::StoredCredentialBatch;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";

/// A party with a real `did:web` document on 127.0.0.1.
async fn spawn_party(segment: &str) -> ServiceIdentity {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), segment);
    let doc = identity.did_document(&[]);
    let app = Router::new().route(
        &format!("/{segment}/did.json"),
        get(move || {
            let doc = doc.clone();
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    identity
}

async fn spawn_credential_service(trusted: &ServiceIdentity) -> (Arc<AppState>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Config::for_test(
        Mode::CredentialService,
        addr,
        format!("127.0.0.1:{}", addr.port()),
    )
    .with_trusted_issuer_dids(vec![trusted.own_did().to_string()]);
    let (state, router) = identity_hub_http::build(config);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (state, format!("http://{addr}"))
}

/// A MembershipCredential JWT signed by `issuer`, bound to `subject`, with
/// `exp` relative to now.
fn vc(issuer: &ServiceIdentity, subject: &str, exp_from_now: i64) -> String {
    let now = now_secs() as i64;
    sign_jws(
        &json!({
            "iss": issuer.own_did(),
            "sub": subject,
            "iat": now - 60,
            "nbf": now - 60,
            "exp": now + exp_from_now,
            "jti": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "MembershipCredential"],
                "issuer": issuer.own_did(),
                "credentialSubject": {"id": subject},
            },
        }),
        &issuer.key_pair.signing_key(),
        issuer.own_key_id(),
    )
}

/// `deliverer` sends a `CredentialMessage` carrying `payload` to the
/// Storage API.
async fn deliver(base: &str, service_did: &str, deliverer: &ServiceIdentity, payload: &str) -> u16 {
    let now = now_secs();
    let token = sign_jws(
        &json!({
            "iss": deliverer.own_did(), "sub": deliverer.own_did(), "aud": service_did,
            "iat": now, "nbf": now, "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
        &deliverer.key_pair.signing_key(),
        deliverer.own_key_id(),
    );
    reqwest::Client::new()
        .post(format!("{base}/credentials"))
        .bearer_auth(token)
        .json(&json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "CredentialMessage",
            "issuerPid": "issuer-pid", "holderPid": "holder-pid", "status": "ISSUED",
            "credentials": [{"credentialType": "MembershipCredential", "payload": payload, "format": "jwt"}],
        }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn the_storage_api_refuses_credentials_it_should_not_hold() {
    let issuer = spawn_party("issuer").await;
    let rogue = spawn_party("rogue").await;
    let (state, base) = spawn_credential_service(&issuer).await;
    let me = state.identity.own_did().to_string();

    for (case, payload) in [
        ("signed by an untrusted issuer", vc(&rogue, &me, 3600)),
        ("already expired", vc(&issuer, &me, -3600)),
        (
            "bound to another holder",
            vc(&issuer, "did:web:somebody-else.example", 3600),
        ),
    ] {
        assert_eq!(
            deliver(&base, &me, &issuer, &payload).await,
            400,
            "a credential {case} was stored"
        );
    }
    assert!(
        state
            .store
            .credentials_of_types(&["MembershipCredential".into()])
            .is_empty(),
        "nothing was stored"
    );

    assert_eq!(
        deliver(&base, &me, &issuer, &vc(&issuer, &me, 3600)).await,
        200,
        "a valid credential is still stored"
    );
}

/// Credentials already in the store (stored before this check existed, or
/// expired since) are not presented once expired, and a credential stored
/// twice is presented once.
#[tokio::test]
async fn a_presentation_leaves_out_expired_and_repeated_credentials() {
    let issuer = spawn_party("issuer").await;
    let (state, base) = spawn_credential_service(&issuer).await;
    let me = state.identity.own_did().to_string();
    let valid = vc(&issuer, &me, 3600);
    let expired = vc(&issuer, &me, -3600);
    let container = |payload: &str| CredentialContainer {
        credential_type: "MembershipCredential".into(),
        payload: json!(payload),
        format: "jwt".into(),
    };
    state.store.store(StoredCredentialBatch {
        issuer_pid: "issuer-pid".into(),
        holder_pid: Some("holder-pid".into()),
        status: "ISSUED".into(),
        rejection_reason: None,
        credentials: vec![container(&valid), container(&expired), container(&valid)],
    });

    let client = reqwest::Client::new();
    let sts: Value = client
        .post(format!("{base}/sts/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", state.config.sts_client_id.as_str()),
            ("client_secret", state.config.sts_client_secret.as_str()),
            ("audience", me.as_str()),
            ("bearer_access_scope", MEMBERSHIP_SCOPE),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let response = client
        .post(format!("{base}/presentations/query"))
        .bearer_auth(sts["access_token"].as_str().expect("STS token"))
        .json(&json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "PresentationQueryMessage",
            "scope": [MEMBERSHIP_SCOPE],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let (_, _, vp) = decode_jws_unverified(body["presentation"][0].as_str().unwrap()).unwrap();
    assert_eq!(
        vp["vp"]["verifiableCredential"],
        json!([valid]),
        "only the valid credential, once"
    );
}
