//! The "Verify Trust" step backed by the dataspace's trusted issuers
//! registry (`ds-trusted-issuers-registry-rs`) instead of the static
//! `--trusted-issuer-did` list: the Credential Service fetches the
//! registry's signed snapshot, verifies it against the registry's own
//! `did:web` document, and trusts an issuer only for the credential types
//! its accreditation chain covers - both the caller delivering a
//! `CredentialMessage`/`CredentialOfferMessage` and each delivered
//! credential's own `iss`. See `crate::registry_trust`.
//!
//! Same real-HTTP, real-ES256 harness as `message_content_validation.rs`,
//! with a stand-in registry (its DID document and `GET /v1/snapshot`,
//! signed with `trusted_issuers_core::sign_snapshot`, the registry's own
//! signing code). Identities live on `localhost`, not `127.0.0.1`: the
//! registry refuses IP addresses in `did:web` ids.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::routing::get;
use axum::{Json, Router};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use trusted_issuers_core::{IssuerRecord, Registry, Role, Status};

const AUD: &str = "did:web:localhost%3A0:credential-service";
const HOLDER_PID: &str = "holder-pid-1";
const ROOT: &str = "did:web:authority.example";

async fn serve(app: Router) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    port
}

/// A party with a resolvable `did:web:localhost%3A<port>:<segment>`.
async fn spawn_identity(segment: &str) -> ServiceIdentity {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let identity = ServiceIdentity::new(&format!("localhost:{port}"), segment);
    let doc = identity.did_document(&[]);
    let app = Router::new().route(
        &format!("/{segment}/did.json"),
        get(move || {
            let doc = doc.clone();
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    identity
}

/// A stand-in registry: its DID document and a snapshot of `registry`
/// signed at request time - by its own key, or by `forger` when set.
struct StandInRegistry {
    base_url: String,
    did: String,
    registry: Arc<Mutex<Registry>>,
    forger: Arc<Mutex<Option<ServiceIdentity>>>,
}

async fn spawn_registry(registry: Registry) -> StandInRegistry {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    let identity = Arc::new(ServiceIdentity::new(
        &format!("localhost:{port}"),
        "registry",
    ));
    let registry = Arc::new(Mutex::new(registry));
    let forger: Arc<Mutex<Option<ServiceIdentity>>> = Arc::new(Mutex::new(None));
    let doc = identity.did_document(&[]);
    let app = Router::new()
        .route(
            "/registry/did.json",
            get(move || {
                let doc = doc.clone();
                async move { Json(doc) }
            }),
        )
        .route(
            "/v1/snapshot",
            get({
                let (identity, registry, forger) =
                    (identity.clone(), registry.clone(), forger.clone());
                move || {
                    let mut key = identity.key_pair.clone();
                    if let Some(f) = forger.lock().unwrap().as_ref() {
                        // Same kid, someone else's key.
                        key = dcp_core::DcpKeyPair {
                            own_did: key.own_did.clone(),
                            own_key_id: key.own_key_id.clone(),
                            ..f.key_pair.clone()
                        };
                    }
                    let token = trusted_issuers_core::sign_snapshot(
                        &registry.lock().unwrap(),
                        &key,
                        dcp_core::now_secs(),
                        600,
                    );
                    async move { token }
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    StandInRegistry {
        base_url: format!("http://localhost:{port}"),
        did: identity.own_did().to_string(),
        registry,
        forger,
    }
}

fn record(id: &str, role: Role, types: &[&str], by: Option<&str>) -> IssuerRecord {
    IssuerRecord {
        id: id.into(),
        role,
        name: None,
        credential_types: types.iter().map(|t| t.to_string()).collect(),
        accredited_by: by.map(Into::into),
        valid_from: None,
        valid_until: None,
        status: Status::Active,
        x509_certificates: Vec::new(),
        updated_at: 0,
    }
}

/// The authority trusting `issuer` for `MembershipCredential` only.
fn registry_trusting(issuer: &ServiceIdentity) -> Registry {
    let mut r = Registry::default();
    r.upsert(record(ROOT, Role::RootTao, &["*"], None), 1)
        .unwrap();
    r.upsert(
        record(
            issuer.own_did(),
            Role::Ti,
            &["MembershipCredential"],
            Some(ROOT),
        ),
        1,
    )
    .unwrap();
    r
}

async fn spawn_credential_service(registry: &StandInRegistry, static_list: Vec<String>) -> String {
    let config = Config::for_test(
        Mode::CredentialService,
        SocketAddr::from(([127, 0, 0, 1], 0)),
        "localhost:0",
    )
    .with_known_holder_pids(vec![HOLDER_PID.to_string()])
    .with_trusted_issuer_dids(static_list)
    .with_trusted_issuers_registry(registry.base_url.clone(), registry.did.clone());
    let (_state, router): (Arc<AppState>, Router) = identity_hub_http::build(config);
    let port = serve(router).await;
    format!("http://127.0.0.1:{port}")
}

fn sign(party: &ServiceIdentity, payload: Value) -> String {
    dcp_core::sign_jws(&payload, &party.key_pair.signing_key(), party.own_key_id())
}

fn bearer(caller: &ServiceIdentity) -> String {
    let now = dcp_core::now_secs();
    sign(
        caller,
        json!({
            "iss": caller.own_did(), "sub": caller.own_did(), "aud": AUD,
            "iat": now, "nbf": now, "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    )
}

fn credential(credential_type: &str, issuer: &ServiceIdentity) -> Value {
    let now = dcp_core::now_secs();
    let jws = sign(
        issuer,
        json!({
            "iss": issuer.own_did(), "sub": AUD,
            "vc": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", credential_type],
                "credentialSubject": {"id": AUD},
            },
            "iat": now, "nbf": now, "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string(),
        }),
    );
    json!({"credentialType": credential_type, "format": "jwt", "payload": jws})
}

async fn deliver(base: &str, caller: &ServiceIdentity, credentials: Vec<Value>) -> u16 {
    let body = json!({
        "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
        "type": "CredentialMessage",
        "issuerPid": "issuer-pid-1", "holderPid": HOLDER_PID, "status": "ISSUED",
        "credentials": credentials,
    });
    post(&format!("{base}/credentials"), caller, &body).await
}

async fn offer(base: &str, caller: &ServiceIdentity, credential_type: &str) -> u16 {
    let body = json!({
        "issuer": caller.own_did(),
        "credentials": [{"id": "c1", "type": "CredentialObject", "credentialType": credential_type}],
    });
    post(&format!("{base}/offers"), caller, &body).await
}

async fn post(url: &str, caller: &ServiceIdentity, body: &Value) -> u16 {
    reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {}", bearer(caller)))
        .json(body)
        .send()
        .await
        .expect("request")
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_credential_the_registry_trusts_its_issuer_for_is_stored() {
    let issuer = spawn_identity("issuer").await;
    let registry = spawn_registry(registry_trusting(&issuer)).await;
    let base = spawn_credential_service(&registry, vec![]).await;
    assert_eq!(
        deliver(
            &base,
            &issuer,
            vec![credential("MembershipCredential", &issuer)]
        )
        .await,
        200
    );
}

#[tokio::test]
async fn a_credential_type_outside_the_issuers_scope_is_refused() {
    let issuer = spawn_identity("issuer").await;
    let registry = spawn_registry(registry_trusting(&issuer)).await;
    let base = spawn_credential_service(&registry, vec![]).await;
    assert_eq!(
        deliver(&base, &issuer, vec![credential("PIDCredential", &issuer)]).await,
        401
    );
}

#[tokio::test]
async fn an_issuer_the_registry_does_not_list_is_refused_even_if_statically_trusted() {
    let issuer = spawn_identity("issuer").await;
    let stranger = spawn_identity("stranger").await;
    let registry = spawn_registry(registry_trusting(&issuer)).await;
    // With a registry configured, --trusted-issuer-did is not consulted.
    let base = spawn_credential_service(&registry, vec![stranger.own_did().to_string()]).await;
    assert_eq!(
        deliver(
            &base,
            &stranger,
            vec![credential("MembershipCredential", &stranger)]
        )
        .await,
        401
    );
}

#[tokio::test]
async fn a_suspended_issuer_is_refused() {
    let issuer = spawn_identity("issuer").await;
    let mut r = registry_trusting(&issuer);
    r.set_status(issuer.own_did(), Status::Suspended, 2)
        .unwrap();
    let registry = spawn_registry(r).await;
    let base = spawn_credential_service(&registry, vec![]).await;
    assert_eq!(
        deliver(
            &base,
            &issuer,
            vec![credential("MembershipCredential", &issuer)]
        )
        .await,
        401
    );
}

#[tokio::test]
async fn a_credential_issued_by_an_unlisted_party_is_refused_even_from_a_trusted_caller() {
    let issuer = spawn_identity("issuer").await;
    let stranger = spawn_identity("stranger").await;
    let registry = spawn_registry(registry_trusting(&issuer)).await;
    let base = spawn_credential_service(&registry, vec![]).await;
    // Genuinely signed by its own (resolvable) issuer, who is not listed.
    assert_eq!(
        deliver(
            &base,
            &issuer,
            vec![credential("MembershipCredential", &stranger)]
        )
        .await,
        401
    );
}

#[tokio::test]
async fn a_snapshot_that_does_not_verify_trusts_nobody() {
    let issuer = spawn_identity("issuer").await;
    let forger = spawn_identity("forger").await;
    let registry = spawn_registry(registry_trusting(&issuer)).await;
    *registry.forger.lock().unwrap() = Some(forger);
    let base = spawn_credential_service(&registry, vec![]).await;
    assert_eq!(
        deliver(
            &base,
            &issuer,
            vec![credential("MembershipCredential", &issuer)]
        )
        .await,
        401
    );
}

#[tokio::test]
async fn offers_are_checked_against_the_offered_credential_types() {
    let issuer = spawn_identity("issuer").await;
    let registry = spawn_registry(registry_trusting(&issuer)).await;
    let base = spawn_credential_service(&registry, vec![]).await;
    assert_eq!(offer(&base, &issuer, "MembershipCredential").await, 200);
    assert_eq!(offer(&base, &issuer, "PIDCredential").await, 401);
    // The registry is the source of truth: a change shows up once the
    // cached snapshot is refreshed (see registry_trust's unit tests for the
    // refresh schedule); a fresh service sees it at once.
    registry
        .registry
        .lock()
        .unwrap()
        .set_status(issuer.own_did(), Status::Revoked, 3)
        .unwrap();
    let fresh = spawn_credential_service(&registry, vec![]).await;
    assert_eq!(offer(&fresh, &issuer, "MembershipCredential").await, 401);
}
