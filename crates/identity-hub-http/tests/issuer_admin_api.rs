//! Issuer Admin API (issuer-service mode), written against the governance
//! console's shared contract (`governance/api-contract.md`, section 1 and
//! its "Status list" subsection). The console, its Playwright e2e suite and
//! this hub are built in parallel against that one file, so these tests pin
//! the wire shape - status codes, field names, error bodies - rather than
//! internal types.
//!
//! What is covered, and why each piece matters to the console:
//!
//! - **Serving and auth.** The admin API is a separate router, only built
//!   when an admin token is configured, and every request needs that token
//!   as a bearer (`401 {"error"}` otherwise). Deny by default: no token, no
//!   listener at all.
//! - **`{pc}` decoding.** EDC base64-encodes the participant context id in
//!   the path; the console may send either alphabet, padded or not. Any other
//!   id is `404`, since this hub is single tenant.
//! - **Credential definitions** replace the old hardcoded
//!   `supported_credential`: CRUD, validation, and the public `/metadata` and
//!   Credential Request API both read the same catalog.
//! - **Holders and the approval policy** (`--holder-approval auto|manual`):
//!   a pending holder's request waits as `SUBMITTED` until an operator
//!   approves or rejects it; the default `auto` keeps the DCP TCK flow
//!   unchanged (immediate delivery).
//! - **Issued credentials and revocation**: every delivered VC carries a
//!   `StatusList2021Entry`, and revoking it flips the matching bit in the
//!   signed status list served on the public API.
//!
//! The holder in these tests is real in every way that matters: it hosts a
//! genuine `did:web` document on `127.0.0.1` (with a `CredentialService`
//! entry), signs genuine Self-Issued ID Tokens, and runs a Storage API that
//! captures the `CredentialMessage` the hub delivers to it.

use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode as AxumStatus;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, HolderApproval, Mode};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const ADMIN_TOKEN: &str = "test-admin-token";

/// Mirrors the contract's holder cap (`state`/issuer constant expected to
/// be 4096): a request from an unknown DID once the registry is full is
/// refused `503` rather than evicting a governance record.
const MAX_HOLDERS: usize = 4096;

/// Mirrors the contract's QuerySpec `limit` cap.
const MAX_QUERY_LIMIT: usize = 500;

/// 131072 bits, the StatusList2021 minimum (16 KiB) the contract fixes.
const STATUS_LIST_BYTES: usize = 16 * 1024;

/// How long a test waits for an asynchronous delivery to settle.
const DELIVERY_BUDGET: Duration = Duration::from_secs(10);

struct Hub {
    state: Arc<AppState>,
    /// Public DCP API base URL.
    public: String,
    /// Admin API base URL, already including `/v1alpha/participants/{pc}`.
    admin: String,
    client: reqwest::Client,
}

fn pc(id: &str) -> String {
    URL_SAFE_NO_PAD.encode(id.as_bytes())
}

async fn spawn_hub(approval: HolderApproval) -> Hub {
    spawn_hub_with(approval, "issuer").await
}

async fn spawn_hub_with(approval: HolderApproval, participant_context_id: &str) -> Hub {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port for the public API");
    let addr = listener.local_addr().expect("local addr");
    let mut config = Config::for_test(
        Mode::IssuerService,
        addr,
        format!("127.0.0.1:{}", addr.port()),
    );
    config.admin_token = Some(ADMIN_TOKEN.to_string());
    config.participant_context_id = participant_context_id.to_string();
    config.holder_approval = approval;
    let (state, router) = identity_hub_http::build(config);
    let admin_router =
        identity_hub_http::build_admin(&state).expect("admin router is built when a token is set");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("public API");
    });
    let admin_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port for the admin API");
    let admin_addr = admin_listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(admin_listener, admin_router)
            .await
            .expect("admin API");
    });
    Hub {
        state,
        public: format!("http://{addr}"),
        admin: format!(
            "http://{admin_addr}/v1alpha/participants/{}",
            pc(participant_context_id)
        ),
        client: reqwest::Client::new(),
    }
}

impl Hub {
    fn issuer_did(&self) -> String {
        self.state.identity.own_did().to_string()
    }

    async fn admin_call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.admin))
            .bearer_auth(ADMIN_TOKEN);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("admin request completes");
        let status = response.status();
        let text = response.text().await.expect("body readable");
        let value = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("admin API must answer JSON ({e}): {text}"))
        };
        (status, value)
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.admin_call(reqwest::Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.admin_call(reqwest::Method::POST, path, Some(body))
            .await
    }

    async fn put(&self, path: &str, body: Value) -> (StatusCode, Value) {
        self.admin_call(reqwest::Method::PUT, path, Some(body))
            .await
    }

    async fn delete(&self, path: &str) -> (StatusCode, Value) {
        self.admin_call(reqwest::Method::DELETE, path, None).await
    }

    async fn query(&self, collection: &str, spec: Value) -> Vec<Value> {
        let (status, body) = self.post(&format!("/{collection}/query"), spec).await;
        assert_eq!(status, StatusCode::OK, "query {collection}: {body}");
        body.as_array()
            .unwrap_or_else(|| panic!("query answers a plain JSON array, got {body}"))
            .clone()
    }

    /// Sends a DCP Credential Request as `holder` for `definition_ids`.
    async fn request_credentials(
        &self,
        holder: &FakeHolder,
        holder_pid: &str,
        definition_ids: &[&str],
    ) -> reqwest::Response {
        let body = json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "CredentialRequestMessage",
            "holderPid": holder_pid,
            "credentials": definition_ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>(),
        });
        self.client
            .post(format!("{}/credentials", self.public))
            .bearer_auth(holder.token(&self.issuer_did()))
            .json(&body)
            .send()
            .await
            .expect("credential request completes")
    }

    /// The issuance process id from an accepted request's `Location`.
    fn process_id(response: &reqwest::Response) -> String {
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("an accepted Credential Request carries a Location header");
        location
            .strip_prefix("/requests/")
            .expect("Location is /requests/{id}")
            .to_string()
    }

    async fn dcp_status(&self, process_id: &str) -> Value {
        let response = self
            .client
            .get(format!("{}/requests/{process_id}", self.public))
            .send()
            .await
            .expect("status request completes");
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.expect("CredentialStatus JSON")
    }

    async fn wait_for_process_state(&self, process_id: &str, wanted: &str) -> Value {
        let deadline = tokio::time::Instant::now() + DELIVERY_BUDGET;
        loop {
            let (status, process) = self.get(&format!("/issuanceprocesses/{process_id}")).await;
            assert_eq!(status, StatusCode::OK, "{process}");
            if process["state"] == json!(wanted) {
                return process;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "process {process_id} never reached {wanted}: {process}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// A holder with a real `did:web` document on `127.0.0.1` and a Storage API
/// that records every `CredentialMessage` delivered to it.
struct FakeHolder {
    identity: ServiceIdentity,
    received: Arc<Mutex<Vec<Value>>>,
}

impl FakeHolder {
    async fn spawn(segment: &str) -> Self {
        Self::spawn_with_storage_status(segment, AxumStatus::OK).await
    }

    /// `storage_status` lets a test make the Storage API refuse delivery.
    async fn spawn_with_storage_status(segment: &str, storage_status: AxumStatus) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral port for the fake holder");
        let addr: SocketAddr = listener.local_addr().expect("local addr");
        let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), segment);
        let doc = identity.did_document(&[("CredentialService", &format!("http://{addr}"))]);
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let app = Router::new()
            .route(
                &format!("/{segment}/did.json"),
                get(move || {
                    let doc = doc.clone();
                    async move { Json(doc) }
                }),
            )
            .route(
                "/credentials",
                post(move |Json(body): Json<Value>| {
                    let sink = sink.clone();
                    async move {
                        sink.lock().unwrap().push(body);
                        storage_status
                    }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("fake holder");
        });
        Self { identity, received }
    }

    fn did(&self) -> &str {
        self.identity.own_did()
    }

    fn token(&self, aud: &str) -> String {
        let now = dcp_core::now_secs();
        dcp_core::sign_jws(
            &json!({
                "iss": self.did(),
                "sub": self.did(),
                "aud": aud,
                "iat": now,
                "nbf": now,
                "exp": now + 300,
                "jti": uuid::Uuid::new_v4().to_string(),
            }),
            &self.identity.key_pair.signing_key(),
            self.identity.own_key_id(),
        )
    }

    fn deliveries(&self) -> Vec<Value> {
        self.received.lock().unwrap().clone()
    }
}

fn jws_payload(jws: &str) -> Value {
    let (_, _, payload) = dcp_core::decode_jws_unverified(jws).expect("decodable JWS");
    payload
}

fn verify_with_issuer_key(hub: &Hub, jws: &str) {
    let signing_key = hub.state.identity.key_pair.signing_key();
    dcp_core::verify_jws_signature(jws, signing_key.verifying_key())
        .expect("signed with the issuer's own key");
}

async fn holder_by_did(hub: &Hub, did: &str) -> Value {
    let holders = hub
        .query(
            "holders",
            json!({"filterExpression": [{"operandLeft": "did", "operator": "=", "operandRight": did}]}),
        )
        .await;
    assert_eq!(
        holders.len(),
        1,
        "exactly one holder for {did}: {holders:?}"
    );
    holders[0].clone()
}

// ---- serving and auth ----

#[tokio::test]
async fn admin_requests_need_the_admin_bearer_token() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let url = hub.admin.clone();

    let missing = hub.client.get(&url).send().await.unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let body: Value = missing.json().await.expect("401 carries a JSON error body");
    assert!(body["error"].is_string(), "{body}");

    let wrong = hub
        .client
        .get(&url)
        .bearer_auth("not-the-token")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let body: Value = wrong.json().await.expect("401 carries a JSON error body");
    assert!(body["error"].is_string(), "{body}");

    // A token that only shares a prefix with the real one is still wrong.
    let prefix = hub
        .client
        .get(&url)
        .bearer_auth(&ADMIN_TOKEN[..4])
        .send()
        .await
        .unwrap();
    assert_eq!(prefix.status(), StatusCode::UNAUTHORIZED);

    let (status, participant) = hub.get("").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        participant,
        json!({"participantContextId": "issuer", "did": hub.issuer_did(), "state": "ACTIVATED"})
    );
}

#[tokio::test]
async fn admin_router_exists_only_for_an_issuer_service_with_a_token() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));

    let without_token = Config::for_test(Mode::IssuerService, addr, "localhost:0");
    assert!(
        without_token.admin_token.is_none(),
        "no admin token by default"
    );
    let (state, _) = identity_hub_http::build(without_token);
    assert!(
        identity_hub_http::build_admin(&state).is_none(),
        "no admin token configured means no admin listener at all"
    );

    let mut credential_service = Config::for_test(Mode::CredentialService, addr, "localhost:0");
    credential_service.admin_token = Some(ADMIN_TOKEN.to_string());
    let (state, _) = identity_hub_http::build(credential_service);
    assert!(
        identity_hub_http::build_admin(&state).is_none(),
        "the issuer admin API exists in issuer-service mode only"
    );

    let defaults = Config::for_test(Mode::IssuerService, addr, "localhost:0");
    assert_eq!(
        defaults.admin_bind,
        SocketAddr::from(([127, 0, 0, 1], 8182))
    );
    assert_eq!(defaults.participant_context_id, "issuer");
    assert_eq!(defaults.holder_approval, HolderApproval::Auto);
}

#[tokio::test]
async fn participant_context_id_accepts_every_base64_flavour() {
    // Chosen so the standard and url-safe alphabets differ ('/' vs '_') and
    // the encoding needs padding.
    let id = "tenant>>?~";
    assert_ne!(STANDARD.encode(id), URL_SAFE.encode(id));
    assert!(STANDARD.encode(id).ends_with('='));
    let hub = spawn_hub_with(HolderApproval::Auto, id).await;
    let root = hub.admin.rsplit_once('/').unwrap().0.to_string();

    for encoded in [
        STANDARD.encode(id),
        STANDARD_NO_PAD.encode(id),
        URL_SAFE.encode(id),
        URL_SAFE_NO_PAD.encode(id),
    ] {
        // '/' must travel percent-encoded inside one path segment.
        let segment = encoded
            .replace('/', "%2F")
            .replace('+', "%2B")
            .replace('=', "%3D");
        let response = hub
            .client
            .get(format!("{root}/{segment}"))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{encoded}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["participantContextId"], json!(id));
    }

    for other in [
        URL_SAFE_NO_PAD.encode("issuer"),
        "!!not-base64!!".to_string(),
    ] {
        let response = hub
            .client
            .get(format!(
                "{root}/{other}/credentialdefinitions/membership-credential"
            ))
            .bearer_auth(ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{other}");
        let body: Value = response
            .json()
            .await
            .expect("404 carries a JSON error body");
        assert!(body["error"].is_string());
    }
}

// ---- credential definitions ----

#[tokio::test]
async fn credential_definitions_crud() {
    let hub = spawn_hub(HolderApproval::Auto).await;

    let (status, seeded) = hub
        .get("/credentialdefinitions/membership-credential")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seeded["credentialType"], json!("MembershipCredential"));
    assert_eq!(seeded["format"], json!("VC1_0_JWT"));
    assert_eq!(seeded["validity"], json!(3600));
    assert_eq!(seeded["mappings"], json!([]));
    assert!(seeded["createdAt"].as_u64().is_some());

    let (status, created) = hub
        .post(
            "/credentialdefinitions",
            json!({"id": "dataprocessor", "credentialType": "DataProcessorCredential"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["id"], json!("dataprocessor"));
    assert_eq!(created["format"], json!("VC1_0_JWT"), "format defaults");
    assert_eq!(
        created["validity"],
        json!(3600),
        "validity defaults to 3600"
    );
    assert_eq!(created["jsonSchemaUrl"], Value::Null);
    assert_eq!(created["rules"], json!([]));
    let created_at = created["createdAt"]
        .as_u64()
        .expect("createdAt set by the hub");
    assert!(
        created_at.abs_diff(dcp_core::now_secs()) < 60,
        "unix seconds"
    );

    let (status, body) = hub
        .post(
            "/credentialdefinitions",
            json!({"id": "dataprocessor", "credentialType": "Other"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].is_string());

    let (status, updated) = hub
        .put(
            "/credentialdefinitions",
            json!({"id": "dataprocessor", "credentialType": "DataProcessorCredential", "validity": 60}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["validity"], json!(60));
    assert_eq!(
        updated["createdAt"],
        json!(created_at),
        "createdAt survives an update"
    );
    let (_, fetched) = hub.get("/credentialdefinitions/dataprocessor").await;
    assert_eq!(fetched["validity"], json!(60));

    let (status, _) = hub
        .put(
            "/credentialdefinitions",
            json!({"id": "nope", "credentialType": "Nope"}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = hub.get("/credentialdefinitions/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].is_string());

    let types = hub
        .query(
            "credentialdefinitions",
            json!({"filterExpression": [{"operandLeft": "credentialType", "operator": "=", "operandRight": "DataProcessorCredential"}]}),
        )
        .await;
    assert_eq!(types.len(), 1);
    assert_eq!(types[0]["id"], json!("dataprocessor"));
    assert_eq!(hub.query("credentialdefinitions", json!({})).await.len(), 2);

    let (status, _) = hub.delete("/credentialdefinitions/dataprocessor").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = hub.delete("/credentialdefinitions/dataprocessor").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn credential_definition_validation() {
    let hub = spawn_hub(HolderApproval::Auto).await;

    let malformed = hub
        .client
        .post(format!("{}/credentialdefinitions", hub.admin))
        .bearer_auth(ADMIN_TOKEN)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let body: Value = malformed
        .json()
        .await
        .expect("400 carries a JSON error body");
    assert!(body["error"].is_string());

    for (case, body) in [
        ("missing credentialType", json!({"id": "x"})),
        ("missing id", json!({"credentialType": "X"})),
        ("empty id", json!({"id": "", "credentialType": "X"})),
        (
            "credentialType pattern",
            json!({"id": "x", "credentialType": "1Bad"}),
        ),
        (
            "credentialType space",
            json!({"id": "x", "credentialType": "Bad Type"}),
        ),
        (
            "zero validity",
            json!({"id": "x", "credentialType": "X", "validity": 0}),
        ),
        (
            "negative validity",
            json!({"id": "x", "credentialType": "X", "validity": -5}),
        ),
        (
            "unsupported format",
            json!({"id": "x", "credentialType": "X", "format": "VC2_0_JOSE"}),
        ),
    ] {
        let (status, error) = hub.post("/credentialdefinitions", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {error}");
        assert!(error["error"].is_string(), "{case}");
    }
}

#[tokio::test]
async fn metadata_and_credential_requests_follow_the_catalog() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let holder = FakeHolder::spawn("holder").await;

    let (status, _) = hub
        .post(
            "/credentialdefinitions",
            json!({"id": "dataprocessor", "credentialType": "DataProcessorCredential"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let metadata: Value = hub
        .client
        .get(format!("{}/metadata", hub.public))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let supported = metadata["credentialsSupported"]
        .as_array()
        .expect("catalog");
    let ids: Vec<&str> = supported
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["membership-credential", "dataprocessor"]);
    let dataprocessor = &supported[1];
    assert_eq!(dataprocessor["type"], json!("CredentialObject"));
    assert_eq!(
        dataprocessor["credentialType"],
        json!("DataProcessorCredential")
    );
    assert_eq!(dataprocessor["profile"], json!("vc10-sl2021/jwt"));
    assert_eq!(dataprocessor["bindingMethods"], json!(["did:web"]));

    let response = hub
        .request_credentials(&holder, "pid-unknown", &["membership-credential", "nope"])
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "every credentials[].id must name an existing definition"
    );
    let response = hub.request_credentials(&holder, "pid-empty", &[]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = hub
        .request_credentials(&holder, "pid-dp", &["dataprocessor"])
        .await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "a newly defined credential is requestable"
    );
    let process_id = Hub::process_id(&response);
    hub.wait_for_process_state(&process_id, "DELIVERED").await;
    let delivered = holder.deliveries();
    let vc = jws_payload(delivered[0]["credentials"][0]["payload"].as_str().unwrap());
    assert_eq!(
        vc["vc"]["type"],
        json!(["VerifiableCredential", "DataProcessorCredential"])
    );
    assert_eq!(
        delivered[0]["credentials"][0]["credentialType"],
        json!("DataProcessorCredential")
    );

    let (status, _) = hub.delete("/credentialdefinitions/dataprocessor").await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "a DELIVERED process does not block deletion"
    );
    let metadata: Value = hub
        .client
        .get(format!("{}/metadata", hub.public))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        metadata["credentialsSupported"].as_array().unwrap().len(),
        1
    );
    let response = hub
        .request_credentials(&holder, "pid-dp-2", &["dataprocessor"])
        .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "deleted definitions are gone"
    );
}

#[tokio::test]
async fn deleting_a_definition_an_active_process_references_is_refused() {
    let hub = spawn_hub(HolderApproval::Manual).await;
    let holder = FakeHolder::spawn("holder").await;
    hub.post(
        "/credentialdefinitions",
        json!({"id": "dataprocessor", "credentialType": "DataProcessorCredential"}),
    )
    .await;

    let response = hub
        .request_credentials(&holder, "pid-1", &["dataprocessor"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let process_id = Hub::process_id(&response);

    let (status, body) = hub.delete("/credentialdefinitions/dataprocessor").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a SUBMITTED process references it"
    );
    assert!(body["error"].is_string());

    let holder_record = holder_by_did(&hub, holder.did()).await;
    let holder_id = holder_record["holderId"].as_str().unwrap();
    let (status, _) = hub
        .post(&format!("/holders/{holder_id}/reject"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    hub.wait_for_process_state(&process_id, "REJECTED").await;

    let (status, _) = hub.delete("/credentialdefinitions/dataprocessor").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "REJECTED is terminal");
}

// ---- holders ----

#[tokio::test]
async fn holders_register_update_get_and_query() {
    let hub = spawn_hub(HolderApproval::Manual).await;

    let (status, acme) = hub
        .post(
            "/holders",
            json!({"did": "did:web:acme.example", "name": "ACME"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{acme}");
    let acme_id = acme["holderId"]
        .as_str()
        .expect("holderId generated")
        .to_string();
    assert!(
        uuid::Uuid::parse_str(&acme_id).is_ok(),
        "generated holderId is a uuid"
    );
    assert_eq!(
        acme["status"],
        json!("approved"),
        "admin-registered holders are approved"
    );
    assert_eq!(acme["name"], json!("ACME"));
    assert_eq!(acme["properties"], json!({}));
    assert!(acme["createdAt"].as_u64().is_some());

    let (status, globex) = hub
        .post(
            "/holders",
            json!({"holderId": "globex", "did": "did:web:globex.example", "properties": {"tier": "gold"}}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(globex["holderId"], json!("globex"));
    assert_eq!(globex["properties"], json!({"tier": "gold"}));

    let (status, _) = hub
        .post(
            "/holders",
            json!({"holderId": "globex", "did": "did:web:other.example"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate holderId");
    let (status, _) = hub
        .post(
            "/holders",
            json!({"holderId": "other", "did": "did:web:acme.example"}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate did");
    let (status, body) = hub.post("/holders", json!({"name": "no did"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "did is required");
    assert!(body["error"].is_string());

    let (status, updated) = hub
        .put(
            "/holders",
            json!({"holderId": acme_id, "name": "ACME Corp", "properties": {"country": "FR"}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["name"], json!("ACME Corp"));
    assert_eq!(
        updated["did"],
        json!("did:web:acme.example"),
        "did is not updatable"
    );
    let (status, _) = hub
        .put("/holders", json!({"holderId": "missing", "name": "x"}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, fetched) = hub.get(&format!("/holders/{acme_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched["properties"], json!({"country": "FR"}));
    let (status, _) = hub.get("/holders/missing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A DCP request from an unknown DID, in manual mode, creates a pending
    // holder.
    let stranger = FakeHolder::spawn("stranger").await;
    let response = hub
        .request_credentials(&stranger, "pid-s", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let pending = hub
        .query(
            "holders",
            json!({"filterExpression": [{"operandLeft": "status", "operator": "=", "operandRight": "pending"}]}),
        )
        .await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["did"], json!(stranger.did()));
    assert_eq!(hub.query("holders", json!({})).await.len(), 3);

    let (status, body) = hub
        .post(
            "/holders/query",
            json!({"filterExpression": [{"operandLeft": "status", "operator": "like", "operandRight": "p%"}]}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "only '=' is supported");
    assert!(body["error"].is_string());

    let (status, _) = hub.post("/holders/missing/approve", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = hub.post("/holders/missing/reject", json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn query_spec_paging_sorting_and_limit_cap() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let total = MAX_QUERY_LIMIT + 10;
    for i in 0..total {
        let (status, _) = hub
            .post(
                "/holders",
                json!({"holderId": format!("h{i:04}"), "did": format!("did:web:h{i}.example"), "name": format!("n{i:04}")}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    assert_eq!(
        hub.query("holders", json!({})).await.len(),
        50,
        "default limit"
    );
    assert_eq!(
        hub.query("holders", json!({"limit": 10_000})).await.len(),
        MAX_QUERY_LIMIT,
        "limit is capped"
    );
    let page = hub
        .query(
            "holders",
            json!({"offset": 505, "limit": 100, "sortField": "holderId", "sortOrder": "ASC"}),
        )
        .await;
    assert_eq!(page.len(), 5);
    assert_eq!(page[0]["holderId"], json!("h0505"));
    let desc = hub
        .query(
            "holders",
            json!({"limit": 2, "sortField": "name", "sortOrder": "DESC"}),
        )
        .await;
    assert_eq!(desc[0]["name"], json!(format!("n{:04}", total - 1)));
    assert_eq!(desc[1]["name"], json!(format!("n{:04}", total - 2)));

    let (status, _) = hub.post("/holders/query", json!({"limit": -1})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = hub
        .post("/holders/query", json!({"sortOrder": "SIDEWAYS"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn holder_registry_is_capped() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    for i in 0..MAX_HOLDERS {
        let (status, body) = hub
            .post("/holders", json!({"did": format!("did:web:h{i}.example")}))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{i}: {body}");
    }
    let (status, body) = hub
        .post("/holders", json!({"did": "did:web:one-more.example"}))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body["error"].is_string());

    let stranger = FakeHolder::spawn("stranger").await;
    let response = hub
        .request_credentials(&stranger, "pid", &["membership-credential"])
        .await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "an unknown DID is refused once the registry is full"
    );
    assert!(hub.query("issuanceprocesses", json!({})).await.is_empty());
}

// ---- approval policy, issuance and revocation ----

#[tokio::test]
async fn manual_approval_delivery_and_revocation_end_to_end() {
    let hub = spawn_hub(HolderApproval::Manual).await;
    let holder = FakeHolder::spawn("holder").await;

    // (1) A request from an unknown DID: pending holder, SUBMITTED process.
    let response = hub
        .request_credentials(&holder, "holder-pid-1", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let process_id = Hub::process_id(&response);

    let holder_record = holder_by_did(&hub, holder.did()).await;
    assert_eq!(holder_record["status"], json!("pending"));
    let holder_id = holder_record["holderId"].as_str().unwrap().to_string();

    let (status, process) = hub.get(&format!("/issuanceprocesses/{process_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(process["id"], json!(process_id));
    assert_eq!(process["state"], json!("SUBMITTED"));
    assert_eq!(process["holderId"], json!(holder_id));
    assert_eq!(process["holderDid"], json!(holder.did()));
    assert_eq!(process["holderPid"], json!("holder-pid-1"));
    assert_eq!(
        process["credentialDefinitions"],
        json!(["membership-credential"])
    );
    assert_eq!(process["errorDetail"], Value::Null);
    assert!(process["createdAt"].as_u64().is_some());
    assert!(process["stateTimestamp"].as_u64().is_some());
    assert_eq!(
        hub.dcp_status(&process_id).await["status"],
        json!("RECEIVED")
    );

    // Nothing is delivered while the holder is pending.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(holder.deliveries().is_empty());
    let submitted = hub
        .query(
            "issuanceprocesses",
            json!({"filterExpression": [{"operandLeft": "state", "operator": "=", "operandRight": "SUBMITTED"}]}),
        )
        .await;
    assert_eq!(submitted.len(), 1);

    // (2) Approve: the process moves on and is delivered.
    let (status, approved) = hub
        .post(&format!("/holders/{holder_id}/approve"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(approved["status"], json!("approved"));
    hub.wait_for_process_state(&process_id, "DELIVERED").await;
    assert_eq!(hub.dcp_status(&process_id).await["status"], json!("ISSUED"));

    // (3) One issued-credential record, active.
    let credentials = hub.query("credentials", json!({})).await;
    assert_eq!(credentials.len(), 1, "{credentials:?}");
    let record = &credentials[0];
    let credential_id = record["id"].as_str().unwrap().to_string();
    assert!(credential_id.starts_with("urn:uuid:"), "{credential_id}");
    assert_eq!(record["credentialType"], json!("MembershipCredential"));
    assert_eq!(
        record["credentialDefinitionId"],
        json!("membership-credential")
    );
    assert_eq!(record["holderId"], json!(holder_id));
    assert_eq!(record["holderDid"], json!(holder.did()));
    assert_eq!(record["issuanceProcessId"], json!(process_id));
    assert_eq!(record["format"], json!("VC1_0_JWT"));
    assert_eq!(record["status"], json!("active"));
    let issued_at = record["issuedAt"].as_u64().unwrap();
    assert_eq!(record["expiresAt"].as_u64().unwrap(), issued_at + 3600);
    let index = record["statusListIndex"].as_u64().expect("statusListIndex") as usize;

    // (4) The delivered VC carries a StatusList2021Entry pointing at it.
    let deliveries = holder.deliveries();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0]["holderPid"], json!("holder-pid-1"));
    assert_eq!(deliveries[0]["issuerPid"], json!(process_id));
    let vc_jws = deliveries[0]["credentials"][0]["payload"].as_str().unwrap();
    verify_with_issuer_key(&hub, vc_jws);
    let vc = jws_payload(vc_jws);
    assert_eq!(vc["sub"], json!(holder.did()));
    assert_eq!(vc["jti"], json!(credential_id));
    assert_eq!(vc["vc"]["id"], json!(credential_id));
    let list_url = format!("{}/statuslist/revocation", hub.public);
    assert_eq!(
        vc["vc"]["credentialStatus"],
        json!({
            "id": format!("{list_url}#{index}"),
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": index.to_string(),
            "statusListCredential": list_url,
        })
    );

    let (status, current) = hub
        .get(&format!(
            "/credentials/{}/status",
            urlencode(&credential_id)
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(current, json!({"status": "active"}));
    assert!(!status_list_bit(&hub, index).await, "not revoked yet");

    // (5) Revoke: idempotent, flips the bit.
    for _ in 0..2 {
        let (status, revoked) = hub
            .post(
                &format!("/credentials/{}/revoke", urlencode(&credential_id)),
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(revoked["status"], json!("revoked"));
        assert_eq!(revoked["id"], json!(credential_id));
    }
    let (_, current) = hub
        .get(&format!(
            "/credentials/{}/status",
            urlencode(&credential_id)
        ))
        .await;
    assert_eq!(current, json!({"status": "revoked"}));
    assert!(status_list_bit(&hub, index).await, "revoked index is set");

    let (status, _) = hub.get("/credentials/urn%3Auuid%3Anope/status").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = hub
        .post("/credentials/urn%3Auuid%3Anope/revoke", json!({}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // (6) An approved holder's next request goes straight through.
    let response = hub
        .request_credentials(&holder, "holder-pid-2", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    hub.wait_for_process_state(&Hub::process_id(&response), "DELIVERED")
        .await;
    let second = hub
        .query(
            "credentials",
            json!({"filterExpression": [{"operandLeft": "status", "operator": "=", "operandRight": "active"}]}),
        )
        .await;
    assert_eq!(second.len(), 1);
    let second_index = second[0]["statusListIndex"].as_u64().unwrap() as usize;
    assert_ne!(second_index, index, "each credential gets its own index");
    assert!(!status_list_bit(&hub, second_index).await);
}

#[tokio::test]
async fn rejected_holders_are_refused() {
    let hub = spawn_hub(HolderApproval::Manual).await;
    let holder = FakeHolder::spawn("holder").await;

    let response = hub
        .request_credentials(&holder, "pid-1", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let process_id = Hub::process_id(&response);
    let holder_id = holder_by_did(&hub, holder.did()).await["holderId"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, rejected) = hub
        .post(&format!("/holders/{holder_id}/reject"), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rejected["status"], json!("rejected"));
    hub.wait_for_process_state(&process_id, "REJECTED").await;
    assert_eq!(
        hub.dcp_status(&process_id).await["status"],
        json!("REJECTED")
    );

    let response = hub
        .request_credentials(&holder, "pid-2", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        hub.query("issuanceprocesses", json!({})).await.len(),
        1,
        "no process is created for a rejected holder"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(holder.deliveries().is_empty());
    assert!(hub.query("credentials", json!({})).await.is_empty());
}

#[tokio::test]
async fn auto_approval_delivers_immediately() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let holder = FakeHolder::spawn("holder").await;

    let response = hub
        .request_credentials(&holder, "pid-1", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let process_id = Hub::process_id(&response);
    hub.wait_for_process_state(&process_id, "DELIVERED").await;
    assert_eq!(hub.dcp_status(&process_id).await["status"], json!("ISSUED"));

    let record = holder_by_did(&hub, holder.did()).await;
    assert_eq!(
        record["status"],
        json!("approved"),
        "auto mode approves unknown DIDs"
    );
    assert_eq!(holder.deliveries().len(), 1);
    assert_eq!(hub.query("credentials", json!({})).await.len(), 1);
}

#[tokio::test]
async fn failed_delivery_is_errored_and_maps_to_dcp_rejected() {
    let hub = spawn_hub(HolderApproval::Manual).await;
    let holder =
        FakeHolder::spawn_with_storage_status("holder", AxumStatus::INTERNAL_SERVER_ERROR).await;

    let response = hub
        .request_credentials(&holder, "pid-1", &["membership-credential"])
        .await;
    let process_id = Hub::process_id(&response);
    assert_eq!(
        hub.dcp_status(&process_id).await["status"],
        json!("RECEIVED"),
        "SUBMITTED"
    );
    let holder_id = holder_by_did(&hub, holder.did()).await["holderId"]
        .as_str()
        .unwrap()
        .to_string();
    hub.post(&format!("/holders/{holder_id}/approve"), json!({}))
        .await;

    let process = hub.wait_for_process_state(&process_id, "ERRORED").await;
    assert!(
        process["errorDetail"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "ERRORED carries an errorDetail: {process}"
    );
    assert_eq!(
        hub.dcp_status(&process_id).await["status"],
        json!("REJECTED")
    );
    assert!(
        hub.query("credentials", json!({})).await.is_empty(),
        "only successfully delivered credentials are recorded"
    );

    let (status, _) = hub.get("/issuanceprocesses/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn status_list_is_a_signed_status_list_credential() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let response = hub
        .client
        .get(format!("{}/statuslist/revocation", hub.public))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[reqwest::header::CONTENT_TYPE],
        "application/vc+jwt"
    );
    let jwt = response.text().await.unwrap();
    verify_with_issuer_key(&hub, &jwt);
    let payload = jws_payload(&jwt);
    let list_url = format!("{}/statuslist/revocation", hub.public);
    assert_eq!(payload["iss"], json!(hub.issuer_did()));
    let vc = &payload["vc"];
    assert_eq!(vc["id"], json!(list_url));
    assert_eq!(
        vc["type"],
        json!(["VerifiableCredential", "StatusList2021Credential"])
    );
    assert_eq!(vc["credentialSubject"]["type"], json!("StatusList2021"));
    assert_eq!(
        vc["credentialSubject"]["statusPurpose"],
        json!("revocation")
    );
    let bits = decode_list(vc["credentialSubject"]["encodedList"].as_str().unwrap());
    assert_eq!(bits.len(), STATUS_LIST_BYTES);
    assert!(bits.iter().all(|b| *b == 0));
}

// ---- helpers ----

fn urlencode(value: &str) -> String {
    value.replace(':', "%3A")
}

fn decode_list(encoded: &str) -> Vec<u8> {
    assert!(!encoded.contains('='), "base64url without padding");
    let gzipped = URL_SAFE_NO_PAD.decode(encoded).expect("base64url");
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(&gzipped[..])
        .read_to_end(&mut bytes)
        .expect("gzip");
    bytes
}

/// Fetches and verifies the public status list, returning bit `index`
/// (most significant bit first within each byte).
async fn status_list_bit(hub: &Hub, index: usize) -> bool {
    let jwt = hub
        .client
        .get(format!("{}/statuslist/revocation", hub.public))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    verify_with_issuer_key(hub, &jwt);
    let bits = decode_list(
        jws_payload(&jwt)["vc"]["credentialSubject"]["encodedList"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(bits.len(), STATUS_LIST_BYTES);
    bits[index / 8] & (0x80 >> (index % 8)) != 0
}

// ---- review findings (2026-10-14 adversarial review) ----

/// A failed delivery (and every duplicate id in one request) used to
/// allocate status-list indexes that never got a record, so a `did:web`
/// holder whose Storage API always fails could exhaust the list. Duplicate
/// ids are now deduplicated and a failed delivery's indexes are reused.
#[tokio::test]
async fn failed_delivery_must_not_burn_status_list_indexes() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let bad = FakeHolder::spawn_with_storage_status("bad", AxumStatus::INTERNAL_SERVER_ERROR).await;
    let ids = vec!["membership-credential"; 500];
    let response = hub.request_credentials(&bad, "pid-bad", &ids).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let pid = Hub::process_id(&response);
    let errored = hub.wait_for_process_state(&pid, "ERRORED").await;
    assert_eq!(
        errored["credentialDefinitions"],
        json!(["membership-credential"]),
        "duplicate ids are deduplicated"
    );

    let good = FakeHolder::spawn("good").await;
    let response = hub
        .request_credentials(&good, "pid-good", &["membership-credential"])
        .await;
    let pid = Hub::process_id(&response);
    hub.wait_for_process_state(&pid, "DELIVERED").await;
    let records = hub.query("credentials", json!({})).await;
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]["statusListIndex"],
        json!(0),
        "the ERRORED request (no record) must give its index back"
    );
}

#[tokio::test]
async fn credential_requests_are_capped_at_sixteen_distinct_ids() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let holder = FakeHolder::spawn("holder").await;
    let ids: Vec<String> = (0..17).map(|i| format!("def-{i}")).collect();
    for id in &ids {
        let (status, _) = hub
            .post(
                "/credentialdefinitions",
                json!({"id": id, "credentialType": "SomeCredential"}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let response = hub.request_credentials(&holder, "pid-17", &refs).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = hub
        .request_credentials(&holder, "pid-16", &refs[..16])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let process = hub
        .wait_for_process_state(&Hub::process_id(&response), "DELIVERED")
        .await;
    assert_eq!(
        process["credentialDefinitions"].as_array().unwrap().len(),
        16
    );
    assert_eq!(
        holder.deliveries()[0]["credentials"]
            .as_array()
            .unwrap()
            .len(),
        16
    );
}

/// A pending holder's SUBMITTED process is a governance item waiting for the
/// operator: other callers' traffic must not evict it. SUBMITTED processes
/// are kept out of the request table's eviction and capped on their own
/// (8 per holder), and other holders' terminal records are evicted instead.
#[tokio::test]
async fn submitted_process_survives_request_table_pressure() {
    const MAX_TRACKED_REQUESTS: usize = 2048;
    const MAX_PENDING_PER_HOLDER: usize = 8;
    let hub = spawn_hub(HolderApproval::Manual).await;
    let victim = FakeHolder::spawn("victim").await;
    let response = hub
        .request_credentials(&victim, "pid-victim", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let victim_pid = Hub::process_id(&response);

    // A pending flooder is held to its own small quota.
    let pending_flooder = FakeHolder::spawn("pending-flooder").await;
    for i in 0..MAX_PENDING_PER_HOLDER {
        let r = hub
            .request_credentials(
                &pending_flooder,
                &format!("p-{i}"),
                &["membership-credential"],
            )
            .await;
        assert_eq!(r.status(), StatusCode::CREATED);
    }
    let r = hub
        .request_credentials(&pending_flooder, "p-over", &["membership-credential"])
        .await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);

    // An approved flooder fills the table with terminal records.
    let flooder =
        FakeHolder::spawn_with_storage_status("flooder", AxumStatus::INTERNAL_SERVER_ERROR).await;
    let (status, _) = hub.post("/holders", json!({"did": flooder.did()})).await;
    assert_eq!(status, StatusCode::CREATED);
    let mut last = String::new();
    for i in 0..MAX_TRACKED_REQUESTS {
        let r = hub
            .request_credentials(&flooder, &format!("f-{i}"), &["membership-credential"])
            .await;
        assert_eq!(r.status(), StatusCode::CREATED, "request {i}");
        last = Hub::process_id(&r);
    }
    hub.wait_for_process_state(&last, "ERRORED").await;

    let (status, body) = hub.get(&format!("/issuanceprocesses/{victim_pid}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pending holder's SUBMITTED process was evicted: {body}"
    );
    assert_eq!(body["state"], json!("SUBMITTED"));
    assert!(hub.state.requests.lock().unwrap().len() <= MAX_TRACKED_REQUESTS);
}

/// Contract: "Errors are always JSON {\"error\": ...}" - including a wrong
/// method on an existing admin route and an unknown admin path.
#[tokio::test]
async fn admin_wrong_method_and_unknown_path_answer_json_errors() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    for (method, path, expected) in [
        (
            reqwest::Method::GET,
            "/credentialdefinitions",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            reqwest::Method::DELETE,
            "/holders/query",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            reqwest::Method::GET,
            "/no-such-thing",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, body) = hub.admin_call(method.clone(), path, None).await;
        assert_eq!(status, expected, "{method} {path}");
        assert!(body["error"].is_string(), "{method} {path}: {body}");
    }
}

/// Contract: "Errors are always JSON". An undecodable percent-escape in a
/// path parameter used to come back as axum's text/plain 400.
#[tokio::test]
async fn admin_bad_path_encoding_answers_json_error() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let (status, body) = hub.get("/holders/%FF").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].is_string(), "{body}");
}

/// RFC 7235: the auth scheme name is case-insensitive.
#[tokio::test]
async fn admin_bearer_scheme_is_case_insensitive() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    for scheme in ["bearer", "BEARER", "Bearer"] {
        let response = hub
            .client
            .get(&hub.admin)
            .header("Authorization", format!("{scheme} {ADMIN_TOKEN}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{scheme}");
    }
}
