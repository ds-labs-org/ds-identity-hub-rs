#![allow(dead_code, unused_imports)]
//! Adversarial review probes for the Issuer Admin API diff (0236dc3..HEAD).
//! Every test here FAILS against the current code and demonstrates a defect.

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
const DELIVERY_BUDGET: Duration = Duration::from_secs(60);
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




// ---- probes ----

/// `issuer.rs` claims "one [record] exists per allocated index", yet a
/// failed delivery (and every duplicate id in one request) allocates status
/// list indexes that never get a record: 131072 indexes can be burnt by an
/// unauthenticated did:web holder whose Storage API returns 500, after which
/// the issuer can never issue again.
#[tokio::test]
async fn failed_delivery_must_not_burn_status_list_indexes() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let bad = FakeHolder::spawn_with_storage_status("bad", AxumStatus::INTERNAL_SERVER_ERROR).await;
    let ids = vec!["membership-credential"; 500];
    let response = hub.request_credentials(&bad, "pid-bad", &ids).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let pid = Hub::process_id(&response);
    hub.wait_for_process_state(&pid, "ERRORED").await;

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
        "the ERRORED request (no record) consumed 500 status-list indexes"
    );
}

/// A pending holder's SUBMITTED process is a governance item waiting for the
/// operator, but the oldest-first eviction of the 2048-entry request table
/// silently drops it once other (unauthenticated did:web) callers send 2048
/// requests; approving the holder afterwards delivers nothing.
#[tokio::test]
async fn submitted_process_survives_request_table_pressure() {
    let hub = spawn_hub(HolderApproval::Manual).await;
    let victim = FakeHolder::spawn("victim").await;
    let response = hub
        .request_credentials(&victim, "pid-victim", &["membership-credential"])
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let victim_pid = Hub::process_id(&response);

    let flooder = FakeHolder::spawn("flooder").await;
    for i in 0..2048 {
        let r = hub
            .request_credentials(&flooder, &format!("f-{i}"), &["membership-credential"])
            .await;
        assert_eq!(r.status(), StatusCode::CREATED);
    }
    let (status, body) = hub.get(&format!("/issuanceprocesses/{victim_pid}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pending holder's SUBMITTED process was evicted: {body}"
    );
}

/// Contract: "Errors are always JSON {\"error\": ...}". A wrong method on an
/// existing admin route gets axum's bare 405 with an empty body.
#[tokio::test]
async fn admin_wrong_method_answers_json_error() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let response = hub
        .client
        .get(format!("{}/credentialdefinitions", hub.admin))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    let parsed: Option<Value> = serde_json::from_str(&text).ok();
    assert!(
        parsed.as_ref().is_some_and(|v| v["error"].is_string()),
        "{status}: non-JSON error body {text:?}"
    );
}

/// Contract: "Errors are always JSON". An undecodable percent-escape in a
/// path parameter is rejected by axum's `Path` extractor (inside the
/// participant-context middleware) with a text/plain 400.
#[tokio::test]
async fn admin_bad_path_encoding_answers_json_error() {
    let hub = spawn_hub(HolderApproval::Auto).await;
    let response = hub
        .client
        .get(format!("{}/holders/%FF", hub.admin))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    let parsed: Option<Value> = serde_json::from_str(&text).ok();
    assert!(
        parsed.as_ref().is_some_and(|v| v["error"].is_string()),
        "{status}: non-JSON error body {text:?}"
    );
}

