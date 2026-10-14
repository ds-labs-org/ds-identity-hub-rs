//! OID4VCI 1.0 alongside DCP, against the real HTTP layer on loopback.
//!
//! The Issuer Service plays the OID4VCI Credential Issuer (Pre-Authorized
//! Code flow) and the Credential Service the OID4VCI Wallet. The headline
//! test runs both processes and shows the two protocols meeting: a
//! credential redeemed over OID4VCI is then disclosed over DCP's
//! Presentation API, with no extra step. The rest pin the issuer's and the
//! wallet's rejection rules one at a time.

use std::sync::Arc;

use identity_hub_core::dcp_core::{self, b64_encode, now_secs};
use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::oid4vci::{
    PRE_AUTHORIZED_CODE_GRANT, PROOF_JWT_TYP, build_jwt_proof, sign_jws_with_header,
};
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const MEMBERSHIP_SCOPE: &str = "org.eclipse.dspace.dcp.vc.type:MembershipCredential";
const CONFIG_ID: &str = "membership-credential";

async fn spawn(mode: Mode, configure: impl FnOnce(Config) -> Config) -> (Arc<AppState>, String) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let config = configure(Config::for_test(
        mode,
        addr,
        format!("127.0.0.1:{}", addr.port()),
    ));
    let (state, router) = identity_hub_http::build(config);
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
    (state, format!("http://{addr}"))
}

async fn spawn_issuer() -> (Arc<AppState>, String) {
    spawn(Mode::IssuerService, |c| c).await
}

/// A holder this test controls, with a real resolvable `did:web` document.
async fn spawn_holder() -> ServiceIdentity {
    use axum::Json;
    use axum::routing::get;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let identity = ServiceIdentity::new(&format!("127.0.0.1:{}", addr.port()), "holder");
    let doc = identity.did_document(&[]);
    let app = axum::Router::new().route(
        "/holder/did.json",
        get(move || {
            let doc = doc.clone();
            async move { Json(doc) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    identity
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn create_offer(state: &AppState, base: &str, body: Value) -> reqwest::Response {
    client()
        .post(format!("{base}/oid4vci/offers"))
        .basic_auth(
            &state.config.sts_client_id,
            Some(&state.config.sts_client_secret),
        )
        .json(&body)
        .send()
        .await
        .expect("create offer")
}

async fn created_offer(state: &AppState, base: &str, tx_code: bool) -> Value {
    let response = create_offer(state, base, json!({"tx_code": tx_code})).await;
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    response.json().await.expect("offer json")
}

fn pre_authorized_code(created: &Value) -> String {
    created["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT]["pre-authorized_code"]
        .as_str()
        .expect("pre-authorized code")
        .to_string()
}

async fn token(base: &str, code: &str, tx_code: Option<&str>) -> reqwest::Response {
    let mut form = vec![
        ("grant_type", PRE_AUTHORIZED_CODE_GRANT.to_string()),
        ("pre-authorized_code", code.to_string()),
    ];
    if let Some(tx) = tx_code {
        form.push(("tx_code", tx.to_string()));
    }
    client()
        .post(format!("{base}/oid4vci/token"))
        .form(&form)
        .send()
        .await
        .expect("token request")
}

async fn access_token(base: &str, code: &str, tx_code: Option<&str>) -> String {
    let response = token(base, code, tx_code).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.expect("token json");
    body["access_token"]
        .as_str()
        .expect("access token")
        .to_string()
}

async fn c_nonce(base: &str) -> String {
    let body: Value = client()
        .post(format!("{base}/oid4vci/nonce"))
        .send()
        .await
        .expect("nonce request")
        .json()
        .await
        .expect("nonce json");
    body["c_nonce"].as_str().expect("c_nonce").to_string()
}

async fn request_credential(
    base: &str,
    access_token: Option<&str>,
    proof: &str,
) -> reqwest::Response {
    let mut request = client()
        .post(format!("{base}/oid4vci/credential"))
        .json(&json!({
            "credential_configuration_id": CONFIG_ID,
            "proofs": {"jwt": [proof]},
        }));
    if let Some(token) = access_token {
        request = request.bearer_auth(token);
    }
    request.send().await.expect("credential request")
}

async fn error_code(response: reqwest::Response) -> String {
    let body: Value = response.json().await.expect("error json");
    body["error"].as_str().expect("error code").to_string()
}

/// A key proof carrying the holder's public key inline as a `jwk`.
fn jwk_proof(holder: &ServiceIdentity, aud: &str, nonce: &str) -> String {
    let kp = &holder.key_pair;
    sign_jws_with_header(
        json!({"typ": PROOF_JWT_TYP, "jwk": {
            "kty": "EC", "crv": "P-256",
            "x": b64_encode(kp.public_key_xy.0), "y": b64_encode(kp.public_key_xy.1),
        }}),
        &json!({"aud": aud, "iat": now_secs(), "nonce": nonce}),
        kp,
    )
}

#[tokio::test]
async fn issuer_publishes_oid4vci_metadata_next_to_its_dcp_metadata() {
    let (state, base) = spawn_issuer().await;
    let oid4vci: Value = client()
        .get(format!("{base}/.well-known/openid-credential-issuer"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(oid4vci["credential_issuer"], json!(base));
    assert_eq!(
        oid4vci["credential_endpoint"],
        json!(format!("{base}/oid4vci/credential"))
    );
    assert_eq!(
        oid4vci["nonce_endpoint"],
        json!(format!("{base}/oid4vci/nonce"))
    );
    let config = &oid4vci["credential_configurations_supported"][CONFIG_ID];
    assert_eq!(config["format"], json!("jwt_vc_json"));
    assert_eq!(
        config["credential_definition"]["type"],
        json!(["VerifiableCredential", "MembershipCredential"])
    );

    let authorization_server: Value = client()
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        authorization_server["token_endpoint"],
        json!(format!("{base}/oid4vci/token"))
    );
    assert_eq!(
        authorization_server["pre-authorized_grant_anonymous_access_supported"],
        json!(true)
    );

    // The DCP Issuer Metadata API is still served, describing the same credential.
    let dcp: Value = client()
        .get(format!("{base}/metadata"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dcp["issuer"], json!(state.identity.own_did()));
    assert_eq!(dcp["credentialsSupported"][0]["id"], json!(CONFIG_ID));
}

#[tokio::test]
async fn issuer_runs_the_pre_authorized_code_flow_for_a_did_web_holder() {
    let (state, base) = spawn_issuer().await;
    let holder = spawn_holder().await;
    let code = pre_authorized_code(&created_offer(&state, &base, false).await);
    let token = access_token(&base, &code, None).await;
    let nonce = c_nonce(&base).await;
    let proof = build_jwt_proof(&holder.key_pair, &base, Some(&nonce));

    let response = request_credential(&base, Some(&token), &proof).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let vc = body["credentials"][0]["credential"]
        .as_str()
        .expect("jwt vc");
    let (_, _, payload) = dcp_core::decode_jws_unverified(vc).unwrap();
    assert_eq!(payload["iss"], json!(state.identity.own_did()));
    assert_eq!(payload["sub"], json!(holder.own_did()));
    assert_eq!(
        payload["vc"]["type"],
        json!(["VerifiableCredential", "MembershipCredential"])
    );
    let issuer_key = state
        .identity
        .key_pair
        .signing_key()
        .verifying_key()
        .to_owned();
    dcp_core::verify_jws_signature(vc, &issuer_key).expect("VC is signed by the issuer's own key");
}

#[tokio::test]
async fn issuer_binds_a_jwk_proof_to_its_did_jwk() {
    let (state, base) = spawn_issuer().await;
    let holder = ServiceIdentity::new("unresolvable.example", "holder");
    let code = pre_authorized_code(&created_offer(&state, &base, false).await);
    let token = access_token(&base, &code, None).await;
    let nonce = c_nonce(&base).await;

    let response =
        request_credential(&base, Some(&token), &jwk_proof(&holder, &base, &nonce)).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    let (_, _, payload) =
        dcp_core::decode_jws_unverified(body["credentials"][0]["credential"].as_str().unwrap())
            .unwrap();
    assert!(payload["sub"].as_str().unwrap().starts_with("did:jwk:"));
}

#[tokio::test]
async fn pre_authorized_code_is_single_use() {
    let (state, base) = spawn_issuer().await;
    let code = pre_authorized_code(&created_offer(&state, &base, false).await);
    access_token(&base, &code, None).await;
    let replay = token(&base, &code, None).await;
    assert_eq!(replay.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(error_code(replay).await, "invalid_grant");
}

#[tokio::test]
async fn tx_code_is_required_checked_and_burns_the_code_after_repeated_failures() {
    let (state, base) = spawn_issuer().await;
    let created = created_offer(&state, &base, true).await;
    let code = pre_authorized_code(&created);
    let tx_code = created["tx_code"]
        .as_str()
        .expect("tx_code returned to the operator");
    assert_eq!(
        created["credential_offer"]["grants"][PRE_AUTHORIZED_CODE_GRANT]["tx_code"]["length"],
        json!(6),
        "the offer describes the tx_code but never carries it"
    );

    assert_eq!(
        error_code(token(&base, &code, None).await).await,
        "invalid_request"
    );
    let wrong = if tx_code == "000000" {
        "111111"
    } else {
        "000000"
    };
    for _ in 0..3 {
        assert_eq!(
            error_code(token(&base, &code, Some(wrong)).await).await,
            "invalid_grant"
        );
    }
    // Burned: even the right code no longer works.
    assert_eq!(
        error_code(token(&base, &code, Some(tx_code)).await).await,
        "invalid_grant"
    );

    let fresh = created_offer(&state, &base, true).await;
    access_token(
        &base,
        &pre_authorized_code(&fresh),
        fresh["tx_code"].as_str(),
    )
    .await;
}

#[tokio::test]
async fn credential_endpoint_requires_a_live_access_token() {
    let (_, base) = spawn_issuer().await;
    let holder = ServiceIdentity::new("unresolvable.example", "holder");
    let nonce = c_nonce(&base).await;
    for token in [None, Some("not-a-token")] {
        let response = request_credential(&base, token, &jwk_proof(&holder, &base, &nonce)).await;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("www-authenticate"));
        assert_eq!(error_code(response).await, "invalid_token");
    }
}

#[tokio::test]
async fn credential_endpoint_rejects_bad_proofs_and_reused_nonces() {
    let (state, base) = spawn_issuer().await;
    let holder = spawn_holder().await;
    let code = pre_authorized_code(&created_offer(&state, &base, false).await);
    let token = access_token(&base, &code, None).await;

    // Wrong audience.
    let nonce = c_nonce(&base).await;
    let proof = build_jwt_proof(
        &holder.key_pair,
        "http://someone-else.example",
        Some(&nonce),
    );
    assert_eq!(
        error_code(request_credential(&base, Some(&token), &proof).await).await,
        "invalid_proof"
    );

    // kid names the holder's real did:web key, but another key signed it.
    let impostor = ServiceIdentity::new("unresolvable.example", "impostor");
    let forged = sign_jws_with_header(
        json!({"typ": PROOF_JWT_TYP, "kid": holder.own_key_id()}),
        &json!({"aud": base, "iat": now_secs(), "nonce": nonce}),
        &impostor.key_pair,
    );
    assert_eq!(
        error_code(request_credential(&base, Some(&token), &forged).await).await,
        "invalid_proof"
    );

    // No nonce at all, then a nonce this issuer never handed out.
    let unnonced = build_jwt_proof(&holder.key_pair, &base, None);
    assert_eq!(
        error_code(request_credential(&base, Some(&token), &unnonced).await).await,
        "invalid_nonce"
    );
    let made_up = build_jwt_proof(&holder.key_pair, &base, Some("made-up"));
    assert_eq!(
        error_code(request_credential(&base, Some(&token), &made_up).await).await,
        "invalid_nonce"
    );

    // A genuine nonce works once, and only once.
    let good = build_jwt_proof(&holder.key_pair, &base, Some(&nonce));
    assert_eq!(
        request_credential(&base, Some(&token), &good)
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    let replay = build_jwt_proof(&holder.key_pair, &base, Some(&nonce));
    assert_eq!(
        error_code(request_credential(&base, Some(&token), &replay).await).await,
        "invalid_nonce"
    );
}

#[tokio::test]
async fn operator_endpoints_require_client_credentials() {
    let (_, issuer_base) = spawn_issuer().await;
    let unauthenticated = client()
        .post(format!("{issuer_base}/oid4vci/offers"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);
    let wrong = client()
        .post(format!("{issuer_base}/oid4vci/offers"))
        .basic_auth("tck-client", Some("wrong"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);

    let (_, wallet_base) = spawn(Mode::CredentialService, |c| c).await;
    let unauthenticated = client()
        .post(format!("{wallet_base}/oid4vci/wallet/offers"))
        .json(&json!({"credential_offer_uri": "http://127.0.0.1:1/x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), reqwest::StatusCode::UNAUTHORIZED);
}

async fn redeem(wallet: &AppState, wallet_base: &str, body: Value) -> reqwest::Response {
    client()
        .post(format!("{wallet_base}/oid4vci/wallet/offers"))
        .basic_auth(
            &wallet.config.sts_client_id,
            Some(&wallet.config.sts_client_secret),
        )
        .json(&body)
        .send()
        .await
        .expect("redeem request")
}

/// The point of running both protocols in one hub: the Credential Service
/// redeems an OID4VCI offer from the Issuer Service (by reference, with a
/// Transaction Code), then a DCP verifier gets that same credential back
/// from `/presentations/query`.
#[tokio::test]
async fn a_credential_redeemed_over_oid4vci_is_presented_over_dcp() {
    let (issuer, issuer_base) = spawn_issuer().await;
    let issuer_did = issuer.identity.own_did().to_string();
    let (wallet, wallet_base) = spawn(Mode::CredentialService, |c| {
        c.with_trusted_issuer_dids(vec![issuer_did.clone()])
    })
    .await;

    let created = created_offer(&issuer, &issuer_base, true).await;
    let offer_uri = created["offer_uri"].as_str().expect("offer uri");
    assert!(offer_uri.starts_with("openid-credential-offer://?credential_offer_uri="));

    let response = redeem(
        &wallet,
        &wallet_base,
        json!({"offer": offer_uri, "tx_code": created["tx_code"]}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let redeemed: Value = response.json().await.unwrap();
    assert_eq!(
        redeemed["stored"],
        json!([{"credential_configuration_id": CONFIG_ID, "credential_type": "MembershipCredential"}])
    );

    // Now a DCP Presentation API read, with a grant from the wallet's own STS.
    let sts: Value = client()
        .post(format!("{wallet_base}/sts/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", wallet.config.sts_client_id.as_str()),
            ("client_secret", wallet.config.sts_client_secret.as_str()),
            ("audience", wallet.identity.own_did()),
            ("bearer_access_scope", MEMBERSHIP_SCOPE),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let presentation: Value = client()
        .post(format!("{wallet_base}/presentations/query"))
        .bearer_auth(sts["access_token"].as_str().unwrap())
        .json(&json!({
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "PresentationQueryMessage",
            "scope": [MEMBERSHIP_SCOPE],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let (_, _, vp) =
        dcp_core::decode_jws_unverified(presentation["presentation"][0].as_str().unwrap()).unwrap();
    let vcs = vp["vp"]["verifiableCredential"].as_array().unwrap();
    assert_eq!(vcs.len(), 1);
    let (_, _, vc) = dcp_core::decode_jws_unverified(vcs[0].as_str().unwrap()).unwrap();
    assert_eq!(vc["iss"], json!(issuer_did));
    assert_eq!(vc["sub"], json!(wallet.identity.own_did()));
}

#[tokio::test]
async fn wallet_redeems_a_by_value_offer_without_tx_code() {
    let (issuer, issuer_base) = spawn_issuer().await;
    let issuer_did = issuer.identity.own_did().to_string();
    let (wallet, wallet_base) = spawn(Mode::CredentialService, |c| {
        c.with_trusted_issuer_dids(vec![issuer_did])
    })
    .await;
    let created = created_offer(&issuer, &issuer_base, false).await;
    let response = redeem(
        &wallet,
        &wallet_base,
        json!({"credential_offer": created["credential_offer"]}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        wallet
            .store
            .credentials_of_types(&["MembershipCredential".to_string()])
            .len(),
        1
    );
}

#[tokio::test]
async fn wallet_refuses_credentials_from_an_issuer_it_does_not_trust() {
    let (issuer, issuer_base) = spawn_issuer().await;
    let (wallet, wallet_base) = spawn(Mode::CredentialService, |c| c).await;
    let created = created_offer(&issuer, &issuer_base, false).await;
    let response = redeem(
        &wallet,
        &wallet_base,
        json!({"credential_offer": created["credential_offer"]}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(
        wallet.store.all().is_empty(),
        "nothing is stored from an untrusted issuer"
    );
}

#[tokio::test]
async fn wallet_does_not_contact_hosts_outside_its_allow_list() {
    let (wallet, wallet_base) = spawn(Mode::CredentialService, |c| c).await;
    let response = redeem(
        &wallet,
        &wallet_base,
        json!({"credential_offer_uri": "http://169.254.169.254/latest/meta-data"}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body: Value = response.json().await.unwrap();
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("not on this service's allow-list"),
        "{body}"
    );
}

#[tokio::test]
async fn wallet_requires_the_tx_code_an_offer_asks_for() {
    let (issuer, issuer_base) = spawn_issuer().await;
    let issuer_did = issuer.identity.own_did().to_string();
    let (wallet, wallet_base) = spawn(Mode::CredentialService, |c| {
        c.with_trusted_issuer_dids(vec![issuer_did])
    })
    .await;
    let created = created_offer(&issuer, &issuer_base, true).await;
    let response = redeem(
        &wallet,
        &wallet_base,
        json!({"credential_offer": created["credential_offer"]}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}
