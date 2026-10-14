//! The Wallet against a stand-in issuer that demands what the OpenID
//! Foundation's `oid4vci-1_0-wallet-test-plan` demands with
//! `client_auth_type=private_key_jwt`, `sender_constrain=dpop` and
//! `vci_grant_type=pre_authorization_code`: a `private_key_jwt` client
//! assertion, DPoP proofs answering a `use_dpop_nonce` challenge at both the
//! token and the credential endpoint, `credential_identifiers` from the
//! token response, and an `sd_jwt_vc` credential. The offer arrives the way
//! the conformance suite delivers it: a GET on the Wallet's Credential
//! Offer Endpoint.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use identity_hub_core::dcp_core::{self, b64_encode};
use identity_hub_core::oid4vci::{CLIENT_ASSERTION_TYPE_JWT_BEARER, DPOP_JWT_TYP, PROOF_JWT_TYP};
use identity_hub_http::AppState;
use identity_hub_http::config::{Config, Mode};
use p256::ecdsa::VerifyingKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const CLIENT_ID: &str = "hub-wallet-client";
const PRE_AUTH_CODE: &str = "pre-auth-code";
const TX_CODE: &str = "123456";
const AS_NONCE: &str = "as-nonce-1";
const RS_NONCE: &str = "rs-nonce-1";
const ACCESS_TOKEN: &str = "dpop-bound-at";
const CONFIG_ID: &str = "eu.example.sd_jwt_vc";
const CREDENTIAL_IDENTIFIER: &str = "sd-jwt-instance-1";

struct Issuer {
    base: String,
    wallet_key: VerifyingKey,
    wallet_kid: String,
    wallet_x: String,
    c_nonce: Option<String>,
    token_calls: usize,
    credential_calls: usize,
    failures: Vec<String>,
}

type S = Arc<Mutex<Issuer>>;

fn oauth_error(status: StatusCode, error: &str, nonce: Option<&str>) -> Response {
    let mut response = (status, Json(json!({ "error": error }))).into_response();
    if let Some(nonce) = nonce {
        response
            .headers_mut()
            .insert("DPoP-Nonce", nonce.parse().unwrap());
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                "WWW-Authenticate",
                "DPoP error=\"use_dpop_nonce\"".parse().unwrap(),
            );
        }
    }
    response
}

/// Checks a DPoP proof: `typ`, signature by the `jwk` it carries (which must
/// be the wallet's key), `htm`/`htu`, and the expected `nonce`/`ath`.
fn check_dpop(
    st: &Issuer,
    headers: &HeaderMap,
    htu: &str,
    access_token: Option<&str>,
) -> Result<Option<String>, String> {
    let proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or("no DPoP header")?;
    let (_, header, claims) = dcp_core::decode_jws_unverified(proof)?;
    if header["typ"] != DPOP_JWT_TYP {
        return Err(format!("DPoP typ {}", header["typ"]));
    }
    let jwk: dcp_core::Jwk =
        serde_json::from_value(header["jwk"].clone()).map_err(|e| e.to_string())?;
    let key = dcp_core::jwk_to_verifying_key(&jwk)?;
    if key != st.wallet_key {
        return Err("DPoP key is not the wallet's key".into());
    }
    dcp_core::verify_jws_signature(proof, &key)?;
    if claims["htm"] != "POST" || claims["htu"] != htu || claims["jti"].as_str().is_none() {
        return Err(format!("DPoP htm/htu/jti wrong: {claims}"));
    }
    if let Some(token) = access_token {
        let ath = b64_encode(Sha256::digest(token.as_bytes()));
        if claims["ath"] != ath {
            return Err("DPoP ath does not hash the access token".into());
        }
    }
    Ok(claims["nonce"].as_str().map(str::to_string))
}

async fn issuer_metadata(State(s): State<S>) -> Json<Value> {
    let base = s.lock().unwrap().base.clone();
    Json(json!({
        "credential_issuer": base,
        "credential_endpoint": format!("{base}/credential"),
        "nonce_endpoint": format!("{base}/nonce"),
        "credential_configurations_supported": {
            CONFIG_ID: {
                "format": "dc+sd-jwt",
                "vct": "urn:eu.europa.ec.eudi:pid:1",
                "cryptographic_binding_methods_supported": ["jwk"],
                "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256"] } }
            }
        }
    }))
}

async fn as_metadata(State(s): State<S>) -> Json<Value> {
    let base = s.lock().unwrap().base.clone();
    Json(json!({
        "issuer": base,
        "token_endpoint": format!("{base}/token"),
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "dpop_signing_alg_values_supported": ["ES256"],
    }))
}

async fn token(
    State(s): State<S>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let mut st = s.lock().unwrap();
    st.token_calls += 1;
    let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let token_url = format!("{}/token", st.base);
    let nonce = match check_dpop(&st, &headers, &token_url, None) {
        Ok(n) => n,
        Err(e) => {
            st.failures.push(format!("token DPoP: {e}"));
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_dpop_proof", None);
        }
    };
    if nonce.as_deref() != Some(AS_NONCE) {
        return oauth_error(StatusCode::BAD_REQUEST, "use_dpop_nonce", Some(AS_NONCE));
    }
    if get("pre-authorized_code").as_deref() != Some(PRE_AUTH_CODE)
        || get("tx_code").as_deref() != Some(TX_CODE)
    {
        st.failures.push("token: wrong code or tx_code".into());
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", None);
    }
    if get("client_id").as_deref() != Some(CLIENT_ID)
        || get("client_assertion_type").as_deref() != Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
    {
        st.failures
            .push("token: client authentication parameters".into());
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", None);
    }
    let assertion = get("client_assertion").unwrap_or_default();
    let checked = dcp_core::decode_jws_unverified(&assertion).and_then(|(_, header, claims)| {
        dcp_core::verify_jws_signature(&assertion, &st.wallet_key)?;
        if header["kid"] != st.wallet_kid.as_str()
            || claims["iss"] != CLIENT_ID
            || claims["sub"] != CLIENT_ID
            || claims["aud"] != st.base.as_str()
        {
            return Err(format!("client assertion claims: {header} {claims}"));
        }
        Ok(())
    });
    if let Err(e) = checked {
        st.failures.push(format!("token: {e}"));
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", None);
    }
    Json(json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "DPoP",
        "expires_in": 300,
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": CONFIG_ID,
            "credential_identifiers": [CREDENTIAL_IDENTIFIER]
        }]
    }))
    .into_response()
}

async fn nonce(State(s): State<S>) -> Response {
    let n = uuid::Uuid::new_v4().to_string();
    s.lock().unwrap().c_nonce = Some(n.clone());
    // Resource-server DPoP nonce piggybacked on the nonce response.
    let mut response = Json(json!({ "c_nonce": n })).into_response();
    response
        .headers_mut()
        .insert("DPoP-Nonce", "stale-rs-nonce".parse().unwrap());
    response
}

async fn credential(State(s): State<S>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let mut st = s.lock().unwrap();
    st.credential_calls += 1;
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("DPoP {ACCESS_TOKEN}"))
    {
        st.failures
            .push("credential: not a DPoP authorization".into());
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token", None);
    }
    let url = format!("{}/credential", st.base);
    match check_dpop(&st, &headers, &url, Some(ACCESS_TOKEN)) {
        Ok(Some(n)) if n == RS_NONCE => {}
        Ok(_) => return oauth_error(StatusCode::UNAUTHORIZED, "use_dpop_nonce", Some(RS_NONCE)),
        Err(e) => {
            st.failures.push(format!("credential DPoP: {e}"));
            return oauth_error(StatusCode::UNAUTHORIZED, "invalid_dpop_proof", None);
        }
    }
    if body["credential_identifier"] != CREDENTIAL_IDENTIFIER
        || body.get("credential_configuration_id").is_some()
    {
        st.failures.push(format!("credential: request {body}"));
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_credential_request", None);
    }
    let proof = body["proofs"]["jwt"][0].as_str().unwrap_or_default();
    let checked = dcp_core::decode_jws_unverified(proof).and_then(|(_, header, claims)| {
        dcp_core::verify_jws_signature(proof, &st.wallet_key)?;
        // The configuration only binds to raw keys ("jwk"), so the proof
        // carries the key inline instead of the DID URL.
        if header["typ"] != PROOF_JWT_TYP
            || header.get("kid").is_some()
            || header["jwk"]["x"] != st.wallet_x.as_str()
            || claims["iss"] != CLIENT_ID
            || claims["aud"] != st.base.as_str()
            || claims["nonce"].as_str() != st.c_nonce.as_deref()
        {
            return Err(format!("key proof: {header} {claims}"));
        }
        Ok(())
    });
    if let Err(e) = checked {
        st.failures.push(format!("credential: {e}"));
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_proof", None);
    }
    Json(json!({ "credentials": [{ "credential": "eyJhbGciOiJFUzI1NiJ9.e30.sig~disclosure~" }] }))
        .into_response()
}

async fn spawn_wallet(configure: impl FnOnce(Config) -> Config) -> (Arc<AppState>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = configure(Config::for_test(
        Mode::CredentialService,
        addr,
        format!("127.0.0.1:{}", addr.port()),
    ));
    let (state, router) = identity_hub_http::build(config);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (state, format!("http://{addr}"))
}

async fn spawn_issuer(wallet: &AppState) -> (String, S) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state: S = Arc::new(Mutex::new(Issuer {
        base: base.clone(),
        wallet_key: *wallet.identity.key_pair.signing_key().verifying_key(),
        wallet_kid: wallet.identity.own_key_id().to_string(),
        wallet_x: dcp_core::b64_encode(wallet.identity.key_pair.public_key_xy.0),
        c_nonce: None,
        token_calls: 0,
        credential_calls: 0,
        failures: Vec::new(),
    }));
    let app = Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route("/.well-known/oauth-authorization-server", get(as_metadata))
        .route("/token", post(token))
        .route("/nonce", post(nonce))
        .route("/credential", post(credential))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, state)
}

fn offer(issuer_base: &str) -> Value {
    json!({
        "credential_issuer": issuer_base,
        "credential_configuration_ids": [CONFIG_ID],
        "grants": { "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": PRE_AUTH_CODE,
            "tx_code": { "length": 6, "input_mode": "numeric" }
        } }
    })
}

#[tokio::test]
async fn offer_endpoint_redeems_with_dpop_and_private_key_jwt() {
    let (wallet, wallet_base) = spawn_wallet(|mut c| {
        c.oid4vci_client_id = Some(CLIENT_ID.to_string());
        c.oid4vci_offer_endpoint = true;
        c.oid4vci_offer_tx_code = Some(TX_CODE.to_string());
        c
    })
    .await;
    let (issuer_base, issuer) = spawn_issuer(&wallet).await;

    let url = reqwest::Url::parse_with_params(
        &format!("{wallet_base}/oid4vci/wallet/credential_offer"),
        &[("credential_offer", offer(&issuer_base).to_string())],
    )
    .unwrap();
    let response = reqwest::get(url).await.unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();

    let st = issuer.lock().unwrap();
    assert!(st.failures.is_empty(), "issuer saw: {:?}", st.failures);
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    // One use_dpop_nonce challenge at each endpoint, answered once.
    assert_eq!(st.token_calls, 2);
    assert_eq!(st.credential_calls, 2);

    // An sd_jwt_vc credential completes the exchange but is not stored:
    // DCP can only present JWT VCs.
    assert_eq!(body["stored"], json!([]));
    assert_eq!(
        body["not_stored"][0]["credential_configuration_id"],
        CONFIG_ID
    );
    assert_eq!(body["not_stored"][0]["format"], "dc+sd-jwt");
    assert!(wallet.store.all().is_empty());
}

#[tokio::test]
async fn offer_endpoint_is_not_mounted_by_default() {
    let (_, wallet_base) = spawn_wallet(|c| c).await;
    let response = reqwest::get(format!(
        "{wallet_base}/oid4vci/wallet/credential_offer?credential_offer_uri=http://127.0.0.1:1/o"
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn offer_endpoint_stays_inside_the_outbound_allow_list() {
    let (_, wallet_base) = spawn_wallet(|mut c| {
        c.oid4vci_offer_endpoint = true;
        c
    })
    .await;
    let response = reqwest::get(format!(
        "{wallet_base}/oid4vci/wallet/credential_offer?credential_offer_uri=http://169.254.169.254/latest/meta-data"
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
}
