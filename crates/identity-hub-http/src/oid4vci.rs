//! OpenID for Verifiable Credential Issuance (OID4VCI 1.0), served side by
//! side with DCP on the same process. Each DCP role gets its OID4VCI
//! counterpart:
//!
//! - **Issuer Service = Credential Issuer** (Pre-Authorized Code flow):
//!   `GET /.well-known/openid-credential-issuer`,
//!   `GET /.well-known/oauth-authorization-server` (this issuer is its own
//!   Authorization Server), `POST /oid4vci/token`, `POST /oid4vci/nonce`,
//!   `POST /oid4vci/credential`, plus `GET /oid4vci/offers/{id}` serving
//!   Credential Offers by reference. Issues the exact same JWT VC the DCP
//!   Credential Request API delivers (`handlers::mint_supported_credential`).
//! - **Credential Service = Wallet**: `POST /oid4vci/wallet/offers` redeems a
//!   Credential Offer from any OID4VCI issuer (this hub's own Issuer Service
//!   or a third party) and stores the result in the same credential store
//!   the DCP Storage API writes to - so a credential obtained over OID4VCI is
//!   presentable over DCP's Presentation API with no further step.
//!
//! Two operator endpoints sit outside both specifications, since neither
//! defines how an offer is created or how a wallet is told to redeem one:
//! `POST /oid4vci/offers` (Issuer Service) and `POST /oid4vci/wallet/offers`
//! (Credential Service). Both require HTTP Basic authentication with this
//! process's configured STS client credentials
//! (`Config::sts_client_id`/`sts_client_secret`) - the one operator secret
//! this bootstrap already has, rather than a second one.
//!
//! Security posture carried over from the DCP side, deliberately:
//! - every outbound request the Wallet makes (offer by reference, issuer
//!   and AS metadata, token, nonce, credential endpoints, the VC issuer's
//!   DID) is checked against `AppState::outbound` first;
//! - a credential is only stored if its JWS verifies against its own `iss`
//!   DID *and* that DID is on `Config::trusted_issuer_dids` (deny by
//!   default, same as `POST /credentials`) *and* it is bound to this
//!   Credential Service's own DID;
//! - every issuer-side table (offers, pre-authorized codes, access tokens,
//!   nonces) is fixed-capacity with oldest-first eviction and per-entry
//!   expiry, like `state::RequestTable`;
//! - pre-authorized codes, `c_nonce` values and offers are single-use, and a
//!   Transaction Code gets [`MAX_TX_CODE_ATTEMPTS`] tries before its code is
//!   burned.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use dcp_core::{Jwk, find_verifying_key, jwk_to_verifying_key, now_secs, resolve_did};
use identity_hub_core::messages::CredentialContainer;
use identity_hub_core::oid4vci::{
    AUTHORIZATION_SERVER_WELL_KNOWN, AuthorizationServerMetadata, CLIENT_ASSERTION_TYPE_JWT_BEARER,
    CREDENTIAL_ISSUER_WELL_KNOWN, CREDENTIAL_OFFER_SCHEME, CredentialConfiguration,
    CredentialDefinition, CredentialIssuerMetadata, CredentialOffer, CredentialRequest,
    CredentialResponse, ErrorResponse, FORMAT_JWT_VC_JSON, IssuedCredential, NonceResponse,
    OfferGrants, PRE_AUTHORIZED_CODE_GRANT, PreAuthorizedCodeGrant, ProofKey, TokenResponse,
    TxCodeDescription, build_client_assertion, build_dpop_proof, build_jwt_proof_for_client,
    inspect_jwt_proof, well_known_url,
};
use identity_hub_core::store::StoredCredentialBatch;

use crate::auth::check_trusted_issuer;
use crate::config::{Config, Mode};
use crate::handlers::mint_supported_credential;
use crate::state::AppState;
use crate::validation::verify_credential_proofs;

/// Capacity of each issuer-side table - same order of magnitude, and same
/// reasoning, as `state::MAX_TRACKED_REQUESTS`.
pub const MAX_OID4VCI_ENTRIES: usize = 2048;
/// How long a Credential Offer (and its pre-authorized code) stays redeemable.
pub const OFFER_TTL_SECS: u64 = 600;
/// Lifetime of an access token issued by `POST /oid4vci/token`.
pub const ACCESS_TOKEN_TTL_SECS: u64 = 300;
/// Lifetime of a `c_nonce` issued by `POST /oid4vci/nonce`.
pub const NONCE_TTL_SECS: u64 = 300;
/// Wrong Transaction Codes tolerated before the pre-authorized code is burned.
pub const MAX_TX_CODE_ATTEMPTS: u32 = 3;
/// Digits in a generated Transaction Code.
const TX_CODE_LENGTH: u32 = 6;

// ---- Bounded, expiring table ----

/// A fixed-capacity, insertion-ordered map with per-entry expiry: the same
/// oldest-first eviction `state::RequestTable` uses, plus an `expires_at`
/// so a lookup never returns a stale entry.
pub struct ExpiringTable<V> {
    entries: HashMap<String, (u64, V)>,
    order: VecDeque<String>,
    capacity: usize,
}

impl<V> ExpiringTable<V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn insert(&mut self, key: String, ttl_secs: u64, value: V) {
        if self
            .entries
            .insert(key.clone(), (now_secs() + ttl_secs, value))
            .is_none()
        {
            self.order.push_back(key);
        }
        while self.entries.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.entries.remove(&oldest);
                }
                None => break,
            }
        }
    }

    /// Returns the live entry for `key`, dropping it first if it expired.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        if self
            .entries
            .get(key)
            .is_some_and(|(exp, _)| *exp <= now_secs())
        {
            self.entries.remove(key);
            return None;
        }
        self.entries.get_mut(key).map(|(_, v)| v)
    }

    /// Removes and returns the live entry for `key` (single-use semantics).
    pub fn take(&mut self, key: &str) -> Option<V> {
        let (exp, value) = self.entries.remove(key)?;
        (exp > now_secs()).then_some(value)
    }
}

/// A pre-authorized code handed out inside a Credential Offer.
pub struct PreAuthorizedGrant {
    pub credential_configuration_ids: Vec<String>,
    pub tx_code: Option<String>,
    pub failed_attempts: u32,
}

/// What an access token from `POST /oid4vci/token` authorizes.
pub struct AccessGrant {
    pub credential_configuration_ids: Vec<String>,
}

/// Issuer-side OID4VCI state (Issuer Service mode).
pub struct IssuerState {
    pub offers: Mutex<ExpiringTable<CredentialOffer>>,
    pub pre_authorized_codes: Mutex<ExpiringTable<PreAuthorizedGrant>>,
    pub access_tokens: Mutex<ExpiringTable<AccessGrant>>,
    pub nonces: Mutex<ExpiringTable<()>>,
}

impl Default for IssuerState {
    fn default() -> Self {
        Self {
            offers: Mutex::new(ExpiringTable::new(MAX_OID4VCI_ENTRIES)),
            pre_authorized_codes: Mutex::new(ExpiringTable::new(MAX_OID4VCI_ENTRIES)),
            access_tokens: Mutex::new(ExpiringTable::new(MAX_OID4VCI_ENTRIES)),
            nonces: Mutex::new(ExpiringTable::new(MAX_OID4VCI_ENTRIES)),
        }
    }
}

pub fn routes(config: &Config) -> Router<Arc<AppState>> {
    match config.mode {
        Mode::IssuerService => Router::new()
            .route(
                &format!("/.well-known/{CREDENTIAL_ISSUER_WELL_KNOWN}"),
                get(credential_issuer_metadata),
            )
            .route(
                &format!("/.well-known/{AUTHORIZATION_SERVER_WELL_KNOWN}"),
                get(authorization_server_metadata),
            )
            .route("/oid4vci/offers", post(create_offer))
            .route("/oid4vci/offers/{id}", get(offer_by_reference))
            .route("/oid4vci/token", post(token))
            .route("/oid4vci/nonce", post(nonce))
            .route("/oid4vci/credential", post(credential)),
        Mode::CredentialService => {
            let router = Router::new().route("/oid4vci/wallet/offers", post(redeem_offer));
            if config.oid4vci_offer_endpoint {
                router.route(
                    "/oid4vci/wallet/credential_offer",
                    get(credential_offer_endpoint),
                )
            } else {
                router
            }
        }
    }
}

// ---- Shared helpers ----

fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn random_tx_code() -> String {
    let n = Uuid::new_v4().as_u128() % 10u128.pow(TX_CODE_LENGTH);
    format!("{n:0width$}", width = TX_CODE_LENGTH as usize)
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn oauth_error(status: StatusCode, error: &str, description: impl Into<String>) -> Response {
    let description = description.into();
    tracing::warn!(error, %description, "rejecting OID4VCI request");
    let mut response = (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
            error_description: Some(description),
        }),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&format!("Bearer error=\"{error}\""))
                .expect("error code is a valid header value"),
        );
    }
    no_store(response)
}

/// Checks HTTP Basic credentials against this process's STS client
/// credentials - the operator gate for the two endpoints neither
/// specification defines (see this module's doc comment).
///
/// Returns the rejection to send, or `None` when the caller is the operator.
fn operator_rejection(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let decoded = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let authorized = decoded
        .as_deref()
        .and_then(|s| s.split_once(':'))
        .is_some_and(|(id, secret)| {
            id == state.config.sts_client_id && secret == state.config.sts_client_secret
        });
    if authorized {
        None
    } else {
        let mut response = oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "operator endpoint requires HTTP Basic client credentials",
        );
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
        Some(response)
    }
}

// ---- Credential Issuer (Issuer Service mode) ----

/// This Issuer Service's Credential Issuer Identifier: its own base URL.
fn credential_issuer_id(state: &AppState) -> String {
    state.base_url()
}

fn configurations_supported(
    state: &AppState,
) -> std::collections::BTreeMap<String, CredentialConfiguration> {
    let supported = &state.supported_credential;
    let credential_type = supported
        .credential_type
        .clone()
        .unwrap_or_else(|| "VerifiableCredential".to_string());
    std::collections::BTreeMap::from([(
        supported.id.clone(),
        CredentialConfiguration {
            format: FORMAT_JWT_VC_JSON.to_string(),
            scope: Some(credential_type.clone()),
            cryptographic_binding_methods_supported: vec!["did:web".to_string(), "jwk".to_string()],
            credential_signing_alg_values_supported: vec!["ES256".to_string()],
            proof_types_supported: Some(
                json!({"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}),
            ),
            credential_definition: Some(CredentialDefinition {
                types: vec!["VerifiableCredential".to_string(), credential_type],
            }),
        },
    )])
}

/// `GET /.well-known/openid-credential-issuer` (OID4VCI section 12.2).
/// `authorization_servers` is omitted: this issuer is its own AS.
async fn credential_issuer_metadata(State(state): State<Arc<AppState>>) -> Response {
    let base = credential_issuer_id(&state);
    Json(CredentialIssuerMetadata {
        credential_issuer: base.clone(),
        authorization_servers: Vec::new(),
        credential_endpoint: format!("{base}/oid4vci/credential"),
        nonce_endpoint: Some(format!("{base}/oid4vci/nonce")),
        credential_configurations_supported: configurations_supported(&state),
    })
    .into_response()
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414), advertising
/// only the Pre-Authorized Code grant, anonymously.
async fn authorization_server_metadata(State(state): State<Arc<AppState>>) -> Response {
    let base = credential_issuer_id(&state);
    Json(AuthorizationServerMetadata {
        issuer: base.clone(),
        token_endpoint: format!("{base}/oid4vci/token"),
        grant_types_supported: vec![PRE_AUTHORIZED_CODE_GRANT.to_string()],
        pre_authorized_grant_anonymous_access_supported: Some(true),
        dpop_signing_alg_values_supported: Vec::new(),
    })
    .into_response()
}

#[derive(Debug, Default, Deserialize)]
struct CreateOfferBody {
    /// Defaults to every configuration this issuer supports.
    #[serde(default)]
    credential_configuration_ids: Option<Vec<String>>,
    /// Require a Transaction Code (generated here, returned once to the
    /// operator to deliver to the holder out of band).
    #[serde(default)]
    tx_code: bool,
}

#[derive(Debug, Serialize)]
struct CreateOfferResponse {
    credential_offer: CredentialOffer,
    credential_offer_uri: String,
    /// `openid-credential-offer://?credential_offer_uri=...`, ready for a
    /// QR code or deep link.
    offer_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_code: Option<String>,
}

/// `POST /oid4vci/offers` (operator): mints a Pre-Authorized Code Credential
/// Offer, servable by value or by reference.
async fn create_offer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<CreateOfferBody>>,
) -> Response {
    if let Some(response) = operator_rejection(&state, &headers) {
        return response;
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let supported = configurations_supported(&state);
    let ids = body
        .credential_configuration_ids
        .unwrap_or_else(|| supported.keys().cloned().collect());
    if ids.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "credential_configuration_ids must not be empty",
        );
    }
    if let Some(unknown) = ids.iter().find(|id| !supported.contains_key(*id)) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unknown_credential_configuration",
            format!("'{unknown}' is not offered by this issuer"),
        );
    }

    let code = random_token();
    let tx_code = body.tx_code.then(random_tx_code);
    let offer = CredentialOffer {
        credential_issuer: credential_issuer_id(&state),
        credential_configuration_ids: ids.clone(),
        grants: Some(OfferGrants {
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: code.clone(),
                tx_code: tx_code.as_ref().map(|_| TxCodeDescription {
                    input_mode: Some("numeric".to_string()),
                    length: Some(TX_CODE_LENGTH),
                    description: Some("Transaction code delivered by the issuer".to_string()),
                }),
                authorization_server: None,
            }),
        }),
    };
    state
        .oid4vci
        .pre_authorized_codes
        .lock()
        .expect("pre-authorized code lock poisoned")
        .insert(
            code,
            OFFER_TTL_SECS,
            PreAuthorizedGrant {
                credential_configuration_ids: ids,
                tx_code: tx_code.clone(),
                failed_attempts: 0,
            },
        );
    let offer_id = Uuid::new_v4().to_string();
    state
        .oid4vci
        .offers
        .lock()
        .expect("offers lock poisoned")
        .insert(offer_id.clone(), OFFER_TTL_SECS, offer.clone());

    let credential_offer_uri =
        format!("{}/oid4vci/offers/{offer_id}", credential_issuer_id(&state));
    let offer_uri = reqwest::Url::parse_with_params(
        CREDENTIAL_OFFER_SCHEME,
        &[("credential_offer_uri", credential_offer_uri.as_str())],
    )
    .map(String::from)
    .unwrap_or_else(|_| {
        format!("{CREDENTIAL_OFFER_SCHEME}?credential_offer_uri={credential_offer_uri}")
    });
    no_store(
        (
            StatusCode::CREATED,
            Json(CreateOfferResponse {
                credential_offer: offer,
                credential_offer_uri,
                offer_uri,
                tx_code,
            }),
        )
            .into_response(),
    )
}

/// `GET /oid4vci/offers/{id}`: the Credential Offer behind a
/// `credential_offer_uri` (section 4.1.3). Single-use, like the
/// pre-authorized code it carries.
async fn offer_by_reference(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state
        .oid4vci
        .offers
        .lock()
        .expect("offers lock poisoned")
        .take(&id)
    {
        Some(offer) => no_store(Json(offer).into_response()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `POST /oid4vci/token` (section 6): Pre-Authorized Code grant only.
async fn token(
    State(state): State<Arc<AppState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if form.get("grant_type").map(String::as_str) != Some(PRE_AUTHORIZED_CODE_GRANT) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only the pre-authorized_code grant is supported",
        );
    }
    let Some(code) = form.get("pre-authorized_code") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "pre-authorized_code is required",
        );
    };
    let ids = {
        let mut codes = state
            .oid4vci
            .pre_authorized_codes
            .lock()
            .expect("pre-authorized code lock poisoned");
        let Some(grant) = codes.get_mut(code) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "pre-authorized_code is unknown, expired, or already used",
            );
        };
        match (&grant.tx_code, form.get("tx_code")) {
            (None, None) => {}
            (None, Some(_)) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "this offer does not use a tx_code",
                );
            }
            (Some(_), None) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "tx_code is required for this offer",
                );
            }
            (Some(expected), Some(given)) if expected != given => {
                grant.failed_attempts += 1;
                if grant.failed_attempts >= MAX_TX_CODE_ATTEMPTS {
                    codes.take(code);
                }
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "wrong tx_code");
            }
            (Some(_), Some(_)) => {}
        }
        codes
            .take(code)
            .expect("grant was live under this same lock")
            .credential_configuration_ids
    };
    let access_token = random_token();
    state
        .oid4vci
        .access_tokens
        .lock()
        .expect("access token lock poisoned")
        .insert(
            access_token.clone(),
            ACCESS_TOKEN_TTL_SECS,
            AccessGrant {
                credential_configuration_ids: ids,
            },
        );
    no_store(
        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: ACCESS_TOKEN_TTL_SECS,
            authorization_details: Vec::new(),
        })
        .into_response(),
    )
}

/// `POST /oid4vci/nonce` (section 7): a fresh, single-use `c_nonce`.
async fn nonce(State(state): State<Arc<AppState>>) -> Response {
    let c_nonce = random_token();
    state
        .oid4vci
        .nonces
        .lock()
        .expect("nonce lock poisoned")
        .insert(c_nonce.clone(), NONCE_TTL_SECS, ());
    no_store(Json(NonceResponse { c_nonce }).into_response())
}

/// `POST /oid4vci/credential` (section 8): exactly one `jwt` key proof,
/// carrying a `c_nonce` from `/oid4vci/nonce`, signed by a `did:web` key
/// (resolved, subject to the outbound allow-list) or an inline P-256 `jwk`
/// (holder identified as its `did:jwk`).
async fn credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let authorized_ids = {
        let mut tokens = state
            .oid4vci
            .access_tokens
            .lock()
            .expect("access token lock poisoned");
        match bearer.and_then(|t| tokens.get_mut(t)) {
            Some(grant) => grant.credential_configuration_ids.clone(),
            None => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "missing, unknown or expired access token",
                );
            }
        }
    };
    let request: CredentialRequest = match serde_json::from_value(body) {
        Ok(request) => request,
        Err(err) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_credential_request",
                err.to_string(),
            );
        }
    };
    let Some(config_id) = request.credential_configuration_id.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential_request",
            "credential_configuration_id is required (credential_identifier is not supported)",
        );
    };
    if !configurations_supported(&state).contains_key(config_id) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unknown_credential_configuration",
            format!("'{config_id}' is not offered by this issuer"),
        );
    }
    if !authorized_ids.iter().any(|id| id == config_id) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_credential_request",
            format!("the access token does not cover '{config_id}'"),
        );
    }
    let proofs = request.jwt_proofs();
    let [proof] = proofs.as_slice() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "exactly one jwt key proof is required",
        );
    };
    let issuer_id = credential_issuer_id(&state);
    let (key, proof_nonce) = match inspect_jwt_proof(proof, &issuer_id) {
        Ok(inspected) => inspected,
        Err(err) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_proof", err.to_string()),
    };
    if let Err(err) = verify_proof_signature(&state, proof, &key).await {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_proof", err);
    }
    let nonce_ok = proof_nonce.is_some_and(|n| {
        state
            .oid4vci
            .nonces
            .lock()
            .expect("nonce lock poisoned")
            .take(&n)
            .is_some()
    });
    if !nonce_ok {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_nonce",
            "the proof must carry an unused c_nonce from the nonce endpoint",
        );
    }

    let vc = mint_supported_credential(&state, key.holder_did());
    tracing::info!(
        holder = key.holder_did(),
        config_id,
        "issued credential over OID4VCI"
    );
    no_store(
        Json(CredentialResponse {
            credentials: vec![IssuedCredential {
                credential: json!(vc),
            }],
            credential: None,
            transaction_id: None,
        })
        .into_response(),
    )
}

async fn verify_proof_signature(
    state: &AppState,
    proof: &str,
    key: &ProofKey,
) -> Result<(), String> {
    let verifying_key = match key {
        ProofKey::Jwk { x, y, .. } => jwk_to_verifying_key(&Jwk {
            x: x.clone(),
            y: y.clone(),
        })?,
        ProofKey::DidUrl { kid, did } => {
            if !did.starts_with("did:web:") {
                return Err(format!("unsupported DID method in kid '{kid}'"));
            }
            state
                .outbound
                .check_did(did, state.config.insecure_http)
                .map_err(|e| e.to_string())?;
            let doc = resolve_did(&state.http, did, state.config.insecure_http).await?;
            find_verifying_key(&doc, kid)?
        }
    };
    dcp_core::verify_jws_signature(proof, &verifying_key)
}

// ---- Wallet (Credential Service mode) ----

/// `POST /oid4vci/wallet/offers` body: exactly one way of conveying the
/// offer, plus the Transaction Code when the offer asks for one.
#[derive(Debug, Default, Deserialize)]
pub struct RedeemOfferBody {
    /// The whole `openid-credential-offer://...` URI (by value or by reference).
    #[serde(default)]
    pub offer: Option<String>,
    #[serde(default)]
    pub credential_offer: Option<CredentialOffer>,
    #[serde(default)]
    pub credential_offer_uri: Option<String>,
    #[serde(default)]
    pub tx_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemedCredential {
    pub credential_configuration_id: String,
    pub credential_type: String,
}

/// Credentials the issuer handed over but this service will not keep,
/// because DCP cannot present their format.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotStoredCredential {
    pub credential_configuration_id: String,
    pub format: String,
    pub count: usize,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemOfferResponse {
    pub credential_issuer: String,
    pub stored: Vec<RedeemedCredential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_stored: Vec<NotStoredCredential>,
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("invalid offer: {0}")]
    InvalidOffer(String),
    #[error("outbound destination is not allowed: {0}")]
    Outbound(String),
    #[error("credential issuer failed: {0}")]
    Upstream(String),
    #[error("issued credential rejected: {0}")]
    Rejected(String),
}

impl WalletError {
    fn status(&self) -> StatusCode {
        match self {
            WalletError::InvalidOffer(_) => StatusCode::BAD_REQUEST,
            WalletError::Outbound(_) | WalletError::Rejected(_) => StatusCode::FORBIDDEN,
            WalletError::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

/// `POST /oid4vci/wallet/offers` (operator): redeems a Credential Offer
/// end to end and stores every credential it yields.
async fn redeem_offer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RedeemOfferBody>,
) -> Response {
    if let Some(response) = operator_rejection(&state, &headers) {
        return response;
    }
    redemption_response(redeem(&state, body).await)
}

/// `GET /oid4vci/wallet/credential_offer` - the Wallet's own Credential
/// Offer Endpoint (section 4.1): an issuer (or a user agent it redirects)
/// delivers `credential_offer` or `credential_offer_uri` as a query
/// parameter, and the offer is redeemed exactly as
/// `POST /oid4vci/wallet/offers` would, with
/// `Config::oid4vci_offer_tx_code` as the Transaction Code.
///
/// Unauthenticated by nature, so mounted only when
/// `Config::oid4vci_offer_endpoint` is on (it is off by default). What an
/// anonymous caller can make this service do stays bounded by the same
/// gates as the operator route: it only ever contacts allow-listed hosts
/// (`AppState::outbound`), and only stores credentials from trusted issuers
/// that are bound to this service's own DID.
async fn credential_offer_endpoint(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let credential_offer = match params.get("credential_offer") {
        Some(json) => match serde_json::from_str(json) {
            Ok(offer) => Some(offer),
            Err(e) => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_credential_offer",
                    format!("credential_offer is not a Credential Offer: {e}"),
                );
            }
        },
        None => None,
    };
    let body = RedeemOfferBody {
        offer: None,
        credential_offer,
        credential_offer_uri: params.get("credential_offer_uri").cloned(),
        tx_code: state.config.oid4vci_offer_tx_code.clone(),
    };
    redemption_response(redeem(&state, body).await)
}

fn redemption_response(result: Result<RedeemOfferResponse, WalletError>) -> Response {
    match result {
        Ok(result) => Json(result).into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "OID4VCI offer redemption failed");
            let status = err.status();
            (
                status,
                Json(ErrorResponse {
                    error: "redemption_failed".to_string(),
                    error_description: Some(err.to_string()),
                }),
            )
                .into_response()
        }
    }
}

async fn get_json<T: serde::de::DeserializeOwned>(
    state: &AppState,
    url: &str,
) -> Result<T, WalletError> {
    state
        .outbound
        .check_url(url)
        .map_err(|e| WalletError::Outbound(e.to_string()))?;
    let response = state
        .http
        .get(url)
        .send()
        .await
        .map_err(|e| WalletError::Upstream(format!("GET {url}: {e}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Upstream(format!(
            "GET {url} returned HTTP {}",
            response.status()
        )));
    }
    response
        .json()
        .await
        .map_err(|e| WalletError::Upstream(format!("GET {url}: {e}")))
}

async fn read_json<T: serde::de::DeserializeOwned>(
    url: &str,
    response: reqwest::Response,
) -> Result<T, WalletError> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(WalletError::Upstream(format!(
            "POST {url} returned HTTP {status}: {body}"
        )));
    }
    response
        .json()
        .await
        .map_err(|e| WalletError::Upstream(format!("POST {url}: {e}")))
}

/// Parses an `openid-credential-offer://` URI into either an inline offer
/// or the `credential_offer_uri` to fetch it from.
fn parse_offer_uri(uri: &str) -> Result<(Option<CredentialOffer>, Option<String>), WalletError> {
    let parsed = reqwest::Url::parse(uri).map_err(|e| WalletError::InvalidOffer(e.to_string()))?;
    let mut by_value = None;
    let mut by_reference = None;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "credential_offer" => {
                by_value = Some(
                    serde_json::from_str(&value)
                        .map_err(|e| WalletError::InvalidOffer(e.to_string()))?,
                )
            }
            "credential_offer_uri" => by_reference = Some(value.into_owned()),
            _ => {}
        }
    }
    Ok((by_value, by_reference))
}

async fn resolve_offer(
    state: &AppState,
    body: &RedeemOfferBody,
) -> Result<CredentialOffer, WalletError> {
    let (mut by_value, mut by_reference) = (
        body.credential_offer.clone(),
        body.credential_offer_uri.clone(),
    );
    if let Some(uri) = &body.offer {
        let (v, r) = parse_offer_uri(uri)?;
        by_value = by_value.or(v);
        by_reference = by_reference.or(r);
    }
    match (by_value, by_reference) {
        (Some(offer), None) => Ok(offer),
        (None, Some(uri)) => get_json(state, &uri).await,
        _ => Err(WalletError::InvalidOffer(
            "give exactly one of a by-value credential_offer or a credential_offer_uri".to_string(),
        )),
    }
}

/// The whole Wallet side of the Pre-Authorized Code flow: resolve the
/// offer, discover the issuer and its AS, exchange the code for an access
/// token, then for each offered configuration fetch a fresh `c_nonce`,
/// prove possession of this Credential Service's own `did:web` key, and
/// verify and store what comes back.
///
/// Two optional hardenings the issuer's metadata can ask for, so the same
/// flow passes the OpenID Foundation's wallet conformance plan:
/// - **DPoP** (RFC 9449): when the AS advertises `ES256` in
///   `dpop_signing_alg_values_supported`, the token and every
///   access-token-bearing call carry a DPoP proof signed with this
///   service's key, and a `use_dpop_nonce` challenge is answered once.
/// - **`private_key_jwt`** (RFC 7523): when `Config::oid4vci_client_id` is
///   set, the token request authenticates as that client with an assertion
///   signed by this service's DID key, and key proofs carry it as `iss`.
///
/// A configuration whose format is not `jwt_vc_json` is still requested,
/// so the exchange completes, but its credentials are reported under
/// `not_stored` and never written to the store: DCP can only present JWT
/// VCs (`validation::verify_credential_proofs`).
pub async fn redeem(
    state: &AppState,
    body: RedeemOfferBody,
) -> Result<RedeemOfferResponse, WalletError> {
    let offer = resolve_offer(state, &body).await?;
    let grant = offer
        .grants
        .as_ref()
        .and_then(|g| g.pre_authorized_code.clone())
        .ok_or_else(|| {
            WalletError::InvalidOffer(
                "only offers with a pre-authorized_code grant are supported".to_string(),
            )
        })?;
    if grant.tx_code.is_some() && body.tx_code.is_none() {
        return Err(WalletError::InvalidOffer(
            "this offer requires a tx_code".to_string(),
        ));
    }

    let metadata_url = well_known_url(&offer.credential_issuer, CREDENTIAL_ISSUER_WELL_KNOWN)
        .map_err(WalletError::InvalidOffer)?;
    let metadata: CredentialIssuerMetadata = get_json(state, &metadata_url).await?;
    if metadata.credential_issuer.trim_end_matches('/')
        != offer.credential_issuer.trim_end_matches('/')
    {
        return Err(WalletError::Upstream(
            "issuer metadata names a different credential_issuer than the offer".to_string(),
        ));
    }
    let authorization_server = grant
        .authorization_server
        .clone()
        .or_else(|| metadata.authorization_servers.first().cloned())
        .unwrap_or_else(|| offer.credential_issuer.clone());
    let as_metadata_url = well_known_url(&authorization_server, AUTHORIZATION_SERVER_WELL_KNOWN)
        .map_err(WalletError::InvalidOffer)?;
    let as_metadata: AuthorizationServerMetadata = get_json(state, &as_metadata_url).await?;

    let key_pair = &state.identity.key_pair;
    let client_id = state.config.oid4vci_client_id.as_deref();
    let use_dpop = as_metadata
        .dpop_signing_alg_values_supported
        .iter()
        .any(|alg| alg == "ES256");

    let mut form = vec![
        ("grant_type", PRE_AUTHORIZED_CODE_GRANT.to_string()),
        ("pre-authorized_code", grant.pre_authorized_code.clone()),
    ];
    if grant.tx_code.is_some()
        && let Some(tx_code) = &body.tx_code
    {
        form.push(("tx_code", tx_code.clone()));
    }
    if let Some(client_id) = client_id {
        form.push(("client_id", client_id.to_string()));
        form.push((
            "client_assertion_type",
            CLIENT_ASSERTION_TYPE_JWT_BEARER.to_string(),
        ));
    }
    let token_url = as_metadata.token_endpoint.clone();
    check_outbound(state, &token_url)?;
    let mut as_nonce: Option<String> = None;
    let mut token_response = None;
    for _ in 0..2 {
        let mut attempt = form.clone();
        if let Some(client_id) = client_id {
            // A fresh assertion per attempt: its `jti` is single-use.
            attempt.push((
                "client_assertion",
                build_client_assertion(key_pair, client_id, &as_metadata.issuer),
            ));
        }
        let mut request = state.http.post(&token_url).form(&attempt);
        if use_dpop {
            request = request.header(
                "DPoP",
                build_dpop_proof(key_pair, "POST", &token_url, as_nonce.as_deref(), None),
            );
        }
        let response = request
            .send()
            .await
            .map_err(|e| WalletError::Upstream(format!("POST {token_url}: {e}")))?;
        if use_dpop
            && as_nonce.is_none()
            && let Some(nonce) = dpop_nonce_challenge(&response)
        {
            as_nonce = Some(nonce);
            continue;
        }
        token_response = Some(response);
        break;
    }
    let token_response = token_response.ok_or_else(|| {
        WalletError::Upstream(format!(
            "POST {token_url}: repeated use_dpop_nonce challenge"
        ))
    })?;
    let token: TokenResponse = read_json(&token_url, token_response).await?;
    let dpop_bound = token.token_type.eq_ignore_ascii_case("dpop");
    if dpop_bound && !use_dpop {
        return Err(WalletError::Upstream(
            "token endpoint issued a DPoP-bound token the wallet did not ask for".to_string(),
        ));
    }

    let own_did = state.identity.own_did();
    let mut resource = ResourceClient {
        state,
        access_token: &token.access_token,
        dpop: dpop_bound,
        nonce: None,
    };
    let mut containers = Vec::new();
    let mut stored = Vec::new();
    let mut not_stored = Vec::new();
    for config_id in &offer.credential_configuration_ids {
        let configuration = metadata
            .credential_configurations_supported
            .get(config_id)
            .ok_or_else(|| {
                WalletError::Upstream(format!("issuer metadata does not describe '{config_id}'"))
            })?;
        // Section 6.2: identifiers named by the token response replace the
        // configuration id in the Credential Request.
        let identifiers = token.credential_identifiers_for(config_id);
        let targets: Vec<Value> = if identifiers.is_empty() {
            vec![json!({"credential_configuration_id": config_id})]
        } else {
            identifiers
                .iter()
                .map(|id| json!({"credential_identifier": id}))
                .collect()
        };
        for target in targets {
            let c_nonce =
                match &metadata.nonce_endpoint {
                    Some(nonce_url) => {
                        check_outbound(state, nonce_url)?;
                        let response =
                            state.http.post(nonce_url).send().await.map_err(|e| {
                                WalletError::Upstream(format!("POST {nonce_url}: {e}"))
                            })?;
                        resource.remember_nonce(&response);
                        let nonce: NonceResponse = read_json(nonce_url, response).await?;
                        Some(nonce.c_nonce)
                    }
                    None => None,
                };
            let proof = build_jwt_proof_for_client(
                key_pair,
                &metadata.credential_issuer,
                c_nonce.as_deref(),
                client_id,
            );
            let mut request = target;
            request["proofs"] = json!({"jwt": [proof]});
            let issued: CredentialResponse = resource
                .post_json(&metadata.credential_endpoint, &request)
                .await?;
            if issued.transaction_id.is_some() {
                return Err(WalletError::Upstream(
                    "deferred issuance is not supported".to_string(),
                ));
            }
            let credentials: Vec<Value> = issued
                .credentials
                .into_iter()
                .map(|c| c.credential)
                .chain(issued.credential)
                .collect();
            if credentials.is_empty() {
                return Err(WalletError::Upstream(
                    "credential response carried no credential".to_string(),
                ));
            }
            if configuration.format != FORMAT_JWT_VC_JSON {
                not_stored.push(NotStoredCredential {
                    credential_configuration_id: config_id.clone(),
                    format: configuration.format.clone(),
                    count: credentials.len(),
                    reason: format!(
                        "only {FORMAT_JWT_VC_JSON} credentials can be presented over DCP"
                    ),
                });
                continue;
            }
            for credential in credentials {
                let credential_type = accept_issued_credential(state, &credential, own_did).await?;
                stored.push(RedeemedCredential {
                    credential_configuration_id: config_id.clone(),
                    credential_type: credential_type.clone(),
                });
                containers.push(CredentialContainer {
                    credential_type,
                    payload: credential,
                    format: FORMAT_JWT_VC_JSON.to_string(),
                });
            }
        }
    }

    if !containers.is_empty() {
        state.store.store(StoredCredentialBatch {
            issuer_pid: format!("oid4vci:{}", Uuid::new_v4()),
            holder_pid: None,
            status: "ISSUED".to_string(),
            rejection_reason: None,
            credentials: containers,
        });
    }
    tracing::info!(
        issuer = %offer.credential_issuer,
        stored = stored.len(),
        not_stored = not_stored.len(),
        "redeemed an OID4VCI offer"
    );
    Ok(RedeemOfferResponse {
        credential_issuer: offer.credential_issuer,
        stored,
        not_stored,
    })
}

fn check_outbound(state: &AppState, url: &str) -> Result<(), WalletError> {
    state
        .outbound
        .check_url(url)
        .map_err(|e| WalletError::Outbound(e.to_string()))
}

/// The `DPoP-Nonce` a server demanded, when `response` is a
/// `use_dpop_nonce` challenge (RFC 9449 sections 8 and 9): a 400
/// `{"error":"use_dpop_nonce"}` from an AS, or a 401 whose
/// `WWW-Authenticate` names that error from a resource server.
fn dpop_nonce_challenge(response: &reqwest::Response) -> Option<String> {
    let nonce = response
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())?
        .to_string();
    let challenged = match response.status() {
        reqwest::StatusCode::UNAUTHORIZED => response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("use_dpop_nonce")),
        // The AS signals it in the JSON body, which is not read here; a 400
        // carrying a fresh DPoP-Nonce header is that challenge in practice.
        reqwest::StatusCode::BAD_REQUEST => true,
        _ => false,
    };
    challenged.then_some(nonce)
}

/// Calls the Credential Issuer's protected endpoints with the access token,
/// as a Bearer token or DPoP-bound (with `ath` and the latest resource
/// server `DPoP-Nonce`).
struct ResourceClient<'a> {
    state: &'a AppState,
    access_token: &'a str,
    dpop: bool,
    nonce: Option<String>,
}

impl ResourceClient<'_> {
    fn remember_nonce(&mut self, response: &reqwest::Response) {
        if let Some(nonce) = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
        {
            self.nonce = Some(nonce.to_string());
        }
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &mut self,
        url: &str,
        body: &Value,
    ) -> Result<T, WalletError> {
        check_outbound(self.state, url)?;
        for attempt in 0..2 {
            let request = self.state.http.post(url).json(body);
            let request = if self.dpop {
                request
                    .header(header::AUTHORIZATION, format!("DPoP {}", self.access_token))
                    .header(
                        "DPoP",
                        build_dpop_proof(
                            &self.state.identity.key_pair,
                            "POST",
                            url,
                            self.nonce.as_deref(),
                            Some(self.access_token),
                        ),
                    )
            } else {
                request.bearer_auth(self.access_token)
            };
            let response = request
                .send()
                .await
                .map_err(|e| WalletError::Upstream(format!("POST {url}: {e}")))?;
            if self.dpop
                && attempt == 0
                && let Some(nonce) = dpop_nonce_challenge(&response)
            {
                self.nonce = Some(nonce);
                continue;
            }
            self.remember_nonce(&response);
            return read_json(url, response).await;
        }
        Err(WalletError::Upstream(format!(
            "POST {url}: repeated use_dpop_nonce challenge"
        )))
    }
}

/// Applies the same acceptance rules the DCP Storage API applies to a
/// delivered credential: genuine signature against its own `iss` DID, that
/// DID on the trusted-issuer allow-list, and - specific to a wallet
/// pulling for itself - bound to this Credential Service's own DID.
/// Returns the credential type to file it under.
async fn accept_issued_credential(
    state: &AppState,
    credential: &Value,
    own_did: &str,
) -> Result<String, WalletError> {
    let jws = credential
        .as_str()
        .ok_or_else(|| WalletError::Rejected("credential is not a JWT string".to_string()))?;
    let (_, _, payload) =
        dcp_core::decode_jws_unverified(jws).map_err(|e| WalletError::Rejected(e.to_string()))?;
    check_trusted_issuer(&payload, &state.config.trusted_issuer_dids)
        .map_err(|e| WalletError::Rejected(e.to_string()))?;
    let probe = CredentialContainer {
        credential_type: String::new(),
        payload: credential.clone(),
        format: FORMAT_JWT_VC_JSON.to_string(),
    };
    verify_credential_proofs(
        &state.http,
        std::slice::from_ref(&probe),
        state.config.insecure_http,
        &state.outbound,
    )
    .await
    .map_err(|e| WalletError::Rejected(e.to_string()))?;
    let subject = payload.get("sub").and_then(Value::as_str).or_else(|| {
        payload
            .pointer("/vc/credentialSubject/id")
            .and_then(Value::as_str)
    });
    if subject != Some(own_did) {
        return Err(WalletError::Rejected(format!(
            "credential is bound to {subject:?}, not to this Credential Service ({own_did})"
        )));
    }
    if let Some(exp) = payload.get("exp").and_then(Value::as_u64)
        && exp <= now_secs()
    {
        return Err(WalletError::Rejected("credential has expired".to_string()));
    }
    payload
        .pointer("/vc/type")
        .and_then(Value::as_array)
        .and_then(|types| {
            types
                .iter()
                .filter_map(Value::as_str)
                .rfind(|t| *t != "VerifiableCredential")
        })
        .map(str::to_string)
        .ok_or_else(|| WalletError::Rejected("credential has no specific vc.type".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiring_table_evicts_oldest_and_takes_once() {
        let mut table = ExpiringTable::new(2);
        table.insert("a".into(), 60, 1);
        table.insert("b".into(), 60, 2);
        table.insert("c".into(), 60, 3);
        assert_eq!(table.len(), 2);
        assert!(table.get_mut("a").is_none());
        assert_eq!(table.take("b"), Some(2));
        assert_eq!(table.take("b"), None);
    }

    #[test]
    fn expiring_table_hides_expired_entries() {
        let mut table = ExpiringTable::new(4);
        table.insert("gone".into(), 0, ());
        assert!(table.get_mut("gone").is_none());
        table.insert("gone2".into(), 0, ());
        assert!(table.take("gone2").is_none());
    }

    #[test]
    fn tx_codes_are_fixed_width_digits() {
        for _ in 0..50 {
            let code = random_tx_code();
            assert_eq!(code.len(), TX_CODE_LENGTH as usize);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn parse_offer_uri_reads_both_forms() {
        let (v, r) = parse_offer_uri(
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fo%2F1",
        )
        .unwrap();
        assert!(v.is_none());
        assert_eq!(r.as_deref(), Some("https://issuer.example/o/1"));

        let inline = serde_json::to_string(&json!({
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": ["x"],
        }))
        .unwrap();
        let uri = reqwest::Url::parse_with_params(
            "openid-credential-offer://",
            &[("credential_offer", inline.as_str())],
        )
        .unwrap();
        let (v, r) = parse_offer_uri(uri.as_str()).unwrap();
        assert_eq!(v.unwrap().credential_configuration_ids, vec!["x"]);
        assert!(r.is_none());
    }
}
