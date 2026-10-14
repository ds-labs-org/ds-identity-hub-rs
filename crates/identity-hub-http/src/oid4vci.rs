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

use axum::extract::{Path, State};
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
    AUTHORIZATION_SERVER_WELL_KNOWN, AuthorizationServerMetadata, CREDENTIAL_ISSUER_WELL_KNOWN,
    CREDENTIAL_OFFER_SCHEME, CredentialConfiguration, CredentialDefinition,
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest, CredentialResponse,
    ErrorResponse, FORMAT_JWT_VC_JSON, IssuedCredential, NonceResponse, OfferGrants,
    PRE_AUTHORIZED_CODE_GRANT, PreAuthorizedCodeGrant, ProofKey, TokenResponse, TxCodeDescription,
    build_jwt_proof, inspect_jwt_proof, well_known_url,
};
use identity_hub_core::store::StoredCredentialBatch;

use crate::auth::check_trusted_issuer;
use crate::config::Mode;
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

pub fn routes(mode: Mode) -> Router<Arc<AppState>> {
    match mode {
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
            Router::new().route("/oid4vci/wallet/offers", post(redeem_offer))
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemOfferResponse {
    pub credential_issuer: String,
    pub stored: Vec<RedeemedCredential>,
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
    match redeem(&state, body).await {
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

    let mut form = vec![
        ("grant_type", PRE_AUTHORIZED_CODE_GRANT.to_string()),
        ("pre-authorized_code", grant.pre_authorized_code.clone()),
    ];
    if grant.tx_code.is_some()
        && let Some(tx_code) = &body.tx_code
    {
        form.push(("tx_code", tx_code.clone()));
    }
    let token_url = as_metadata.token_endpoint;
    state
        .outbound
        .check_url(&token_url)
        .map_err(|e| WalletError::Outbound(e.to_string()))?;
    let token_response = state
        .http
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| WalletError::Upstream(format!("POST {token_url}: {e}")))?;
    let token: TokenResponse = read_json(&token_url, token_response).await?;

    let own_did = state.identity.own_did();
    let mut containers = Vec::new();
    let mut stored = Vec::new();
    for config_id in &offer.credential_configuration_ids {
        let configuration = metadata
            .credential_configurations_supported
            .get(config_id)
            .ok_or_else(|| {
                WalletError::Upstream(format!("issuer metadata does not describe '{config_id}'"))
            })?;
        if configuration.format != FORMAT_JWT_VC_JSON {
            return Err(WalletError::Rejected(format!(
                "'{config_id}' uses format '{}', only {FORMAT_JWT_VC_JSON} is supported",
                configuration.format
            )));
        }
        let c_nonce = match &metadata.nonce_endpoint {
            Some(nonce_url) => {
                state
                    .outbound
                    .check_url(nonce_url)
                    .map_err(|e| WalletError::Outbound(e.to_string()))?;
                let response = state
                    .http
                    .post(nonce_url)
                    .send()
                    .await
                    .map_err(|e| WalletError::Upstream(format!("POST {nonce_url}: {e}")))?;
                let nonce: NonceResponse = read_json(nonce_url, response).await?;
                Some(nonce.c_nonce)
            }
            None => None,
        };
        let proof = build_jwt_proof(
            &state.identity.key_pair,
            &metadata.credential_issuer,
            c_nonce.as_deref(),
        );
        let credential_url = &metadata.credential_endpoint;
        state
            .outbound
            .check_url(credential_url)
            .map_err(|e| WalletError::Outbound(e.to_string()))?;
        let response = state
            .http
            .post(credential_url)
            .bearer_auth(&token.access_token)
            .json(&json!({
                "credential_configuration_id": config_id,
                "proofs": {"jwt": [proof]},
            }))
            .send()
            .await
            .map_err(|e| WalletError::Upstream(format!("POST {credential_url}: {e}")))?;
        let issued: CredentialResponse = read_json(credential_url, response).await?;
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

    state.store.store(StoredCredentialBatch {
        issuer_pid: format!("oid4vci:{}", Uuid::new_v4()),
        holder_pid: None,
        status: "ISSUED".to_string(),
        rejection_reason: None,
        credentials: containers,
    });
    tracing::info!(issuer = %offer.credential_issuer, count = stored.len(), "stored credentials redeemed over OID4VCI");
    Ok(RedeemOfferResponse {
        credential_issuer: offer.credential_issuer,
        stored,
    })
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
