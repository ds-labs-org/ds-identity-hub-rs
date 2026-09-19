use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use dcp_core::{now_secs, service_endpoint_url, sign_jws};
use identity_hub_core::messages::{
    CredentialContainer, CredentialMessage, CredentialOfferMessage, CredentialRequestMessage,
    CredentialStatus, IssuerMetadata, PresentationQueryMessage, PresentationResponseMessage,
    VC_CONTEXT,
};
use identity_hub_core::store::StoredCredentialBatch;
use identity_hub_core::sts::{self, StsTokenRequest};

use crate::auth::{AuthError, verify_bearer_token};
use crate::config::Mode;
use crate::state::{AppState, RequestRecord};

pub fn router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route("/{segment}/did.json", get(did_document))
        .route("/sts/token", post(sts_token));

    router = match state.mode() {
        Mode::CredentialService => router
            .route("/presentations/query", post(presentation_query))
            .route("/credentials", post(storage_write))
            .route("/offers", post(credential_offer)),
        Mode::IssuerService => router
            .route("/credentials", post(credential_request))
            .route("/requests/{id}", get(request_status))
            .route("/metadata", get(issuer_metadata)),
    };

    router.with_state(state)
}

fn bearer_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

fn auth_error_response(err: AuthError) -> Response {
    tracing::warn!(error = %err, "rejecting request: bearer token validation failed");
    (StatusCode::UNAUTHORIZED, err.to_string()).into_response()
}

// ---- DID hosting ----

/// `GET /<segment>/did.json` - resolvable per the `did:web` method for
/// either this process's own identity (`did.holder`/`did.issuer`) or the
/// synthetic STS-party identity (see `identity_hub_core::sts`'s module doc).
async fn did_document(State(state): State<Arc<AppState>>, Path(segment): Path<String>) -> Response {
    if segment == state.identity.did_path_segment {
        let service_type = match state.mode() {
            Mode::CredentialService => "CredentialService",
            Mode::IssuerService => "IssuerService",
        };
        let base_url = state.base_url();
        let doc = state
            .identity
            .did_document(&[(service_type, base_url.as_str())]);
        Json(doc).into_response()
    } else if segment == state.sts_party.did_path_segment {
        Json(state.sts_party.did_document(&[])).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// ---- Secure Token Service ----

#[derive(Debug, Deserialize)]
struct StsFormBody {
    grant_type: String,
    client_id: String,
    client_secret: String,
    audience: String,
    #[serde(default)]
    bearer_access_scope: Option<String>,
}

/// `POST /sts/token` - a minimal OAuth2 `client_credentials`-grant-shaped
/// endpoint per `specifications/identity-trust-sts-api.yaml`. See
/// `identity_hub_core::sts` for what identity mints the returned token.
async fn sts_token(State(state): State<Arc<AppState>>, Form(body): Form<StsFormBody>) -> Response {
    let result = sts::issue_token(
        &state.sts_config,
        &state.sts_party,
        StsTokenRequest {
            grant_type: body.grant_type,
            client_id: body.client_id,
            client_secret: body.client_secret,
            audience: body.audience,
            bearer_access_scope: body.bearer_access_scope,
        },
    );
    match result {
        Ok(response) => Json(response).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_client", "error_description": err.to_string()})),
        )
            .into_response(),
    }
}

// ---- Verifiable Presentation Protocol: Resolution API ----

/// `POST /presentations/query`. See
/// `verifiable.presentation.protocol.md#resolution-api`.
async fn presentation_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(message): Json<PresentationQueryMessage>,
) -> Response {
    let claims = match verify_bearer_token(
        &state.http,
        bearer_header(&headers),
        state.identity.own_did(),
        state.config.insecure_http,
    )
    .await
    {
        Ok(claims) => claims,
        Err(err) => return auth_error_response(err),
    };
    // The querying party's own DID (`iss` == `sub` on a valid Self-Issued ID
    // Token, checked by `verify_bearer_token`'s signature/DID-resolution
    // step) - the returned Verifiable Presentation must be addressed back to
    // it (see `build_presentation`).
    let caller_did = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let has_scope = !message.scope.is_empty();
    // A `presentationDefinition` must be a non-empty, valid object per the
    // spec ("OPTIONAL: presentationDefinition: a non-empty, valid
    // Presentation Definition") - `null` or `{}` is a malformed request
    // (400), not "a definition this bootstrap doesn't support" (501).
    let has_definition =
        matches!(&message.presentation_definition, Some(Value::Object(map)) if !map.is_empty());
    let has_malformed_definition = message.presentation_definition.is_some() && !has_definition;
    if has_malformed_definition {
        return (
            StatusCode::BAD_REQUEST,
            "presentationDefinition must be a non-empty object",
        )
            .into_response();
    }
    if has_scope && has_definition {
        return (
            StatusCode::BAD_REQUEST,
            "PresentationQueryMessage must not set both scope and presentationDefinition",
        )
            .into_response();
    }
    if has_definition {
        // Real per the spec: "An implementation MAY support the
        // presentationDefinition parameter. If it does not, it MUST return
        // 501 Not Implemented." - this bootstrap doesn't (see
        // ../../ARCHITECTURE.md).
        return StatusCode::NOT_IMPLEMENTED.into_response();
    }
    if !has_scope {
        return (
            StatusCode::BAD_REQUEST,
            "PresentationQueryMessage must set a non-empty scope or a presentationDefinition",
        )
            .into_response();
    }

    let requested_types = state.scope_matcher.credential_types(&message.scope);
    let matched = state.store.credentials_of_types(&requested_types);
    let vp_jws = build_presentation(&state, caller_did, &matched);

    Json(PresentationResponseMessage::new(vec![vp_jws])).into_response()
}

fn build_presentation(
    state: &AppState,
    audience: &str,
    credentials: &[CredentialContainer],
) -> String {
    let now = now_secs();
    let verifiable_credentials: Vec<Value> =
        credentials.iter().map(|c| c.payload.clone()).collect();
    let payload = json!({
        "iss": state.identity.own_did(),
        "sub": state.identity.own_did(),
        "aud": audience,
        "vp": {
            "@context": [VC_CONTEXT],
            "type": ["VerifiablePresentation"],
            "holder": state.identity.own_did(),
            "verifiableCredential": verifiable_credentials,
        },
        "iat": now,
        "exp": now + 300,
        "jti": Uuid::new_v4().to_string(),
    });
    sign_jws(
        &payload,
        &state.identity.key_pair.signing_key(),
        state.identity.own_key_id(),
    )
}

// ---- Credential Issuance Protocol: Storage API ----

/// `POST /credentials` on a Credential Service. See
/// `credential.issuance.protocol.md#storage-api`.
///
/// Deliberately accepts every well-formed `CredentialMessage`
/// unconditionally, without requiring the `Authorization` header the spec
/// allows a Credential Service to demand - see `../../ARCHITECTURE.md` for
/// why: the real `dcp-tck`'s own setup phase for every Credential Service
/// test case depends on this endpoint genuinely accepting its dynamically
/// generated test credentials, and this bootstrap does not yet implement
/// per-client write authorization.
async fn storage_write(
    State(state): State<Arc<AppState>>,
    Json(message): Json<CredentialMessage>,
) -> StatusCode {
    state.store.store(StoredCredentialBatch {
        issuer_pid: message.issuer_pid,
        holder_pid: message.holder_pid,
        status: message.status,
        rejection_reason: message.rejection_reason,
        credentials: message.credentials,
    });
    StatusCode::OK
}

// ---- Credential Issuance Protocol: Credential Offer API ----

/// `POST /offers` on a Credential Service. See
/// `credential.issuance.protocol.md#credential-offer-api`. This bootstrap
/// only acknowledges the offer (no holder-driven follow-up request is
/// triggered) - see `../../ARCHITECTURE.md`.
async fn credential_offer(
    State(_state): State<Arc<AppState>>,
    Json(message): Json<CredentialOfferMessage>,
) -> StatusCode {
    tracing::info!(issuer = %message.issuer, count = message.credentials.len(), "received credential offer");
    StatusCode::OK
}

// ---- Credential Issuance Protocol: Issuer Service ----

/// `POST /credentials` on an Issuer Service (the Credential Request API).
/// See `credential.issuance.protocol.md#credential-request-api`.
async fn credential_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(message): Json<CredentialRequestMessage>,
) -> Response {
    let claims = match verify_bearer_token(
        &state.http,
        bearer_header(&headers),
        state.identity.own_did(),
        state.config.insecure_http,
    )
    .await
    {
        Ok(claims) => claims,
        Err(err) => return auth_error_response(err),
    };
    let holder_did = match claims.get("sub").and_then(Value::as_str) {
        Some(did) => did.to_string(),
        None => return (StatusCode::BAD_REQUEST, "token has no sub claim").into_response(),
    };
    let delivery_bearer = claims
        .get("token")
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    let known_id = &state.supported_credential.id;
    if message.credentials.is_empty() || !message.credentials.iter().all(|c| &c.id == known_id) {
        return (
            StatusCode::BAD_REQUEST,
            format!("unknown credential id: only '{known_id}' is supported by this bootstrap"),
        )
            .into_response();
    }

    let request_id = Uuid::new_v4().to_string();
    state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .insert(
            request_id.clone(),
            RequestRecord {
                issuer_pid: request_id.clone(),
                holder_pid: message.holder_pid.clone(),
                status: "RECEIVED".to_string(),
            },
        );

    let state = state.clone();
    let holder_pid = message.holder_pid.clone();
    let req_id_for_task = request_id.clone();
    tokio::spawn(async move {
        deliver_issued_credential(
            state,
            req_id_for_task,
            holder_pid,
            holder_did,
            delivery_bearer,
        )
        .await;
    });

    let mut response = StatusCode::CREATED.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        format!("/requests/{request_id}")
            .parse()
            .expect("request id is a valid header value"),
    );
    response
}

/// The asynchronous half of the Credential Request API: resolves the
/// holder's own `did:web` document to find its `CredentialService`
/// endpoint, mints a self-issued token addressed to it, signs a real VC for
/// this bootstrap's one supported credential type, and delivers it via the
/// Storage API - see `credential.issuance.protocol.md`, step 7 of the
/// Issuance Flow.
async fn deliver_issued_credential(
    state: Arc<AppState>,
    request_id: String,
    holder_pid: String,
    holder_did: String,
    delivery_bearer: Option<String>,
) {
    let outcome = try_deliver_issued_credential(
        &state,
        &request_id,
        &holder_pid,
        &holder_did,
        delivery_bearer,
    )
    .await;
    let status = if outcome.is_ok() {
        "ISSUED"
    } else {
        "REJECTED"
    };
    if let Err(err) = &outcome {
        tracing::warn!(request_id, error = %err, "failed to deliver issued credential");
    }
    if let Some(record) = state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .get_mut(&request_id)
    {
        record.status = status.to_string();
    }
}

async fn try_deliver_issued_credential(
    state: &AppState,
    request_id: &str,
    holder_pid: &str,
    holder_did: &str,
    delivery_bearer: Option<String>,
) -> Result<(), String> {
    let holder_doc =
        dcp_core::resolve_did(&state.http, holder_did, state.config.insecure_http).await?;
    let endpoint = service_endpoint_url(&holder_doc, "CredentialService")?;

    let now = now_secs();
    let credential_type = state
        .supported_credential
        .credential_type
        .clone()
        .unwrap_or_else(|| "VerifiableCredential".to_string());
    let vc_payload = json!({
        "iss": state.identity.own_did(),
        "sub": holder_did,
        "vc": {
            "@context": [VC_CONTEXT],
            "type": ["VerifiableCredential", credential_type],
            "credentialSubject": { "id": holder_did },
        },
        "iat": now,
        "exp": now + 3600,
        "jti": Uuid::new_v4().to_string(),
    });
    let vc_jws = sign_jws(
        &vc_payload,
        &state.identity.key_pair.signing_key(),
        state.identity.own_key_id(),
    );

    let container = CredentialContainer {
        credential_type: state
            .supported_credential
            .credential_type
            .clone()
            .unwrap_or_default(),
        payload: json!(vc_jws),
        format: "jwt".to_string(),
    };
    let message = CredentialMessage {
        context: vec![identity_hub_core::messages::DCP_CONTEXT.to_string()],
        message_type: "CredentialMessage".to_string(),
        issuer_pid: request_id.to_string(),
        holder_pid: Some(holder_pid.to_string()),
        status: "ISSUED".to_string(),
        credentials: vec![container],
        rejection_reason: None,
    };

    // Per credential.issuance.protocol.md, step 7: "The Credential Issuer
    // authenticates by adding a Self-Issued ID Token of their own to the
    // CredentialMessage [request]. If present in the client's initial
    // Self-Issued ID Token, the access token MUST be contained in the
    // Credential Issuer's Self-Issued ID Token `token` claim."
    let mut si_payload = json!({
        "iss": state.identity.own_did(),
        "sub": state.identity.own_did(),
        "aud": holder_did,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": Uuid::new_v4().to_string(),
    });
    if let Some(token) = delivery_bearer {
        si_payload["token"] = json!(token);
    }
    let si_token = sign_jws(
        &si_payload,
        &state.identity.key_pair.signing_key(),
        state.identity.own_key_id(),
    );

    let response = state
        .http
        .post(format!("{endpoint}/credentials"))
        .bearer_auth(si_token)
        .json(&message)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("Storage API returned HTTP {}", response.status()));
    }
    Ok(())
}

/// `GET /requests/<id>` (Credential Request Status API). See
/// `credential.issuance.protocol.md#credential-request-status-api`.
async fn request_status(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .get(&id)
    {
        Some(record) => Json(CredentialStatus::new(
            record.issuer_pid.clone(),
            record.holder_pid.clone(),
            &record.status,
        ))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `GET /metadata` (Issuer Metadata API). See
/// `credential.issuance.protocol.md#issuer-metadata-api`.
async fn issuer_metadata(State(state): State<Arc<AppState>>) -> Json<IssuerMetadata> {
    Json(IssuerMetadata::new(
        state.identity.own_did().to_string(),
        vec![state.supported_credential.clone()],
    ))
}
