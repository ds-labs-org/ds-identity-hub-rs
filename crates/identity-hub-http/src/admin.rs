//! The Issuer Admin API (issuer-service mode only): the governance
//! console's operator surface over `crate::issuer`'s state, per the shared
//! contract `governance/api-contract.md`, section 1 (shape mirrors Eclipse
//! EDC IdentityHub's Issuer Admin API `v1alpha`).
//!
//! ## Why a separate router on a separate listener
//!
//! Everything here changes who gets credentials, so it must never share the
//! public DCP listener's exposure: `crate::build_admin` returns this router
//! only when an admin token is configured (deny by default - no token, no
//! listener at all), and `main.rs` binds it on `--admin-bind`, loopback by
//! default. Every request, including unknown paths, first passes
//! [`require_admin_token`].
//!
//! ## Errors
//!
//! Always JSON `{"error": "..."}`: `400` malformed body / missing field /
//! invalid value, `401` missing or wrong token, `404` unknown id (or a
//! participant context other than this hub's), `409` duplicate or rule
//! violation, `503` a bounded table is full. Bodies are parsed by hand from
//! raw bytes rather than with axum's `Json` extractor, whose rejections are
//! plain text with `415`/`422` statuses the contract does not allow.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

use dcp_core::now_secs;
use identity_hub_core::sts::constant_time_eq;

use crate::handlers::spawn_delivery;
use crate::issuer::{
    CredentialDefinitionInput, Holder, HolderRegistration, HolderStatus, HolderUpdate, IssuerError,
    ProcessState, QuerySpec,
};
use crate::state::AppState;

const PREFIX: &str = "/v1alpha/participants/{pc}";

/// Builds the admin router. Callers go through `crate::build_admin`, which
/// decides whether it exists at all.
pub(crate) fn router(state: Arc<AppState>) -> Router {
    let routes = Router::new()
        .route(PREFIX, get(participant))
        .route(
            &format!("{PREFIX}/credentialdefinitions"),
            post(create_definition).put(update_definition),
        )
        .route(
            &format!("{PREFIX}/credentialdefinitions/query"),
            post(query_definitions),
        )
        .route(
            &format!("{PREFIX}/credentialdefinitions/{{id}}"),
            get(get_definition).delete(delete_definition),
        )
        .route(
            &format!("{PREFIX}/holders"),
            post(register_holder).put(update_holder),
        )
        .route(&format!("{PREFIX}/holders/query"), post(query_holders))
        .route(&format!("{PREFIX}/holders/{{holder_id}}"), get(get_holder))
        .route(
            &format!("{PREFIX}/holders/{{holder_id}}/approve"),
            post(approve_holder),
        )
        .route(
            &format!("{PREFIX}/holders/{{holder_id}}/reject"),
            post(reject_holder),
        )
        .route(
            &format!("{PREFIX}/issuanceprocesses/query"),
            post(query_processes),
        )
        .route(
            &format!("{PREFIX}/issuanceprocesses/{{id}}"),
            get(get_process),
        )
        .route(
            &format!("{PREFIX}/credentials/query"),
            post(query_credentials),
        )
        .route(
            &format!("{PREFIX}/credentials/{{id}}/status"),
            get(credential_status),
        )
        .route(
            &format!("{PREFIX}/credentials/{{id}}/revoke"),
            post(revoke_credential),
        )
        // Runs after routing, so `{pc}` is available; only matched routes.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            check_participant_context,
        ))
        .fallback(|| async { error(StatusCode::NOT_FOUND, "no such admin endpoint") })
        .method_not_allowed_fallback(|| async {
            error(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed on this admin endpoint",
            )
        });
    routes
        // Runs before routing: every request, unknown paths included, needs
        // the token first.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_token,
        ))
        .with_state(state)
}

// ---- plumbing ----

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({"error": message.into()}))).into_response()
}

impl IntoResponse for IssuerError {
    fn into_response(self) -> Response {
        match self {
            IssuerError::Invalid(m) => error(StatusCode::BAD_REQUEST, m),
            IssuerError::NotFound(m) => error(StatusCode::NOT_FOUND, m),
            IssuerError::Conflict(m) => error(StatusCode::CONFLICT, m),
            IssuerError::Full(m) => error(StatusCode::SERVICE_UNAVAILABLE, m),
        }
    }
}

/// Parses a JSON body into `T`; any syntax error, wrong type or missing
/// required field is a `400` with serde's own message.
fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, IssuerError> {
    serde_json::from_slice(body)
        .map_err(|e| IssuerError::Invalid(format!("invalid request body: {e}")))
}

fn to_json<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("admin records always serialize")
}

/// Runs a QuerySpec body (empty body or `{}` = defaults) over `items`.
fn run_query(body: &[u8], items: Vec<Value>) -> Response {
    let spec: QuerySpec = if body.iter().all(u8::is_ascii_whitespace) {
        QuerySpec::default()
    } else {
        match parse_body(body) {
            Ok(spec) => spec,
            Err(err) => return err.into_response(),
        }
    };
    match spec.apply(items) {
        Ok(page) => Json(page).into_response(),
        Err(message) => error(StatusCode::BAD_REQUEST, message),
    }
}

async fn require_admin_token(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = state
        .config
        .admin_token
        .as_deref()
        .filter(|t| !t.is_empty())
    else {
        // Unreachable through `crate::build_admin`, but never fail open.
        return error(StatusCode::UNAUTHORIZED, "admin API is disabled");
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token);
    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(request).await
        }
        Some(_) => error(StatusCode::UNAUTHORIZED, "invalid admin token"),
        None => error(StatusCode::UNAUTHORIZED, "missing admin bearer token"),
    }
}

/// The credentials of an `Authorization: Bearer <token>` header. The scheme
/// name is case-insensitive (RFC 7235 section 2.1), so `bearer` and
/// `BEARER` work too.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim_start_matches(' '))
}

/// `Path`, with rejections (e.g. an undecodable percent-escape) answered
/// as the contract's JSON `400 {"error"}` instead of axum's text/plain.
struct AdminPath<T>(T);

impl<S, T> FromRequestParts<S> for AdminPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| AdminPath(value))
            .map_err(|rejection| error(StatusCode::BAD_REQUEST, rejection.body_text()))
    }
}

/// Decodes EDC's base64 participant-context path segment, in any of the
/// four flavours a client may produce (standard or url-safe alphabet,
/// padded or not).
fn decode_participant_context(encoded: &str) -> Option<String> {
    [&STANDARD, &URL_SAFE, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(encoded).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// Single tenant: any `{pc}` that does not decode to this hub's own
/// `--participant-context-id` is `404`, as if the context did not exist.
async fn check_participant_context(
    State(state): State<Arc<AppState>>,
    AdminPath(params): AdminPath<HashMap<String, String>>,
    request: Request,
    next: Next,
) -> Response {
    let ours = params
        .get("pc")
        .and_then(|pc| decode_participant_context(pc))
        .is_some_and(|id| id == state.config.participant_context_id);
    if ours {
        next.run(request).await
    } else {
        error(StatusCode::NOT_FOUND, "unknown participant context")
    }
}

// ---- participant ----

async fn participant(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({
        "participantContextId": state.config.participant_context_id,
        "did": state.identity.own_did(),
        "state": "ACTIVATED",
    }))
    .into_response()
}

// ---- credential definitions ----

async fn create_definition(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let input: CredentialDefinitionInput = match parse_body(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    let definition = match input.into_definition(now_secs()) {
        Ok(definition) => definition,
        Err(err) => return err.into_response(),
    };
    let mut catalog = state.definitions.lock().expect("definitions lock poisoned");
    match catalog.create(definition.clone()) {
        Ok(()) => (StatusCode::CREATED, Json(definition)).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn update_definition(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let input: CredentialDefinitionInput = match parse_body(&body) {
        Ok(input) => input,
        Err(err) => return err.into_response(),
    };
    let definition = match input.into_definition(now_secs()) {
        Ok(definition) => definition,
        Err(err) => return err.into_response(),
    };
    let mut catalog = state.definitions.lock().expect("definitions lock poisoned");
    match catalog.update(definition) {
        Ok(updated) => Json(updated).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn get_definition(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, id)): AdminPath<(String, String)>,
) -> Response {
    match state
        .definitions
        .lock()
        .expect("definitions lock poisoned")
        .get(&id)
    {
        Some(definition) => Json(definition.clone()).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            format!("no credential definition '{id}'"),
        ),
    }
}

/// `409` while a SUBMITTED or APPROVED issuance process still needs the
/// definition: approving its holder later would otherwise deliver nothing.
async fn delete_definition(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, id)): AdminPath<(String, String)>,
) -> Response {
    // Lock order: definitions -> requests (see `crate::issuer`).
    let mut catalog = state.definitions.lock().expect("definitions lock poisoned");
    if catalog.get(&id).is_none() {
        return error(
            StatusCode::NOT_FOUND,
            format!("no credential definition '{id}'"),
        );
    }
    let in_use = state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .iter()
        .any(|p| p.state.is_active() && p.credential_definitions.contains(&id));
    if in_use {
        return error(
            StatusCode::CONFLICT,
            format!("credential definition '{id}' is referenced by an active issuance process"),
        );
    }
    catalog.remove(&id);
    StatusCode::NO_CONTENT.into_response()
}

async fn query_definitions(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let items = state
        .definitions
        .lock()
        .expect("definitions lock poisoned")
        .all()
        .iter()
        .map(to_json)
        .collect();
    run_query(&body, items)
}

// ---- holders ----

/// Admin-registered holders are created `approved`: the operator *is* the
/// approval.
async fn register_holder(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let registration: HolderRegistration = match parse_body(&body) {
        Ok(registration) => registration,
        Err(err) => return err.into_response(),
    };
    if !registration.did.starts_with("did:") {
        return error(StatusCode::BAD_REQUEST, "did must be a DID (did:...)");
    }
    if registration
        .holder_id
        .as_deref()
        .is_some_and(|id| id.trim().is_empty())
    {
        return error(StatusCode::BAD_REQUEST, "holderId must not be empty");
    }
    let holder = Holder {
        holder_id: registration
            .holder_id
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        did: registration.did,
        name: registration.name,
        properties: registration.properties.unwrap_or_default(),
        status: HolderStatus::Approved,
        created_at: now_secs(),
    };
    match state
        .holders
        .lock()
        .expect("holders lock poisoned")
        .insert(holder)
    {
        Ok(holder) => (StatusCode::CREATED, Json(holder)).into_response(),
        Err(err) => err.into_response(),
    }
}

async fn update_holder(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let update: HolderUpdate = match parse_body(&body) {
        Ok(update) => update,
        Err(err) => return err.into_response(),
    };
    let mut holders = state.holders.lock().expect("holders lock poisoned");
    let Some(holder) = holders.get_mut(&update.holder_id) else {
        return error(
            StatusCode::NOT_FOUND,
            format!("no holder '{}'", update.holder_id),
        );
    };
    if update.name.is_some() {
        holder.name = update.name;
    }
    if let Some(properties) = update.properties {
        holder.properties = properties;
    }
    Json(holder.clone()).into_response()
}

async fn get_holder(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, holder_id)): AdminPath<(String, String)>,
) -> Response {
    match state
        .holders
        .lock()
        .expect("holders lock poisoned")
        .get(&holder_id)
    {
        Some(holder) => Json(holder.clone()).into_response(),
        None => error(StatusCode::NOT_FOUND, format!("no holder '{holder_id}'")),
    }
}

async fn query_holders(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let items = state
        .holders
        .lock()
        .expect("holders lock poisoned")
        .all()
        .map(to_json)
        .collect();
    run_query(&body, items)
}

/// Sets the holder's status and moves every SUBMITTED process of that
/// holder to `next`, under one holders -> requests critical section so a
/// Credential Request arriving concurrently is either seen here or sees the
/// new status. A rejection also stops APPROVED processes whose delivery task
/// has not claimed them yet (still queued on the delivery semaphore); one
/// already delivering finishes. Returns the holder and the ids of the
/// moved processes.
fn decide_holder(
    state: &AppState,
    holder_id: &str,
    status: HolderStatus,
    next: ProcessState,
) -> Result<(Holder, Vec<String>), IssuerError> {
    let mut holders = state.holders.lock().expect("holders lock poisoned");
    let Some(holder) = holders.get_mut(holder_id) else {
        return Err(IssuerError::NotFound(format!("no holder '{holder_id}'")));
    };
    holder.status = status;
    let now = now_secs();
    let mut moved = Vec::new();
    for process in state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .iter_mut()
        .filter(|p| {
            p.holder_id == holder_id
                && (p.state == ProcessState::Submitted
                    || (next == ProcessState::Rejected
                        && p.state == ProcessState::Approved
                        && !p.delivery_started))
        })
    {
        process.transition(next, now);
        moved.push(process.id.clone());
    }
    Ok((holder.clone(), moved))
}

async fn approve_holder(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, holder_id)): AdminPath<(String, String)>,
) -> Response {
    match decide_holder(
        &state,
        &holder_id,
        HolderStatus::Approved,
        ProcessState::Approved,
    ) {
        Ok((holder, approved)) => {
            for process_id in approved {
                spawn_delivery(state.clone(), process_id);
            }
            Json(holder).into_response()
        }
        Err(err) => err.into_response(),
    }
}

async fn reject_holder(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, holder_id)): AdminPath<(String, String)>,
) -> Response {
    match decide_holder(
        &state,
        &holder_id,
        HolderStatus::Rejected,
        ProcessState::Rejected,
    ) {
        Ok((holder, _)) => Json(holder).into_response(),
        Err(err) => err.into_response(),
    }
}

// ---- issuance processes ----

async fn get_process(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, id)): AdminPath<(String, String)>,
) -> Response {
    match state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .get(&id)
    {
        Some(process) => Json(process.clone()).into_response(),
        None => error(StatusCode::NOT_FOUND, format!("no issuance process '{id}'")),
    }
}

async fn query_processes(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let items = state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .iter()
        .map(to_json)
        .collect();
    run_query(&body, items)
}

// ---- issued credentials ----

async fn query_credentials(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let items = state
        .issued
        .lock()
        .expect("issued lock poisoned")
        .all()
        .map(to_json)
        .collect();
    run_query(&body, items)
}

async fn credential_status(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, id)): AdminPath<(String, String)>,
) -> Response {
    match state.issued.lock().expect("issued lock poisoned").get(&id) {
        Some(record) => Json(json!({"status": record.status})).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            format!("no issued credential '{id}'"),
        ),
    }
}

/// Idempotent: revoking a revoked credential answers the same record.
async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    AdminPath((_pc, id)): AdminPath<(String, String)>,
) -> Response {
    match state
        .issued
        .lock()
        .expect("issued lock poisoned")
        .revoke(&id)
    {
        Some(record) => Json(record).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            format!("no issued credential '{id}'"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        for header in ["Bearer tok", "bearer tok", "BEARER tok", "bEaReR  tok"] {
            assert_eq!(bearer_token(header), Some("tok"), "{header}");
        }
        assert_eq!(bearer_token("Basic tok"), None);
        assert_eq!(bearer_token("Bearertok"), None);
    }

    #[test]
    fn constant_time_eq_is_plain_equality() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn participant_context_flavours() {
        for encoded in ["aXNzdWVy", "aXNzdWVy"] {
            assert_eq!(
                decode_participant_context(encoded).as_deref(),
                Some("issuer")
            );
        }
        assert_eq!(
            decode_participant_context("dGVuYW50Pj4/fg==").as_deref(),
            Some("tenant>>?~")
        );
        assert_eq!(
            decode_participant_context("dGVuYW50Pj4_fg").as_deref(),
            Some("tenant>>?~")
        );
        assert_eq!(decode_participant_context("!!"), None);
    }
}
