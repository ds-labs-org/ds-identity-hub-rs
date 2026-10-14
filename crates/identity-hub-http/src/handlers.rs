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
    CredentialContainer, CredentialMessage, CredentialObject, CredentialOfferMessage,
    CredentialRequestMessage, CredentialStatus, IssuerMetadata, PresentationQueryMessage,
    PresentationResponseMessage, VC_CONTEXT,
};
use identity_hub_core::store::StoredCredentialBatch;
use identity_hub_core::sts::{self, StsTokenRequest};

use crate::auth::{
    AuthError, check_trusted_issuer, verify_bearer_token, verify_nested_access_token,
};
use crate::config::{HolderApproval, Mode};
use crate::issuer::{
    CredentialDefinition, CredentialRecordStatus, Holder, HolderStatus, IssuanceProcess,
    IssuedCredential, ProcessState, STATUS_LIST_CONTEXT, STATUS_LIST_PATH,
};
use crate::state::AppState;
use crate::validation::{
    ValidationError, check_known_holder_pid, validate_offer_credentials, validate_status,
    verify_credential_proofs,
};

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
            .route("/metadata", get(issuer_metadata))
            .route(STATUS_LIST_PATH, get(status_list)),
    };
    // OID4VCI runs side by side with DCP on the same process: the Issuer
    // Service is also an OID4VCI Credential Issuer, the Credential Service
    // also an OID4VCI Wallet - see `crate::oid4vci`.
    router = router.merge(crate::oid4vci::routes(&state.config));

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

fn validation_error_response(err: ValidationError) -> Response {
    tracing::warn!(error = %err, "rejecting request: message content validation failed");
    (StatusCode::BAD_REQUEST, err.to_string()).into_response()
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
            own_service_did: state.identity.own_did().to_string(),
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
        &state.seen_jti,
        &state.outbound,
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
    let allowed_types = match granted_credential_types(&state, &claims, caller_did).await {
        Ok(allowed) => allowed,
        // A nested `token` claim was present but failed authentication or
        // authorization (undecodable, unverifiable, expired, not bound back
        // to this caller, or not issued by a party authoritative over this
        // service's credentials) - reject the whole request outright,
        // closing `cs_04_03_03_idTokenInvalidIssuerSub`/
        // `cs_05_04_invalidTokenNotAuthorized`. See
        // `granted_credential_types`/`auth::verify_nested_access_token`'s
        // own doc comments.
        Err(err) => return auth_error_response(err),
    };
    // Deny by default (2026-09-20 security audit, Finding 1, CRITICAL):
    // `allowed_types` is exactly what the caller's own nested access token
    // proves it was granted - empty when there is no nested token at all,
    // or when the token carries no `scope` claim. A caller that requests
    // more than it was granted, or requests anything with no grant to show
    // for it, only ever receives the intersection - silently filtered, not
    // rejected outright, per the real TCK's own `verifyCredentials`
    // (asserts a 2xx response, not a 4xx). See `granted_credential_types`'s
    // doc comment for exactly what is and isn't checked about that token.
    // This closes `cs_05_04_01_02_invalidScopeEscalationRequest` as before,
    // and now also the read-authorization bypass a missing grant used to be
    // (a bare outer envelope used to fall through to `requested_types`
    // unfiltered - the weakest possible request outranking a real one).
    let effective_types: Vec<String> = requested_types
        .into_iter()
        .filter(|t| allowed_types.contains(t))
        .collect();
    let matched = state.store.credentials_of_types(&effective_types);
    let vp_jws = build_presentation(&state, caller_did, &matched);

    Json(PresentationResponseMessage::new(vec![vp_jws])).into_response()
}

/// The credential types the caller's own nested `token` claim actually
/// grants - see `presentation_query`'s own doc comment for how the result
/// is used.
///
/// A missing grant means *no* access, not unrestricted access (2026-09-20
/// security audit, Finding 1, CRITICAL - the previous `Option`-returning
/// contract's `None` meant "no restriction", which let a caller bypass
/// every scope check simply by omitting the `token` claim; deny-by-default
/// replaces it, and there is no longer a "no restriction" case to fall
/// into by mistake):
///
/// - `Ok(types)`, empty: either there is no nested `token` claim at all, or
///   one is present, genuinely authenticated *and* authoritative (see
///   below), but its `scope` claim is absent - either way, nothing is
///   granted.
/// - `Ok(types)`, non-empty: a nested token is present and was genuinely
///   authenticated and authorized by `auth::verify_nested_access_token`
///   (signature verified against its own resolved `did:web` issuer, issued
///   by this service's own STS party - the only issuer this bootstrap
///   recognizes as authoritative over its own credentials, not merely
///   self-consistent - not expired, and bound back to `outer_sub` via its
///   own `aud` claim) - `types` is whatever its `scope` claim actually
///   grants.
/// - `Err(_)`: a nested token is present but failed authentication or
///   authorization - `presentation_query` must reject the whole request
///   outright, closing `cs_04_03_03_idTokenInvalidIssuerSub` (a nested
///   token minted for/bound to a *different* party - a confused-deputy
///   forward), `cs_05_04_invalidTokenNotAuthorized` (a nested token that
///   isn't even a real JWS), and the 2026-09-20 audit's Finding 2
///   (CRITICAL - a token an arbitrary, non-authoritative `did:web` party
///   minted and self-signed for itself) - see
///   `auth::verify_nested_access_token`'s own doc comment.
async fn granted_credential_types(
    state: &AppState,
    claims: &Value,
    outer_sub: &str,
) -> Result<Vec<String>, AuthError> {
    let Some(nested_token) = claims.get("token").and_then(Value::as_str) else {
        return Ok(Vec::new());
    };
    let nested_payload = verify_nested_access_token(
        &state.http,
        nested_token,
        outer_sub,
        state.sts_party.own_did(),
        state.config.insecure_http,
        &state.outbound,
    )
    .await?;
    let granted_scope = nested_payload
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("");
    let granted_scopes = identity_hub_core::scope::split_scope_string(granted_scope);
    Ok(state.scope_matcher.credential_types(&granted_scopes))
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
/// Requires a valid Self-Issued ID Token addressed to this service, exactly
/// like the Presentation API (`presentation_query`) and the Issuer
/// Service's Credential Request API (`credential_request`) already do -
/// see `crate::auth::verify_bearer_token`, which all three now share.
/// Confirmed empirically (not assumed) that the real `dcp-tck`'s own
/// Credential-Service setup phase carries exactly such a token on every one
/// of its legitimate Storage API calls - see `../../ARCHITECTURE.md`'s
/// "What's simplified or stubbed" for how this was checked. `iss == sub`,
/// `nbf`, `iat`, `capabilityInvocation`, and `jti` replay are all real
/// checks now too. On top of that envelope validation, the caller's `iss`
/// must also be on `state.config.trusted_issuer_dids`
/// (`crate::auth::check_trusted_issuer`) - a genuinely valid, correctly
/// self-signed token from an unrelated but otherwise-legitimate DID is
/// still not this service's issuer, and (2026-09-20 fix, HIGH) an *empty*
/// `trusted_issuer_dids` now denies every caller rather than none, so a
/// deployment must opt a real issuer in with `--trusted-issuer-did` before
/// this endpoint accepts anything. The nested `token` claim's own
/// signature/binding is not checked here - see the same section for
/// exactly what remains and why.
///
/// Once the token envelope and issuer are both trusted, the message *body*
/// itself is validated too (`crate::validation`, added 2026-09-20): `status`
/// must be a recognized value, `holderPid` must be one this service was
/// configured to expect (`Config::known_holder_pids`), and every JWT-format
/// embedded credential's own proof must genuinely verify - see
/// `crate::validation`'s module doc comment for exactly what each closes.
async fn storage_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(message): Json<CredentialMessage>,
) -> Response {
    let claims = match verify_bearer_token(
        &state.http,
        bearer_header(&headers),
        state.identity.own_did(),
        state.config.insecure_http,
        &state.seen_jti,
        &state.outbound,
    )
    .await
    {
        Ok(claims) => claims,
        Err(err) => return auth_error_response(err),
    };
    if let Err(err) = check_trusted_issuer(&claims, &state.config.trusted_issuer_dids) {
        return auth_error_response(err);
    }
    if let Err(err) = validate_status(&message.status) {
        return validation_error_response(err);
    }
    if let Err(err) = check_known_holder_pid(&message.holder_pid, &state.config.known_holder_pids) {
        return validation_error_response(err);
    }
    if let Err(err) = verify_credential_proofs(
        &state.http,
        &message.credentials,
        state.config.insecure_http,
        &state.outbound,
    )
    .await
    {
        return validation_error_response(err);
    }
    state.store.store(StoredCredentialBatch {
        issuer_pid: message.issuer_pid,
        holder_pid: Some(message.holder_pid),
        status: message.status,
        rejection_reason: message.rejection_reason,
        credentials: message.credentials,
    });
    StatusCode::OK.into_response()
}

// ---- Credential Issuance Protocol: Credential Offer API ----

/// `POST /offers` on a Credential Service. See
/// `credential.issuance.protocol.md#credential-offer-api`. This bootstrap
/// records the offer as a real, queryable RDF record in the same
/// Contreforts-backed graph the Storage API uses (see
/// `identity_hub_graph::CredentialGraph::add_offer` and
/// `../../ARCHITECTURE.md`, "Provenance: Contreforts") but does not yet
/// trigger a holder-driven follow-up request - see `../../ARCHITECTURE.md`.
/// Requires a valid Self-Issued ID Token addressed to this service, the
/// same way `storage_write` does now (see that handler's doc comment,
/// including the trusted-issuer allow-list check). The offer's own
/// `credentials` array is validated too (`crate::validation::validate_offer_credentials`,
/// added 2026-09-20): it must be non-empty, and any *sparse* (id-only)
/// entry must resolve against the offering issuer's own real Issuer
/// Metadata API catalog.
async fn credential_offer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(message): Json<CredentialOfferMessage>,
) -> Response {
    let claims = match verify_bearer_token(
        &state.http,
        bearer_header(&headers),
        state.identity.own_did(),
        state.config.insecure_http,
        &state.seen_jti,
        &state.outbound,
    )
    .await
    {
        Ok(claims) => claims,
        Err(err) => return auth_error_response(err),
    };
    if let Err(err) = check_trusted_issuer(&claims, &state.config.trusted_issuer_dids) {
        return auth_error_response(err);
    }
    if let Err(err) = validate_offer_credentials(
        &state.http,
        &message.issuer,
        &message.credentials,
        state.config.insecure_http,
        &state.outbound,
    )
    .await
    {
        return validation_error_response(err);
    }
    let offer_id = state
        .store
        .graph()
        .add_offer(identity_hub_graph::NewAcceptedOffer {
            issuer: message.issuer.clone(),
            credentials: message
                .credentials
                .iter()
                .map(|c| identity_hub_graph::OfferedCredential {
                    id: c.id.clone(),
                    credential_type: c.credential_type.clone(),
                })
                .collect(),
        })
        .expect("accepted-offer insert into RDF store");
    tracing::info!(issuer = %message.issuer, count = message.credentials.len(), offer_id = %offer_id, "received credential offer, recorded as RDF");
    StatusCode::OK.into_response()
}

// ---- Credential Issuance Protocol: Issuer Service ----

/// `POST /credentials` on an Issuer Service (the Credential Request API).
/// See `credential.issuance.protocol.md#credential-request-api`.
///
/// On top of the token checks, the request is governed by the Issuer Admin
/// API's state (`crate::issuer`, contract section 1):
/// - every `credentials[].id` must name a definition in the catalog (`400`);
/// - the caller's DID is looked up in the holder registry: a `rejected`
///   holder is refused `403` with no process created; an unknown DID gets a
///   holder record, `approved` or `pending` per `--holder-approval`, or
///   `503` if the registry is full;
/// - the issuance process starts `APPROVED` (delivery spawned now) for an
///   approved holder, `SUBMITTED` (waits for the operator) otherwise.
///
/// With the default `--holder-approval auto` every first-time caller is
/// approved on the spot, which is exactly the pre-catalog behaviour the DCP
/// TCK was run against.
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
        &state.seen_jti,
        &state.outbound,
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

    let now = now_secs();
    let process_id = Uuid::new_v4().to_string();
    // Lock order: definitions -> holders -> requests (see `crate::issuer`).
    // All three are held together so a concurrent definition delete or
    // holder approval can never miss this process.
    let deliver_now = {
        let definitions = state.definitions.lock().expect("definitions lock poisoned");
        if message.credentials.is_empty() {
            return (StatusCode::BAD_REQUEST, "credentials must not be empty").into_response();
        }
        if let Some(unknown) = message
            .credentials
            .iter()
            .find(|c| definitions.get(&c.id).is_none())
        {
            return (
                StatusCode::BAD_REQUEST,
                format!("unknown credential id: '{}'", unknown.id),
            )
                .into_response();
        }
        let mut holders = state.holders.lock().expect("holders lock poisoned");
        let holder = match holders.by_did(&holder_did) {
            Some(holder) => holder.clone(),
            None => {
                let status = match state.config.holder_approval {
                    HolderApproval::Auto => HolderStatus::Approved,
                    HolderApproval::Manual => HolderStatus::Pending,
                };
                let new_holder = Holder {
                    holder_id: Uuid::new_v4().to_string(),
                    did: holder_did.clone(),
                    name: None,
                    properties: Default::default(),
                    status,
                    created_at: now,
                };
                match holders.insert(new_holder) {
                    Ok(holder) => holder,
                    Err(err) => {
                        tracing::warn!(?err, "refusing credential request: holder registry full");
                        return (StatusCode::SERVICE_UNAVAILABLE, "holder registry is full")
                            .into_response();
                    }
                }
            }
        };
        let process_state = match holder.status {
            HolderStatus::Rejected => {
                return (
                    StatusCode::FORBIDDEN,
                    "holder has been rejected by this issuer",
                )
                    .into_response();
            }
            HolderStatus::Pending => ProcessState::Submitted,
            HolderStatus::Approved => ProcessState::Approved,
        };
        state
            .requests
            .lock()
            .expect("requests lock poisoned")
            .insert(
                process_id.clone(),
                IssuanceProcess {
                    id: process_id.clone(),
                    state: process_state,
                    holder_id: holder.holder_id,
                    holder_did,
                    holder_pid: message.holder_pid.clone(),
                    credential_definitions: message
                        .credentials
                        .iter()
                        .map(|c| c.id.clone())
                        .collect(),
                    error_detail: None,
                    created_at: now,
                    state_timestamp: now,
                    delivery_bearer,
                },
            );
        process_state == ProcessState::Approved
    };

    if deliver_now {
        spawn_delivery(state.clone(), process_id.clone());
    }

    let mut response = StatusCode::CREATED.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        format!("/requests/{process_id}")
            .parse()
            .expect("request id is a valid header value"),
    );
    response
}

/// Starts the asynchronous delivery of an `APPROVED` issuance process - from
/// the Credential Request API for an already-approved holder, or from the
/// admin API's holder approval for every process that was waiting on it.
pub(crate) fn spawn_delivery(state: Arc<AppState>, process_id: String) {
    tokio::spawn(async move {
        deliver_issued_credential(state, process_id).await;
    });
}

/// What a delivery needs from its process record, copied out so no lock is
/// held across the network calls.
struct DeliveryJob {
    process_id: String,
    holder_id: String,
    holder_pid: String,
    holder_did: String,
    delivery_bearer: Option<String>,
    definitions: Vec<CredentialDefinition>,
}

/// The asynchronous half of the Credential Request API: resolves the
/// holder's own `did:web` document to find its `CredentialService`
/// endpoint, mints a self-issued token addressed to it, signs one real VC
/// per requested credential definition, and delivers them via the Storage
/// API - see `credential.issuance.protocol.md`, step 7 of the Issuance
/// Flow. Success records an issued-credential entry per VC and moves the
/// process to `DELIVERED`; any failure moves it to `ERRORED` with the reason
/// in `errorDetail`.
async fn deliver_issued_credential(state: Arc<AppState>, process_id: String) {
    // Caps how many delivery tasks are doing outbound network I/O at once
    // (`AppState::delivery_semaphore`, `state::MAX_IN_FLIGHT_DELIVERIES`) -
    // acquired here, inside the spawned task, never on the request path, so
    // the Credential Request API's own `201 Created` response (and the
    // admin API's approve response) is never delayed or refused by this.
    // See `../../ARCHITECTURE.md`, "What's simplified or stubbed"
    // (2026-09-20 independent security audit, MEDIUM).
    let _permit = state
        .delivery_semaphore
        .acquire()
        .await
        .expect("delivery_semaphore is never closed");

    let Some(process) = state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .get(&process_id)
        .cloned()
    else {
        // Evicted from the bounded table before delivery started.
        return;
    };
    let definitions: Result<Vec<CredentialDefinition>, String> = {
        let catalog = state.definitions.lock().expect("definitions lock poisoned");
        process
            .credential_definitions
            .iter()
            .map(|id| {
                catalog
                    .get(id)
                    .cloned()
                    .ok_or_else(|| format!("credential definition '{id}' no longer exists"))
            })
            .collect()
    };
    let outcome = match definitions {
        Ok(definitions) => {
            try_deliver_issued_credential(
                &state,
                DeliveryJob {
                    process_id: process.id.clone(),
                    holder_id: process.holder_id.clone(),
                    holder_pid: process.holder_pid.clone(),
                    holder_did: process.holder_did.clone(),
                    delivery_bearer: process.delivery_bearer.clone(),
                    definitions,
                },
            )
            .await
        }
        Err(err) => Err(err),
    };

    let now = now_secs();
    let (process_state, error_detail) = match outcome {
        Ok(records) => {
            let mut issued = state.issued.lock().expect("issued lock poisoned");
            for record in records {
                issued.insert(record);
            }
            (ProcessState::Delivered, None)
        }
        Err(err) => {
            tracing::warn!(process_id, error = %err, "failed to deliver issued credential");
            (ProcessState::Errored, Some(err))
        }
    };
    if let Some(record) = state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .get_mut(&process_id)
    {
        record.transition(process_state, now);
        record.error_detail = error_detail;
    }
}

async fn try_deliver_issued_credential(
    state: &AppState,
    job: DeliveryJob,
) -> Result<Vec<IssuedCredential>, String> {
    let holder_did = job.holder_did.as_str();
    // 2026-09-20 independent security audit, Finding 5 (HIGH): the holder's
    // own DID is a value this service was itself asked to resolve as part
    // of the Credential Request flow, but resolving it is still an
    // outbound request to a destination the caller ultimately named -
    // checked before `resolve_did`, mirroring `auth::verify_bearer_token`.
    state
        .outbound
        .check_did(holder_did, state.config.insecure_http)
        .map_err(|e| e.to_string())?;
    let holder_doc =
        dcp_core::resolve_did(&state.http, holder_did, state.config.insecure_http).await?;
    let endpoint = service_endpoint_url(&holder_doc, "CredentialService")?;
    // The delivery destination itself is a string lifted verbatim out of
    // the requester's own DID document - never validated before this fix
    // (2026-09-20 audit, Finding 5). Checked before the POST below.
    state
        .outbound
        .check_url(&endpoint)
        .map_err(|e| e.to_string())?;

    let mut containers = Vec::with_capacity(job.definitions.len());
    let mut records = Vec::with_capacity(job.definitions.len());
    for definition in &job.definitions {
        let index = state
            .issued
            .lock()
            .expect("issued lock poisoned")
            .status_list
            .allocate()
            .ok_or(
                "the revocation status list is exhausted; no further credentials can be issued",
            )?;
        let minted = mint_credential(state, definition, holder_did, Some(index));
        containers.push(CredentialContainer {
            credential_type: definition.credential_type.clone(),
            payload: json!(minted.jws),
            format: "jwt".to_string(),
        });
        records.push(IssuedCredential {
            id: minted.id,
            credential_type: definition.credential_type.clone(),
            credential_definition_id: definition.id.clone(),
            holder_id: job.holder_id.clone(),
            holder_did: holder_did.to_string(),
            issuance_process_id: job.process_id.clone(),
            format: definition.format.clone(),
            issued_at: minted.issued_at,
            expires_at: minted.expires_at,
            status: CredentialRecordStatus::Active,
            status_list_index: index,
        });
    }

    let message = CredentialMessage {
        context: vec![identity_hub_core::messages::DCP_CONTEXT.to_string()],
        message_type: "CredentialMessage".to_string(),
        issuer_pid: job.process_id.clone(),
        holder_pid: job.holder_pid.clone(),
        status: "ISSUED".to_string(),
        credentials: containers,
        rejection_reason: None,
    };

    // Per credential.issuance.protocol.md, step 7: "The Credential Issuer
    // authenticates by adding a Self-Issued ID Token of their own to the
    // CredentialMessage [request]. If present in the client's initial
    // Self-Issued ID Token, the access token MUST be contained in the
    // Credential Issuer's Self-Issued ID Token `token` claim."
    let now = now_secs();
    let mut si_payload = json!({
        "iss": state.identity.own_did(),
        "sub": state.identity.own_did(),
        "aud": holder_did,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": Uuid::new_v4().to_string(),
    });
    if let Some(token) = job.delivery_bearer {
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
    Ok(records)
}

/// A freshly signed credential and the facts its record needs.
pub(crate) struct MintedCredential {
    pub id: String,
    pub jws: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// The public URL of this issuer's revocation status list.
pub(crate) fn status_list_url(state: &AppState) -> String {
    format!("{}{STATUS_LIST_PATH}", state.base_url())
}

/// Signs `definition` as a JWT VC (`vc` claim, W3C VC 1.1 data model) bound
/// to `holder_did`, valid for the definition's `validity`. Shared by both
/// issuance protocols this hub speaks - DCP's asynchronous delivery
/// (`try_deliver_issued_credential`) and OID4VCI's Credential Endpoint
/// (`crate::oid4vci`) - so a holder gets the same credential whichever
/// protocol it asked through.
///
/// With `status_index`, the VC carries a `StatusList2021Entry` pointing at
/// that bit of [`status_list_url`]. DCP deliveries always pass one (they
/// get an issued-credential record the admin API can revoke); OID4VCI
/// issuance passes `None`, since nothing records it for revocation.
pub(crate) fn mint_credential(
    state: &AppState,
    definition: &CredentialDefinition,
    holder_did: &str,
    status_index: Option<usize>,
) -> MintedCredential {
    let issued_at = now_secs();
    let expires_at = issued_at + definition.validity;
    let id = format!("urn:uuid:{}", Uuid::new_v4());
    let mut vc = json!({
        "@context": [VC_CONTEXT],
        "id": id,
        "type": ["VerifiableCredential", definition.credential_type],
        "issuer": state.identity.own_did(),
        "credentialSubject": { "id": holder_did },
    });
    if let Some(index) = status_index {
        let list_url = status_list_url(state);
        vc["@context"] = json!([VC_CONTEXT, STATUS_LIST_CONTEXT]);
        vc["credentialStatus"] = json!({
            "id": format!("{list_url}#{index}"),
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": index.to_string(),
            "statusListCredential": list_url,
        });
    }
    let vc_payload = json!({
        "iss": state.identity.own_did(),
        "sub": holder_did,
        "vc": vc,
        "iat": issued_at,
        "exp": expires_at,
        "jti": id,
    });
    let jws = sign_jws(
        &vc_payload,
        &state.identity.key_pair.signing_key(),
        state.identity.own_key_id(),
    );
    MintedCredential {
        id,
        jws,
        issued_at,
        expires_at,
    }
}

/// `GET /requests/<id>` (Credential Request Status API). See
/// `credential.issuance.protocol.md#credential-request-status-api`. The
/// issuance process state is mapped onto DCP's three statuses by
/// `ProcessState::dcp_status`.
async fn request_status(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match state
        .requests
        .lock()
        .expect("requests lock poisoned")
        .get(&id)
    {
        Some(record) => Json(CredentialStatus::new(
            record.id.clone(),
            record.holder_pid.clone(),
            record.state.dcp_status(),
        ))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// One catalog entry as a DCP `CredentialObject`.
pub(crate) fn credential_object(definition: &CredentialDefinition) -> CredentialObject {
    CredentialObject {
        context: None,
        id: definition.id.clone(),
        object_type: "CredentialObject".to_string(),
        credential_type: Some(definition.credential_type.clone()),
        binding_methods: Some(vec!["did:web".to_string()]),
        credential_schema: None,
        profile: Some("vc10-sl2021/jwt".to_string()),
        issuance_policy: None,
        offer_reason: None,
    }
}

/// `GET /metadata` (Issuer Metadata API). See
/// `credential.issuance.protocol.md#issuer-metadata-api`. Lists the whole
/// credential catalog, in catalog order.
async fn issuer_metadata(State(state): State<Arc<AppState>>) -> Json<IssuerMetadata> {
    let supported = state
        .definitions
        .lock()
        .expect("definitions lock poisoned")
        .all()
        .iter()
        .map(credential_object)
        .collect();
    Json(IssuerMetadata::new(
        state.identity.own_did().to_string(),
        supported,
    ))
}

/// `GET /statuslist/revocation`: this issuer's StatusList2021Credential as a
/// JWT signed with the issuer's own key (`application/vc+jwt`). Public and
/// unauthenticated by design - verifiers dereference `statusListCredential`
/// - so the signed JWT is cached until the next revocation changes a bit.
async fn status_list(State(state): State<Arc<AppState>>) -> Response {
    let jwt = {
        let mut issued = state.issued.lock().expect("issued lock poisoned");
        match &issued.status_list.cached_jwt {
            Some(jwt) => jwt.clone(),
            None => {
                let list_url = status_list_url(&state);
                let now = now_secs();
                let payload = json!({
                    "iss": state.identity.own_did(),
                    "sub": list_url,
                    "iat": now,
                    "nbf": now,
                    "vc": {
                        "@context": [VC_CONTEXT, STATUS_LIST_CONTEXT],
                        "id": list_url,
                        "type": ["VerifiableCredential", "StatusList2021Credential"],
                        "issuer": state.identity.own_did(),
                        "credentialSubject": {
                            "id": format!("{list_url}#list"),
                            "type": "StatusList2021",
                            "statusPurpose": "revocation",
                            "encodedList": issued.status_list.encoded(),
                        },
                    },
                });
                let jwt = sign_jws(
                    &payload,
                    &state.identity.key_pair.signing_key(),
                    state.identity.own_key_id(),
                );
                issued.status_list.cached_jwt = Some(jwt.clone());
                jwt
            }
        }
    };
    ([(header::CONTENT_TYPE, "application/vc+jwt")], jwt).into_response()
}
