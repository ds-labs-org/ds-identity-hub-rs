//! Validates an incoming Self-Issued ID Token per
//! `specifications/base.protocol.md#validating-self-issued-id-tokens`:
//! resolve the caller's `did:web` document, find the verification method
//! named by the JWS `kid` header, verify the signature, check that the
//! signing key is actually authorized to invoke a capability
//! (`capabilityInvocation`), then check `iss == sub`, `aud`, `exp`, `nbf`,
//! `iat` (not in the future), and `jti` replay. Every one of these is now
//! real. [`check_trusted_issuer`] is a separate, later step (DCP's own
//! "Verify Trust") that endpoints expecting one specific counterparty (the
//! Storage/Credential Offer APIs) call afterwards - see its own doc comment.
//! [`verify_nested_access_token`] is yet another, separate step - it
//! authenticates the caller's own nested `token` claim (the actual
//! Verifiable-Presentation access token forwarded inside the outer
//! envelope, per `base.protocol.md`), called by the Presentation API - see
//! its own doc comment and `../../ARCHITECTURE.md`'s "DCP TCK conformance
//! snapshot" for exactly which TCK-caught gaps each of these closed.

use std::collections::HashSet;
use std::sync::Mutex;

use dcp_core::{
    decode_jws_unverified, find_verifying_key, now_secs, resolve_did, verify_jws_signature,
};
use serde_json::Value;

use crate::outbound::OutboundPolicy;

/// How far into the future an `nbf` claim may sit before a token is treated
/// as not-yet-valid, to tolerate ordinary clock skew between this process
/// and a genuinely legitimate caller's own clock - not a deliberate
/// weakening of the check itself (an `nbf` past this window is still
/// rejected).
const NBF_LEEWAY_SECS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing or malformed Authorization: Bearer header")]
    MissingToken,
    #[error("could not resolve caller DID: {0}")]
    DidResolution(String),
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("token audience does not match this service's DID")]
    WrongAudience,
    #[error("token has expired")]
    Expired,
    #[error("token sub does not match iss - a Self-Issued ID Token must be about its own issuer")]
    IssuerSubjectMismatch,
    #[error("token is not yet valid (nbf is in the future)")]
    NotYetValid,
    #[error("token iat (issued-at) is in the future")]
    IssuedInFuture,
    #[error(
        "signing key '{0}' is not listed under the caller's own capabilityInvocation verification relationship"
    )]
    KeyNotAuthorizedForInvocation(String),
    #[error("token jti has already been used (replay)")]
    TokenReplayed,
    #[error("issuer '{0}' is not on this service's trusted-issuer allow-list")]
    UntrustedIssuer(String),
    #[error("nested access token is not valid: {0}")]
    InvalidNestedToken(String),
    #[error("nested access token has expired")]
    NestedTokenExpired,
    #[error(
        "nested access token is not bound to the party presenting it (aud does not match the outer envelope's own caller)"
    )]
    NestedTokenNotBoundToCaller,
    #[error("nested access token issuer '{0}' is not authoritative for this service's credentials")]
    NestedTokenIssuerNotAuthoritative(String),
    #[error("outbound destination is not allowed: {0}")]
    OutboundDestinationNotAllowed(String),
}

/// Extracts a Self-Issued ID Token from an `Authorization: Bearer <jwt>`
/// header value, verifies it against the caller's resolved `did:web`
/// document, and asserts:
///
/// - the signing key is listed under the caller's own `capabilityInvocation`
///   array (`base.protocol.md`, "Validating Self-Issued ID Tokens", step 3 -
///   not just present in `verificationMethod`, which only proves the key
///   belongs to the DID at all);
/// - `sub` equals `iss` (a Self-Issued ID Token is always about its own
///   issuer - a mismatch means the caller is trying to assert an identity
///   it isn't signing as);
/// - `aud` matches `expected_audience` (this service's own DID);
/// - the token is not expired (`exp`) and, if `nbf` is present, not yet
///   valid (with [`NBF_LEEWAY_SECS`] of clock-skew tolerance);
/// - if `iat` is present, it is not in the future (with the same
///   [`NBF_LEEWAY_SECS`] clock-skew tolerance as `nbf` - a correctly-clocked
///   signer can never produce an issued-at timestamp ahead of "now");
/// - `jti`, once seen in `seen_jti`, is never accepted again for the
///   lifetime of this process (in-memory only - sufficient for this
///   bootstrap's process-lifetime scope, see `../../ARCHITECTURE.md`).
///
/// Returns the token's decoded JSON payload (`iss`/`sub`/`aud`/optionally
/// `token`, ...) for the caller to inspect further.
pub async fn verify_bearer_token(
    http: &reqwest::Client,
    authorization_header: Option<&str>,
    expected_audience: &str,
    insecure_http: bool,
    seen_jti: &Mutex<HashSet<String>>,
    outbound: &OutboundPolicy,
) -> Result<Value, AuthError> {
    let token = authorization_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(AuthError::MissingToken)?;

    let (_, header, payload) =
        decode_jws_unverified(token).map_err(|e| AuthError::InvalidSignature(e.to_string()))?;
    let caller_did = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::InvalidSignature("token has no iss claim".to_string()))?;
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::InvalidSignature("token has no kid header".to_string()))?;

    // 2026-09-20 independent security audit, Finding 4 (HIGH): an
    // unauthenticated caller's own `iss` claim is entirely attacker-chosen,
    // and this function must resolve it before it can check anything at
    // all - so the destination is checked against the outbound allow-list
    // *before* `resolve_did` is ever reached, not after.
    outbound
        .check_did(caller_did, insecure_http)
        .map_err(|e| AuthError::OutboundDestinationNotAllowed(e.to_string()))?;

    let caller_doc = resolve_did(http, caller_did, insecure_http)
        .await
        .map_err(AuthError::DidResolution)?;
    let caller_key = find_verifying_key(&caller_doc, kid).map_err(AuthError::InvalidSignature)?;
    verify_jws_signature(token, &caller_key).map_err(AuthError::InvalidSignature)?;

    if !caller_doc.capability_invocation.iter().any(|id| id == kid) {
        return Err(AuthError::KeyNotAuthorizedForInvocation(kid.to_string()));
    }

    let sub = payload.get("sub").and_then(Value::as_str).unwrap_or("");
    if sub != caller_did {
        return Err(AuthError::IssuerSubjectMismatch);
    }

    let aud = payload.get("aud").and_then(Value::as_str).unwrap_or("");
    if aud != expected_audience {
        return Err(AuthError::WrongAudience);
    }

    let exp = payload.get("exp").and_then(Value::as_u64).unwrap_or(0);
    if exp <= now_secs() {
        return Err(AuthError::Expired);
    }

    if let Some(nbf) = payload.get("nbf").and_then(Value::as_u64)
        && nbf > now_secs() + NBF_LEEWAY_SECS
    {
        return Err(AuthError::NotYetValid);
    }

    if let Some(iat) = payload.get("iat").and_then(Value::as_u64)
        && iat > now_secs() + NBF_LEEWAY_SECS
    {
        return Err(AuthError::IssuedInFuture);
    }

    if let Some(jti) = payload.get("jti").and_then(Value::as_str) {
        let mut seen = seen_jti.lock().expect("seen_jti lock poisoned");
        if !seen.insert(jti.to_string()) {
            return Err(AuthError::TokenReplayed);
        }
    }

    Ok(payload)
}

/// The DCP spec's own "Verify Trust" step: distinct from, and applied after,
/// `verify_bearer_token`'s signature/envelope checks, which only prove a
/// token's `iss` really signed it - not that this service has any reason to
/// treat that `iss` as *the* issuer it expects to hear from on an endpoint
/// like the Storage API or Credential Offer API. `trusted_issuer_dids` empty
/// means no restriction is configured (this bootstrap's permissive default -
/// see `Config::trusted_issuer_dids`'s doc comment); non-empty, `claims`'
/// `iss` must be one of them.
pub fn check_trusted_issuer(
    claims: &Value,
    trusted_issuer_dids: &[String],
) -> Result<(), AuthError> {
    if trusted_issuer_dids.is_empty() {
        return Ok(());
    }
    let iss = claims.get("iss").and_then(Value::as_str).unwrap_or("");
    if trusted_issuer_dids.iter().any(|trusted| trusted == iss) {
        Ok(())
    } else {
        Err(AuthError::UntrustedIssuer(iss.to_string()))
    }
}

/// Authenticates the caller's own nested `token` claim (the DCP
/// "Verifiable Presentation Access Token", `base.protocol.md`) - distinct
/// from, and applied after, `verify_bearer_token`'s validation of the
/// *outer* Self-Issued ID Token envelope that carries it.
///
/// This checks both that the nested token is *authentic* (genuinely signed
/// by whoever it claims to be from, not expired, bound to the party
/// presenting it) and that its issuer is *authoritative* - i.e. actually
/// recognized by this service as a party allowed to grant reads of its own
/// credentials. The two are independent: an attacker who hosts a perfectly
/// well-formed `did:web` document can mint a token that is authentic (it
/// really is signed by them) but has no authority whatsoever over this
/// service's store. Checking only authenticity was the 2026-09-20 security
/// audit's Finding 2 (CRITICAL).
///
/// Concretely:
/// - the nested token's own `iss` must equal `authoritative_issuer` (this
///   service's own STS party DID - the only party this bootstrap's
///   Presentation API recognizes as able to grant reads of its own store,
///   see `handlers::granted_credential_types`'s call site for why). This is
///   checked *before* `resolve_did` so an attacker-controlled DID is never
///   fetched at all for a token that could never have been authoritative in
///   the first place.
/// - the nested token's own signature verifies against its own resolved
///   `did:web` issuer (the same `resolve_did`/`find_verifying_key`/
///   `verify_jws_signature` primitives `verify_bearer_token` already uses for
///   the outer envelope);
/// - it has not expired;
/// - and - the confused-deputy fix, closing `cs_04_03_03_idTokenInvalidIssuerSub` -
///   its own `aud` claim equals `outer_sub` (the outer envelope's own
///   `iss`/`sub`, i.e. whoever is actually presenting this request): a
///   nested token minted for/bound to a *different* party is a forwarded
///   token, not a legitimate grant to the party presenting it now. This
///   check is not subsumed by the issuer check above: a token our own STS
///   genuinely minted (so `iss` passes) but bound to the verifier and
///   forwarded by a third party must still be rejected here.
///
/// Returns the nested token's decoded payload (so the caller can read its
/// own `scope` claim) on success. Callers must treat any `Err` here as an
/// outright rejection of the whole request rather than a fallback to
/// unrestricted access - once a nested token is present at all, it must be
/// genuinely authenticated and authorized, not best-effort-decoded (see
/// `cs_05_04_invalidTokenNotAuthorized`, whose nested token, `"faketoken"`,
/// isn't even a real JWS).
pub async fn verify_nested_access_token(
    http: &reqwest::Client,
    nested_token: &str,
    outer_sub: &str,
    authoritative_issuer: &str,
    insecure_http: bool,
    outbound: &OutboundPolicy,
) -> Result<Value, AuthError> {
    let (_, header, payload) = decode_jws_unverified(nested_token)
        .map_err(|e| AuthError::InvalidNestedToken(e.to_string()))?;
    let nested_iss = payload.get("iss").and_then(Value::as_str).ok_or_else(|| {
        AuthError::InvalidNestedToken("nested token has no iss claim".to_string())
    })?;
    let kid = header.get("kid").and_then(Value::as_str).ok_or_else(|| {
        AuthError::InvalidNestedToken("nested token has no kid header".to_string())
    })?;

    if nested_iss != authoritative_issuer {
        return Err(AuthError::NestedTokenIssuerNotAuthoritative(
            nested_iss.to_string(),
        ));
    }

    // Defence in depth (the authoritative-issuer check above already
    // narrows `nested_iss` to exactly `authoritative_issuer`, so this can
    // only ever reject when that party's own host somehow isn't
    // allow-listed) - checked before `resolve_did`, mirroring
    // `verify_bearer_token`'s own ordering.
    outbound
        .check_did(nested_iss, insecure_http)
        .map_err(|e| AuthError::OutboundDestinationNotAllowed(e.to_string()))?;

    let issuer_doc = resolve_did(http, nested_iss, insecure_http)
        .await
        .map_err(AuthError::DidResolution)?;
    let issuer_key = find_verifying_key(&issuer_doc, kid).map_err(AuthError::InvalidNestedToken)?;
    verify_jws_signature(nested_token, &issuer_key).map_err(AuthError::InvalidNestedToken)?;

    let exp = payload.get("exp").and_then(Value::as_u64).unwrap_or(0);
    if exp <= now_secs() {
        return Err(AuthError::NestedTokenExpired);
    }

    let nested_aud = payload.get("aud").and_then(Value::as_str).unwrap_or("");
    if nested_aud != outer_sub {
        return Err(AuthError::NestedTokenNotBoundToCaller);
    }

    Ok(payload)
}
