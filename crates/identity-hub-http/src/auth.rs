//! Validates an incoming Self-Issued ID Token per
//! `specifications/base.protocol.md#validating-self-issued-id-tokens`:
//! resolve the caller's `did:web` document, find the verification method
//! named by the JWS `kid` header, verify the signature, check that the
//! signing key is actually authorized to invoke a capability
//! (`capabilityInvocation`), then check `iss == sub`, `aud`, `exp`, `nbf`,
//! `iat` (not in the future), and `jti` replay. Every one of these is now
//! real. [`check_trusted_issuer`] is a separate, later step (DCP's own
//! "Verify Trust") that endpoints expecting one specific counterparty (the
//! Storage/Credential Offer APIs) call afterwards - see its own doc comment
//! and `../../ARCHITECTURE.md`'s "DCP TCK conformance snapshot" for exactly
//! which TCK-caught gaps this closed and which (nested-access-token
//! authentication, message-content validation) remain out of this
//! bootstrap's scope.

use std::collections::HashSet;
use std::sync::Mutex;

use dcp_core::{
    decode_jws_unverified, find_verifying_key, now_secs, resolve_did, verify_jws_signature,
};
use serde_json::Value;

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
