//! Validates an incoming Self-Issued ID Token per
//! `specifications/base.protocol.md#validating-self-issued-id-tokens`:
//! resolve the caller's `did:web` document, find the verification method
//! named by the JWS `kid` header, verify the signature, then check
//! `aud`/`exp`. Real `jti`-replay tracking and `nbf` leeway are out of scope
//! for this bootstrap (see `../../ARCHITECTURE.md`).

use dcp_core::{
    decode_jws_unverified, find_verifying_key, now_secs, resolve_did, verify_jws_signature,
};
use serde_json::Value;

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
}

/// Extracts a Self-Issued ID Token from an `Authorization: Bearer <jwt>`
/// header value, verifies it against the caller's resolved `did:web`
/// document, and asserts it is addressed to `expected_audience` (this
/// service's own DID) and not expired. Returns the token's decoded JSON
/// payload (`iss`/`sub`/`aud`/optionally `token`, ...) for the caller to
/// inspect further.
pub async fn verify_bearer_token(
    http: &reqwest::Client,
    authorization_header: Option<&str>,
    expected_audience: &str,
    insecure_http: bool,
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

    let aud = payload.get("aud").and_then(Value::as_str).unwrap_or("");
    if aud != expected_audience {
        return Err(AuthError::WrongAudience);
    }

    let exp = payload.get("exp").and_then(Value::as_u64).unwrap_or(0);
    if exp <= now_secs() {
        return Err(AuthError::Expired);
    }

    Ok(payload)
}
