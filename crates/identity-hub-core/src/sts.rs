//! A minimal in-memory Secure Token Service (STS): one hardcoded
//! client_id/client_secret pair, an OAuth2 `client_credentials`-grant-shaped
//! `/sts/token` request/response (see
//! `specifications/identity-trust-sts-api.yaml` in
//! `eclipse-dataspace-dcp/decentralized-claims-protocol`), and a real
//! ES256-signed Self-Issued ID Token minted from it.
//!
//! ## Whose identity does the minted token carry?
//!
//! The DCP presentation flow has each participant obtain Self-Issued ID
//! Tokens from *its own* STS, signed with *its own* key. This bootstrap's
//! own Credential Service also hosts the STS the real, official
//! `dcp-tck` container is configured to call (`dataspacetck.sts.url`) when
//! it plays the Verifier role against our Presentation API - the TCK has no
//! DCP identity infrastructure of its own to mint that token with.
//!
//! So the token minted here is signed with a *second*, synthetic
//! [`identity::ServiceIdentity`](crate::identity::ServiceIdentity) this
//! process also generates and hosts a `did:web` document for (conventionally
//! at the `sts-party` path segment) - never with the Credential/Issuer
//! Service's own identity, which must stay resolvable as a stable
//! `did.holder`/`did.issuer` value across a whole TCK run and shouldn't be
//! shared with an unrelated STS-client role. This mirrors the same
//! "separate identity for a locally hosted counterparty" pattern
//! `ds-catalog-broker-rs/compliance/dcp-test-env`'s "verifier" participant
//! and `ds-dcp-core-rs::HolderIdentity` already use, just generated
//! in-process instead of via a real second Java runtime.
use dcp_core::{now_secs, sign_jws};
use serde::Serialize;

use crate::identity::ServiceIdentity;

pub struct StsConfig {
    pub client_id: String,
    pub client_secret: String,
}

impl StsConfig {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StsError {
    #[error("unsupported_grant_type: only client_credentials is supported")]
    UnsupportedGrantType,
    #[error("invalid_client: unknown client_id/client_secret")]
    InvalidClient,
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
}

/// A `/sts/token` request, already parsed out of its
/// `application/x-www-form-urlencoded` body per
/// `specifications/identity-trust-sts-api.yaml`.
pub struct StsTokenRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    /// The intended audience of the minted **outer** Self-Issued ID Token
    /// envelope - the DID of whichever party this envelope is addressed to.
    ///
    /// This is *not* automatically the same party that will go on to
    /// *present* the **nested** `token` claim (see `bearer_access_scope`
    /// below) - that used to be the bug (2026-09-20 security audit, Finding
    /// 9, MEDIUM): the nested access token's own `aud` binds to whoever
    /// presents it, which is this envelope's own `audience` only in the
    /// direct case (a caller asking for a token to present straight back to
    /// this Credential Service); in the DCP hand-off case the real TCK
    /// exercises, `audience` is the verifier that will receive and forward
    /// the envelope, while the presenter of the nested grant stays this
    /// STS's own party. See `issue_token`'s doc comment for exactly how the
    /// nested `aud` is derived from this field plus `own_service_did`,
    /// rather than copied from it.
    pub audience: String,
    /// Requested scope for the nested `token` claim (a
    /// Verifiable-Presentation access token); per `base.protocol.md`, no
    /// `bearer_access_scope` means no `token` claim.
    pub bearer_access_scope: Option<String>,
    /// This Credential/Issuer Service's own DID (`AppState::identity`, not
    /// `signer`/`sts_party`) - needed to tell apart the two cases
    /// `audience`'s own doc comment describes. See `issue_token`.
    pub own_service_did: String,
}

#[derive(Debug, Serialize)]
pub struct StsTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

const TOKEN_TTL_SECS: u64 = 300;

/// Validates `req` against `config` and, if valid, mints a Self-Issued ID
/// Token signed by `signer` (see this module's doc comment for why that's a
/// distinct identity from the Credential/Issuer Service's own).
///
/// ## The nested access token's `aud` is not always `req.audience`
///
/// The outer envelope's `aud` is always `req.audience`, unconditionally -
/// that part is simple: it is who this *envelope* is addressed to. The
/// nested `token` claim (when `req.bearer_access_scope` is present) is a
/// second, structurally different JWS - a bearer access token that gets
/// *presented* by whoever holds it, and its own `aud` must bind to
/// *that* party, not to whoever the outer envelope happens to be addressed
/// to (2026-09-20 security audit, Finding 9, MEDIUM - conflating the two
/// meant a token this hub's own STS minted for its own direct case could
/// never pass its own `auth::verify_nested_access_token`, since that check
/// compares the nested `aud` against the outer envelope's `sub`, which is
/// always `signer.own_did()`).
///
/// - If `req.audience == req.own_service_did` - the caller asked for a
///   token to present straight back to *this* Credential Service - then
///   `signer` (this STS's own party) is the one presenting the nested
///   grant, so nested `aud = signer.own_did()`.
/// - Otherwise - the DCP hand-off the real TCK exercises
///   (`DcpSystemLauncher.createAuthToken` requests a token audienced to the
///   *verifier*, which receives the outer envelope, discards it, and
///   re-presents only the nested token wrapped in its own new envelope) -
///   the presenter is whoever `req.audience` names, so nested
///   `aud = req.audience`, unchanged.
pub fn issue_token(
    config: &StsConfig,
    signer: &ServiceIdentity,
    req: StsTokenRequest,
) -> Result<StsTokenResponse, StsError> {
    if req.grant_type != "client_credentials" {
        return Err(StsError::UnsupportedGrantType);
    }
    if req.client_id != config.client_id || req.client_secret != config.client_secret {
        return Err(StsError::InvalidClient);
    }
    if req.audience.trim().is_empty() {
        return Err(StsError::InvalidRequest(
            "audience must not be empty".to_string(),
        ));
    }

    let now = now_secs();
    let mut payload = serde_json::json!({
        "iss": signer.own_did(),
        "sub": signer.own_did(),
        "aud": req.audience,
        "iat": now,
        "nbf": now,
        "exp": now + TOKEN_TTL_SECS,
        "jti": uuid::Uuid::new_v4().to_string(),
    });

    if let Some(scope) = req.bearer_access_scope {
        // The nested access token's own `aud` binds to whoever will
        // *present* it, which is only `req.audience` in the direct case -
        // see this function's own doc comment for why the two cases differ.
        let nested_aud = if req.audience == req.own_service_did {
            signer.own_did().to_string()
        } else {
            req.audience.clone()
        };
        // A real access token in its own right (see base.protocol.md,
        // "Verifiable Presentation Access Token"): itself a JWS, signed by
        // the same identity, scoped to whoever will present it.
        let access_token_payload = serde_json::json!({
            "iss": signer.own_did(),
            "sub": signer.own_did(),
            "aud": nested_aud,
            "scope": scope,
            "iat": now,
            "exp": now + TOKEN_TTL_SECS,
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        let access_token = sign_jws(
            &access_token_payload,
            &signer.key_pair.signing_key(),
            signer.own_key_id(),
        );
        payload["token"] = serde_json::json!(access_token);
    }

    let id_token = sign_jws(
        &payload,
        &signer.key_pair.signing_key(),
        signer.own_key_id(),
    );
    Ok(StsTokenResponse {
        access_token: id_token,
        expires_in: TOKEN_TTL_SECS,
        token_type: "Bearer".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcp_core::decode_jws_unverified;

    #[test]
    fn issues_a_real_signed_id_token_for_valid_client_credentials() {
        let config = StsConfig::new("client-1", "secret-1");
        let signer = ServiceIdentity::new("localhost:9999", "sts-party");
        // The direct case: the caller asks for a token to present straight
        // back to this Credential Service, so `audience == own_service_did`
        // and the nested access token's `aud` must bind to `signer` itself
        // (2026-09-20 security audit, Finding 9) - not to `audience`, which
        // is only correct for the DCP hand-off case (see `issue_token`'s
        // doc comment and `StsTokenRequest::audience`'s).
        let response = issue_token(
            &config,
            &signer,
            StsTokenRequest {
                grant_type: "client_credentials".to_string(),
                client_id: "client-1".to_string(),
                client_secret: "secret-1".to_string(),
                audience: "did:web:localhost%3A9999:credential-service".to_string(),
                bearer_access_scope: Some(
                    "org.eclipse.dspace.dcp.vc.type:MembershipCredential".to_string(),
                ),
                own_service_did: "did:web:localhost%3A9999:credential-service".to_string(),
            },
        )
        .expect("valid request issues a token");

        assert_eq!(response.token_type, "Bearer");
        let (_, _, payload) = decode_jws_unverified(&response.access_token).unwrap();
        assert_eq!(payload["iss"], serde_json::json!(signer.own_did()));
        assert_eq!(payload["sub"], serde_json::json!(signer.own_did()));
        assert_eq!(
            payload["aud"],
            serde_json::json!("did:web:localhost%3A9999:credential-service"),
            "the outer envelope's aud is always req.audience, unconditionally"
        );
        let nested_token = payload["token"]
            .as_str()
            .expect("bearer_access_scope must produce a token claim");
        let (_, _, nested_payload) = decode_jws_unverified(nested_token).unwrap();
        assert_eq!(
            nested_payload["aud"],
            serde_json::json!(signer.own_did()),
            "in the direct case (audience == own_service_did), the nested access token \
             is presented by signer itself, so its aud must bind to signer.own_did() - \
             not to req.audience, which is signer's own outer sub and would make this \
             hub's own STS output rejected by this hub's own verifier (Finding 9)"
        );
    }

    #[test]
    fn rejects_wrong_client_secret() {
        let config = StsConfig::new("client-1", "secret-1");
        let signer = ServiceIdentity::new("localhost:9999", "sts-party");
        let err = issue_token(
            &config,
            &signer,
            StsTokenRequest {
                grant_type: "client_credentials".to_string(),
                client_id: "client-1".to_string(),
                client_secret: "wrong".to_string(),
                audience: "did:web:localhost%3A9999:credential-service".to_string(),
                bearer_access_scope: None,
                own_service_did: "did:web:localhost%3A9999:credential-service".to_string(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, StsError::InvalidClient));
    }

    #[test]
    fn no_bearer_access_scope_means_no_token_claim() {
        let config = StsConfig::new("client-1", "secret-1");
        let signer = ServiceIdentity::new("localhost:9999", "sts-party");
        let response = issue_token(
            &config,
            &signer,
            StsTokenRequest {
                grant_type: "client_credentials".to_string(),
                client_id: "client-1".to_string(),
                client_secret: "secret-1".to_string(),
                audience: "did:web:localhost%3A9999:credential-service".to_string(),
                bearer_access_scope: None,
                own_service_did: "did:web:localhost%3A9999:credential-service".to_string(),
            },
        )
        .unwrap();
        let (_, _, payload) = decode_jws_unverified(&response.access_token).unwrap();
        assert!(payload.get("token").is_none());
    }

    #[test]
    fn nested_access_token_aud_stays_the_audience_in_the_dcp_hand_off_case() {
        // The DCP hand-off the real TCK exercises: `req.audience` names the
        // verifier that will receive this outer envelope and re-present the
        // nested token onward, which is *not* this service itself - so the
        // nested aud must stay `req.audience`, unchanged (2026-09-20
        // security audit, Finding 9's non-regression requirement).
        let config = StsConfig::new("client-1", "secret-1");
        let signer = ServiceIdentity::new("localhost:9999", "sts-party");
        let response = issue_token(
            &config,
            &signer,
            StsTokenRequest {
                grant_type: "client_credentials".to_string(),
                client_id: "client-1".to_string(),
                client_secret: "secret-1".to_string(),
                audience: "did:web:verifier.example:verifier".to_string(),
                bearer_access_scope: Some(
                    "org.eclipse.dspace.dcp.vc.type:MembershipCredential".to_string(),
                ),
                own_service_did: "did:web:localhost%3A9999:credential-service".to_string(),
            },
        )
        .expect("valid request issues a token");

        let (_, _, payload) = decode_jws_unverified(&response.access_token).unwrap();
        let nested_token = payload["token"].as_str().unwrap();
        let (_, _, nested_payload) = decode_jws_unverified(nested_token).unwrap();
        assert_eq!(
            nested_payload["aud"],
            serde_json::json!("did:web:verifier.example:verifier"),
            "when audience != own_service_did, the presenter is whoever audience names"
        );
    }
}
