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
    /// The intended audience of the minted Self-Issued ID Token - the DID
    /// of whichever party this token will be presented to.
    pub audience: String,
    /// Requested scope for the nested `token` claim (a
    /// Verifiable-Presentation access token); per `base.protocol.md`, no
    /// `bearer_access_scope` means no `token` claim.
    pub bearer_access_scope: Option<String>,
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
        // A real access token in its own right (see base.protocol.md,
        // "Verifiable Presentation Access Token"): itself a JWS, signed by
        // the same identity, scoped to the same audience.
        let access_token_payload = serde_json::json!({
            "iss": signer.own_did(),
            "sub": signer.own_did(),
            "aud": req.audience,
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
            },
        )
        .expect("valid request issues a token");

        assert_eq!(response.token_type, "Bearer");
        let (_, _, payload) = decode_jws_unverified(&response.access_token).unwrap();
        assert_eq!(payload["iss"], serde_json::json!(signer.own_did()));
        assert_eq!(payload["sub"], serde_json::json!(signer.own_did()));
        assert_eq!(
            payload["aud"],
            serde_json::json!("did:web:localhost%3A9999:credential-service")
        );
        assert!(
            payload["token"].is_string(),
            "bearer_access_scope must produce a token claim"
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
            },
        )
        .unwrap();
        let (_, _, payload) = decode_jws_unverified(&response.access_token).unwrap();
        assert!(payload.get("token").is_none());
    }
}
