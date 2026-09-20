//! Message-content/business-logic validation for the Storage API
//! (`POST /credentials`) and Credential Offer API (`POST /offers`) -
//! distinct from, and applied *after*, `crate::auth`'s Self-Issued ID Token
//! checks (`verify_bearer_token`/`check_trusted_issuer`): every case this
//! module handles presents a genuinely valid, genuinely trusted token, so
//! what's being rejected is the *message itself*, not who sent it. See
//! `../../ARCHITECTURE.md`'s "What's simplified or stubbed" ("No
//! message-content/business-logic validation...") for the four gaps this
//! closes, and `crate::handlers::storage_write`/`credential_offer` for how
//! they're wired in. Investigated by decompiling the real
//! `eclipsedataspacetck/dcp-tck-runtime:latest`'s own
//! `org.eclipse.dataspacetck.dcp.verification.issuance.cs.CredentialIssuanceTest`/
//! `CredentialOfferTest` and their shared `org.eclipse.dataspacetck.dcp.system.cs`
//! model classes, not guessed from test names alone.

use std::collections::HashSet;

use serde_json::Value;

use identity_hub_core::messages::{CredentialContainer, CredentialObject, IssuerMetadata};

/// `CredentialMessage.status` values this bootstrap recognizes - the same
/// two the real TCK's own (decompiled)
/// `org.eclipse.dataspacetck.dcp.system.cs.CredentialMessage.validate()`
/// checks against: `"ISSUED"` (delivery succeeded) and `"REJECTED"` (the
/// issuer declined, with `rejectionReason` carrying why).
const VALID_CREDENTIAL_MESSAGE_STATUSES: &[&str] = &["ISSUED", "REJECTED"];

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error(
        "credential message status '{0}' is not one of the recognized values (ISSUED, REJECTED)"
    )]
    InvalidStatus(String),
    #[error("holderPid '{0}' does not match a request this service was configured to expect")]
    UnknownHolderPid(String),
    #[error("a credential's own embedded proof could not be verified: {0}")]
    UnverifiableProof(String),
    #[error("a CredentialOfferMessage must offer at least one credential")]
    EmptyCredentials,
    #[error("offered credential id '{0}' does not match the issuer's own known catalog")]
    UnknownCredentialId(String),
    #[error("could not resolve the offering issuer's own credential catalog: {0}")]
    CatalogUnavailable(String),
}

/// `CredentialMessage.status` must be one of [`VALID_CREDENTIAL_MESSAGE_STATUSES`] -
/// closes the real TCK's own
/// `cs_06_05_01_credentialMessage_invalidStatus`/`cs_06_06_01_credentialOfferMessage_invalidStatus`-style
/// gap: before this check existed, `storage_write` stored a batch with any
/// `status` string at all, "INVALID_STATUS" included.
pub fn validate_status(status: &str) -> Result<(), ValidationError> {
    if VALID_CREDENTIAL_MESSAGE_STATUSES.contains(&status) {
        Ok(())
    } else {
        Err(ValidationError::InvalidStatus(status.to_string()))
    }
}

/// `holderPid` must match a value this service was configured to expect -
/// see `Config::known_holder_pids`'s doc comment for why an empty list
/// (this bootstrap's permissive default) means no restriction is
/// configured, the same posture `Config::trusted_issuer_dids` already
/// established for the caller's own identity rather than the message's
/// correlation id.
pub fn check_known_holder_pid(
    holder_pid: &str,
    known_holder_pids: &[String],
) -> Result<(), ValidationError> {
    if known_holder_pids.is_empty() || known_holder_pids.iter().any(|known| known == holder_pid) {
        Ok(())
    } else {
        Err(ValidationError::UnknownHolderPid(holder_pid.to_string()))
    }
}

/// Genuinely verifies every JWT-format credential container's own embedded
/// JWS proof: resolves the credential's own `iss` claim's `did:web`
/// document, finds the verification method named by the JWS `kid` header,
/// and checks the signature against it - reusing exactly the primitives
/// `crate::auth::verify_bearer_token` already uses for the *outer*
/// Self-Issued ID Token envelope (`dcp_core::{resolve_did,
/// find_verifying_key, verify_jws_signature}`), not a reimplementation.
/// Before this check existed, a `CredentialMessage`'s embedded credentials
/// were stored unconditionally, so a forwarded or forged credential (signed
/// by someone other than the party it claims to be from) was accepted just
/// as readily as a genuine one.
///
/// A non-JWT-format container (`format` not containing `"jwt"`, e.g. a
/// JSON-LD credential) is left opaque and unverified here, matching
/// `identity_hub_graph::store`'s own module doc comment on why this store
/// never decodes a non-JWT payload either - out of scope for this
/// bootstrap, not silently assumed valid by omission.
pub async fn verify_credential_proofs(
    http: &reqwest::Client,
    credentials: &[CredentialContainer],
    insecure_http: bool,
) -> Result<(), ValidationError> {
    for container in credentials {
        if !container.format.to_lowercase().contains("jwt") {
            continue;
        }
        let jws = container.payload.as_str().ok_or_else(|| {
            ValidationError::UnverifiableProof(
                "a jwt-format credential's payload must be a JWS string".to_string(),
            )
        })?;
        let (_, header, payload) =
            dcp_core::decode_jws_unverified(jws).map_err(ValidationError::UnverifiableProof)?;
        let vc_issuer = payload.get("iss").and_then(Value::as_str).ok_or_else(|| {
            ValidationError::UnverifiableProof("credential has no iss claim".to_string())
        })?;
        let kid = header.get("kid").and_then(Value::as_str).ok_or_else(|| {
            ValidationError::UnverifiableProof("credential JWS has no kid header".to_string())
        })?;
        let issuer_doc = dcp_core::resolve_did(http, vc_issuer, insecure_http)
            .await
            .map_err(ValidationError::UnverifiableProof)?;
        let verifying_key = dcp_core::find_verifying_key(&issuer_doc, kid)
            .map_err(ValidationError::UnverifiableProof)?;
        dcp_core::verify_jws_signature(jws, &verifying_key)
            .map_err(ValidationError::UnverifiableProof)?;
    }
    Ok(())
}

/// Validates a `CredentialOfferMessage`'s own `credentials` array: it must
/// be non-empty, and every *sparse* entry (id only, no `credentialType` -
/// `credential.issuance.protocol.md`'s "reference by id" shape) must
/// resolve against the offering issuer's own real Issuer Metadata API
/// catalog (`GET <issuer's IssuerService endpoint>/metadata`). A *full*
/// entry (one that already carries its own `credentialType`) is
/// self-describing and needs no catalog lookup - confirmed, not guessed,
/// by decompiling the real TCK's own `CredentialOfferTest`: its
/// always-passing default offer uses a random, unregistered id but always
/// carries a `credentialType`, while only the id-only "sparse" variants are
/// checked against a catalog - one with the offering issuer's real, known
/// ids (`cs_06_06_01_credentialOfferMessage_sparse`, expects `2xx`), one
/// with random, unregistered ones
/// (`cs_06_06_01_credentialOfferMessage_sparse_randomIds_expect400`,
/// expects `4xx`).
pub async fn validate_offer_credentials(
    http: &reqwest::Client,
    issuer_did: &str,
    credentials: &[CredentialObject],
    insecure_http: bool,
) -> Result<(), ValidationError> {
    if credentials.is_empty() {
        return Err(ValidationError::EmptyCredentials);
    }
    let sparse_ids: Vec<&str> = credentials
        .iter()
        .filter(|c| c.credential_type.is_none())
        .map(|c| c.id.as_str())
        .collect();
    if sparse_ids.is_empty() {
        return Ok(());
    }
    let issuer_doc = dcp_core::resolve_did(http, issuer_did, insecure_http)
        .await
        .map_err(ValidationError::CatalogUnavailable)?;
    let endpoint = dcp_core::service_endpoint_url(&issuer_doc, "IssuerService")
        .map_err(ValidationError::CatalogUnavailable)?;
    let response = http
        .get(format!("{endpoint}/metadata"))
        .send()
        .await
        .map_err(|e| ValidationError::CatalogUnavailable(e.to_string()))?;
    if !response.status().is_success() {
        return Err(ValidationError::CatalogUnavailable(format!(
            "issuer metadata endpoint returned HTTP {}",
            response.status()
        )));
    }
    let metadata: IssuerMetadata = response
        .json()
        .await
        .map_err(|e| ValidationError::CatalogUnavailable(e.to_string()))?;
    let known_ids: HashSet<&str> = metadata
        .credentials_supported
        .iter()
        .flatten()
        .map(|c| c.id.as_str())
        .collect();
    for id in sparse_ids {
        if !known_ids.contains(id) {
            return Err(ValidationError::UnknownCredentialId(id.to_string()));
        }
    }
    Ok(())
}
