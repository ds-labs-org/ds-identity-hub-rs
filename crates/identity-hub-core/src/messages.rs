//! DCP wire-message shapes for the Verifiable Presentation Protocol (VPP)
//! and Credential Issuance Protocol (CIP) that `ds-dcp-core-rs` doesn't
//! carry - it only ships `PresentationQueryMessage` (serialize-only, used by
//! a client) and a minimal `PresentationResponseMessage`. This service is
//! the *receiving* end of a `PresentationQueryMessage` (needs
//! `Deserialize`), the DCP-spec-required `@context`/`type` envelope fields
//! `ds-dcp-core-rs`'s own `PresentationResponseMessage` omits, and the whole
//! Storage API / Credential Offer API / Credential Request API / Issuer
//! Metadata API message vocabulary CIP defines - so it's defined here
//! instead, field-for-field against
//! `specifications/verifiable.presentation.protocol.md` and
//! `specifications/credential.issuance.protocol.md` in
//! <https://github.com/eclipse-dataspace-dcp/decentralized-claims-protocol>
//! (JSON key spelling cross-checked against that repo's own
//! `artifacts/src/main/resources/{presentation,issuance}/example/*.json`,
//! not guessed).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The DCP JSON-LD `@context` URI (`base.protocol.md`, "The Decentralized
/// Claims Protocol Context").
pub const DCP_CONTEXT: &str = "https://w3id.org/dspace-dcp/v1.0/dcp.jsonld";
/// `@context` for a W3C Verifiable Presentation/Credential, as embedded in
/// the `vp`/`vc` claim of a signed JWS (see `build_presentation`/the
/// Verifiable Presentation Protocol's presentation validation rules).
pub const VC_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

fn dcp_context() -> Vec<String> {
    vec![DCP_CONTEXT.to_string()]
}

// ---- Verifiable Presentation Protocol (Resolution API) ----

/// `POST /presentations/query` request body. See
/// `verifiable.presentation.protocol.md#presentation-query-message`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationQueryMessage {
    #[serde(rename = "@context", default = "dcp_context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub presentation_definition: Option<Value>,
}

/// `POST /presentations/query` response body. See
/// `verifiable.presentation.protocol.md#presentation-response-message`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationResponseMessage {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub message_type: String,
    pub presentation: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<Value>,
}

impl PresentationResponseMessage {
    pub fn new(presentation: Vec<String>) -> Self {
        Self {
            context: dcp_context(),
            message_type: "PresentationResponseMessage".to_string(),
            presentation,
            presentation_submission: None,
        }
    }
}

// ---- Credential Issuance Protocol: Storage API ----

/// One entry of a [`CredentialMessage`]'s `credentials` array. See
/// `credential.issuance.protocol.md#credential-container`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialContainer {
    pub credential_type: String,
    pub payload: Value,
    pub format: String,
}

/// `POST /credentials` request body on the Storage API (Issuer Service ->
/// Credential Service). See
/// `credential.issuance.protocol.md#credential-message`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMessage {
    #[serde(rename = "@context", default = "dcp_context")]
    pub context: Vec<String>,
    #[serde(rename = "type", default = "credential_message_type")]
    pub message_type: String,
    pub issuer_pid: String,
    #[serde(default)]
    pub holder_pid: Option<String>,
    pub status: String,
    #[serde(default)]
    pub credentials: Vec<CredentialContainer>,
    #[serde(default)]
    pub rejection_reason: Option<String>,
}

fn credential_message_type() -> String {
    "CredentialMessage".to_string()
}

// ---- Credential Issuance Protocol: Credential Request API ----

/// A reference into the Issuer's `credentialsSupported` list, by id. See
/// `credential.issuance.protocol.md#credential-request-message`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CredentialRef {
    pub id: String,
}

/// `POST /credentials` request body on the Credential Request API (a
/// potential Holder -> Issuer Service).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequestMessage {
    #[serde(rename = "@context", default = "dcp_context")]
    pub context: Vec<String>,
    #[serde(rename = "type", default = "credential_request_message_type")]
    pub message_type: String,
    pub holder_pid: String,
    pub credentials: Vec<CredentialRef>,
}

fn credential_request_message_type() -> String {
    "CredentialRequestMessage".to_string()
}

/// `GET /requests/<id>` response body. See
/// `credential.issuance.protocol.md#credentialstatus`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    #[serde(rename = "@context", default = "dcp_context")]
    pub context: Vec<String>,
    #[serde(rename = "type", default = "credential_status_type")]
    pub message_type: String,
    pub issuer_pid: String,
    pub holder_pid: String,
    pub status: String,
}

fn credential_status_type() -> String {
    "CredentialStatus".to_string()
}

impl CredentialStatus {
    pub fn new(issuer_pid: impl Into<String>, holder_pid: impl Into<String>, status: &str) -> Self {
        Self {
            context: dcp_context(),
            message_type: credential_status_type(),
            issuer_pid: issuer_pid.into(),
            holder_pid: holder_pid.into(),
            status: status.to_string(),
        }
    }
}

// ---- Credential Issuance Protocol: Credential Offer API / Issuer Metadata ----

/// See `credential.issuance.protocol.md#credentialobject`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialObject {
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,
    pub id: String,
    #[serde(rename = "type", default = "credential_object_type")]
    pub object_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_policy: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_reason: Option<String>,
}

fn credential_object_type() -> String {
    "CredentialObject".to_string()
}

/// `POST /offers` request body (Credential Issuer -> Credential Service).
/// See `credential.issuance.protocol.md#credential-offer-message`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOfferMessage {
    #[serde(rename = "@context", default = "dcp_context")]
    pub context: Vec<String>,
    #[serde(rename = "type", default = "credential_offer_message_type")]
    pub message_type: String,
    pub issuer: String,
    pub credentials: Vec<CredentialObject>,
}

fn credential_offer_message_type() -> String {
    "CredentialOfferMessage".to_string()
}

/// `GET /metadata` response body. See
/// `credential.issuance.protocol.md#issuermetadata`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerMetadata {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub message_type: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_supported: Option<Vec<CredentialObject>>,
}

impl IssuerMetadata {
    pub fn new(issuer: impl Into<String>, credentials_supported: Vec<CredentialObject>) -> Self {
        Self {
            context: dcp_context(),
            message_type: "IssuerMetadata".to_string(),
            issuer: issuer.into(),
            credentials_supported: Some(credentials_supported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_query_message_deserializes_the_spec_example() {
        let json = r#"{
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "PresentationQueryMessage",
            "scope": ["presentation1", "presentation2"]
        }"#;
        let msg: PresentationQueryMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "PresentationQueryMessage");
        assert_eq!(msg.scope, vec!["presentation1", "presentation2"]);
        assert!(msg.presentation_definition.is_none());
    }

    #[test]
    fn presentation_response_message_serializes_the_spec_shape() {
        let msg = PresentationResponseMessage::new(vec!["vp-jwt".to_string()]);
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["@context"], serde_json::json!([DCP_CONTEXT]));
        assert_eq!(
            value["type"],
            serde_json::json!("PresentationResponseMessage")
        );
        assert_eq!(value["presentation"], serde_json::json!(["vp-jwt"]));
        assert!(value.get("presentationSubmission").is_none());
    }

    #[test]
    fn credential_message_deserializes_the_spec_example() {
        let json = r#"{
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "CredentialMessage",
            "credentials": [
                {"credentialType": "MembershipCredential", "payload": "<JWT-STRING>", "format": "jwt"}
            ],
            "issuerPid": "issuerPid",
            "holderPid": "holderPid",
            "status": "ISSUED"
        }"#;
        let msg: CredentialMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.issuer_pid, "issuerPid");
        assert_eq!(msg.holder_pid.as_deref(), Some("holderPid"));
        assert_eq!(msg.status, "ISSUED");
        assert_eq!(msg.credentials[0].credential_type, "MembershipCredential");
    }

    #[test]
    fn credential_request_message_deserializes_the_spec_example() {
        let json = r#"{
            "@context": ["https://w3id.org/dspace-dcp/v1.0/dcp.jsonld"],
            "type": "CredentialRequestMessage",
            "holderPid": "holderPid",
            "credentials": [{"id": "d5c77b0e-7f4e-4fd5-8c5f-28b5fc3f96d1"}]
        }"#;
        let msg: CredentialRequestMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.holder_pid, "holderPid");
        assert_eq!(
            msg.credentials[0].id,
            "d5c77b0e-7f4e-4fd5-8c5f-28b5fc3f96d1"
        );
    }
}
