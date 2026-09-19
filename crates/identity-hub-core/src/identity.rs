//! A `did:web`-hosted service identity: a P-256 key pair (via
//! `dcp_core::DcpKeyPair`) plus the machinery to build a DID document that
//! actually satisfies the Decentralized Claims Protocol's own validation
//! rules, not just `dcp_core::DcpKeyPair::did_document`'s bare shape.
//!
//! ## Why this doesn't just call `DcpKeyPair::did_document`
//!
//! `dcp_core::DcpKeyPair::did_document` (extracted from `ds-catalog-broker-rs`,
//! whose own DCP usage never needed this) emits a `verificationMethod` entry
//! with no `authentication`/`assertionMethod`/`capabilityInvocation`
//! verification-relationship arrays. The real DCP spec requires them:
//! `base.protocol.md` ("Validating Self-Issued ID Tokens", step 3) requires
//! the signing key to carry `capabilityInvocation`, and
//! `verifiable.presentation.protocol.md` ("Presentation Validation", step 3)
//! requires a Verifiable Presentation's signing key to carry
//! `authentication`. The real, official `dcp-tck` enforces this directly
//! (see `TestFixtures.assertVerificationRelationship` in
//! `eclipse-dataspacetck/dcp-tck`) - a DID document missing these arrays
//! fails presentation-flow tests even when every signature is otherwise
//! valid. `did_document` below builds the full shape by hand instead.

use dcp_core::DcpKeyPair;
use serde_json::{Value, json};

/// `@context` entries a DID document needs: the plain DID Core context plus
/// the DCP JSON-LD context (the same combination the spec's own examples
/// use for a document carrying a `CredentialService`/`IssuerService` entry).
const DID_CONTEXT: &[&str] = &[
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/dspace-dcp/v1.0/dcp.jsonld",
];

/// A single `did:web`-hosted identity this process controls: it can sign as
/// this DID, and it serves this DID's own document (see
/// `identity-hub-http`'s `did_document` route) so any resolver - including
/// this same process, for a synthetic counterparty identity - can fetch it.
#[derive(Debug, Clone)]
pub struct ServiceIdentity {
    pub key_pair: DcpKeyPair,
    /// The path segment(s) this identity's DID document is served under,
    /// e.g. `"credential-service"` for `did:web:<host>:credential-service`,
    /// resolved (per the did:web method) at `GET /credential-service/did.json`.
    pub did_path_segment: String,
}

impl ServiceIdentity {
    /// Builds a fresh identity: `did:web:<did_host, ':' percent-encoded>:<did_path_segment>`,
    /// with a freshly generated P-256 key pair. Like `HolderIdentity` in
    /// `ds-dcp-core-rs`, the key is never persisted - this is a self-hosted
    /// `did:web` identity, so whichever key is running when a document is
    /// resolved is, by construction, correct (see that crate's own doc
    /// comment on `HolderIdentity` for the full argument).
    pub fn new(did_host: &str, did_path_segment: impl Into<String>) -> Self {
        let did_path_segment = did_path_segment.into();
        let own_did = format!(
            "did:web:{}:{did_path_segment}",
            did_host.replace(':', "%3A")
        );
        Self {
            key_pair: DcpKeyPair::generate(own_did),
            did_path_segment,
        }
    }

    pub fn own_did(&self) -> &str {
        &self.key_pair.own_did
    }

    pub fn own_key_id(&self) -> &str {
        &self.key_pair.own_key_id
    }

    /// Builds this identity's DID document, including the
    /// `authentication`/`assertionMethod`/`capabilityInvocation`
    /// verification-relationship arrays the real DCP spec (and the real TCK)
    /// requires - see this module's doc comment. `services` lets a
    /// Credential Service advertise a `CredentialService` entry (and an
    /// Issuer Service an `IssuerService` entry); a synthetic
    /// STS-counterparty identity that nobody ever looks up services on
    /// passes an empty slice.
    pub fn did_document(&self, services: &[(&str, &str)]) -> Value {
        let key_id = self.own_key_id();
        json!({
            "@context": DID_CONTEXT,
            "id": self.own_did(),
            "verificationMethod": [{
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": self.own_did(),
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": dcp_core::b64_encode(self.key_pair.public_key_xy.0),
                    "y": dcp_core::b64_encode(self.key_pair.public_key_xy.1),
                }
            }],
            "authentication": [key_id],
            "assertionMethod": [key_id],
            "capabilityInvocation": [key_id],
            "service": services.iter().map(|(ty, endpoint)| json!({
                "id": format!("{}#{ty}", self.own_did()),
                "type": ty,
                "serviceEndpoint": endpoint,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_document_carries_verification_relationships() {
        let identity = ServiceIdentity::new("localhost:9999", "credential-service");
        let doc = identity.did_document(&[("CredentialService", "http://localhost:9999")]);
        let key_id = identity.own_key_id();
        assert_eq!(doc["authentication"], json!([key_id]));
        assert_eq!(doc["assertionMethod"], json!([key_id]));
        assert_eq!(doc["capabilityInvocation"], json!([key_id]));
        assert_eq!(doc["service"][0]["type"], json!("CredentialService"));
        assert_eq!(
            doc["service"][0]["serviceEndpoint"],
            json!("http://localhost:9999")
        );
    }
}
