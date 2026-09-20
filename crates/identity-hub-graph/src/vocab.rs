//! RDF namespace IRIs used to describe an accepted credential batch and an
//! accepted credential offer: the real W3C Verifiable Credentials Data
//! Model vocabulary where it genuinely fits, plus this project's own small
//! vocabulary for everything that is a DCP wire-message field with no
//! existing term (`issuerPid`/`holderPid`/`status`/`rejectionReason` and
//! the rest of `CredentialMessage`/`CredentialOfferMessage`'s own
//! correlation/status shape - see `../../../ARCHITECTURE.md`, "Provenance:
//! Contreforts", for the full reasoning behind each choice).
//!
//! `ds:order` exists for the same reason `ds-sql-dps-rs/config-graph`'s own
//! `ds:order` does: a batch's `credentials` array (and an offer's
//! `credentials` array) is an *ordered* JSON array, but plain RDF triples
//! for a multi-valued blank-node property carry no order at all - see
//! `store.rs`'s module doc for the read-back side of this.

pub const VC: &str = "https://www.w3.org/2018/credentials#";
pub const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
pub const XSD: &str = "http://www.w3.org/2001/XMLSchema#";

/// This project's own tiny vocabulary: DCP wire-message fields
/// (`credential.issuance.protocol.md`'s `CredentialMessage`/
/// `CredentialOfferMessage`) that have no W3C Verifiable Credentials term,
/// plus `order`.
pub const DS: &str = "https://ds42.org/ontologies/ds-identity-hub-rs#";

pub fn vc(term: &str) -> String {
    format!("{VC}{term}")
}

pub fn rdf(term: &str) -> String {
    format!("{RDF}{term}")
}

pub fn xsd(term: &str) -> String {
    format!("{XSD}{term}")
}

pub fn ds(term: &str) -> String {
    format!("{DS}{term}")
}
