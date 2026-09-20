//! The credential graph for `ds-identity-hub-rs`: an embedded Oxigraph RDF
//! store for accepted `CredentialMessage` batches (the Storage API's
//! backing store) and accepted `CredentialOfferMessage`s, decomposed into
//! real triples - addressed by IRI/blank node and queried via SPARQL,
//! rather than kept as an opaque `Vec`/`HashMap` - and reachable through
//! Contreforts' connector interface via the sibling `identity-hub-contreforts`
//! crate. See `../../ARCHITECTURE.md`, "Provenance: Contreforts", for the
//! full design rationale and what this is (and deliberately isn't).

mod model;
mod store;
pub mod vocab;

pub use model::{
    AcceptedOffer, CredentialBatch, CredentialEntry, NewAcceptedOffer, NewCredentialBatch,
    OfferedCredential,
};
pub use store::{CredentialGraph, CredentialGraphError};
