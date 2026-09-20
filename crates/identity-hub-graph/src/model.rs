//! Plain Rust domain types for this crate's own store: input to
//! [`crate::CredentialGraph::add_batch`]/[`crate::CredentialGraph::add_offer`],
//! and what [`crate::CredentialGraph::batches`]/[`crate::CredentialGraph::offers`]
//! reconstruct.
//!
//! These are this crate's *own* types, not re-exports of
//! `identity-hub-core::messages`/`identity-hub-core::store` - mirroring
//! `ds-sql-dps-rs/config-graph/src/offer.rs`'s `FileOffer`, which is that
//! crate's own input type rather than something borrowed from `dataplane`.
//! Keeping this crate independent of `identity-hub-core` is what lets
//! `identity-hub-core::store::InMemoryCredentialStore` depend on this crate
//! (to get a real graph backing its own, unchanged public surface) without
//! a dependency cycle.

use serde_json::Value;

/// One `credentials` array entry of an accepted `CredentialMessage` (or a
/// credential this bootstrap's own Issuer Service delivers).
#[derive(Debug, Clone)]
pub struct CredentialEntry {
    pub credential_type: String,
    pub payload: Value,
    pub format: String,
}

/// Input to [`crate::CredentialGraph::add_batch`] - one accepted
/// `CredentialMessage`, before the graph mints an id for it.
#[derive(Debug, Clone)]
pub struct NewCredentialBatch {
    pub issuer_pid: String,
    pub holder_pid: Option<String>,
    pub status: String,
    pub rejection_reason: Option<String>,
    pub credentials: Vec<CredentialEntry>,
}

/// One stored batch, read back from the graph: the same shape as
/// [`NewCredentialBatch`] plus the id [`crate::CredentialGraph::add_batch`]
/// minted for it - used by `identity-hub-contreforts`'s connector as the
/// `remote_id` [`crate::CredentialGraph::batch`] looks entities up by.
#[derive(Debug, Clone)]
pub struct CredentialBatch {
    pub id: String,
    pub issuer_pid: String,
    pub holder_pid: Option<String>,
    pub status: String,
    pub rejection_reason: Option<String>,
    pub credentials: Vec<CredentialEntry>,
}

/// One `CredentialObject` reference inside an accepted
/// `CredentialOfferMessage`.
#[derive(Debug, Clone)]
pub struct OfferedCredential {
    pub id: String,
    pub credential_type: Option<String>,
}

/// Input to [`crate::CredentialGraph::add_offer`].
#[derive(Debug, Clone)]
pub struct NewAcceptedOffer {
    pub issuer: String,
    pub credentials: Vec<OfferedCredential>,
}

/// One accepted offer, read back from the graph.
#[derive(Debug, Clone)]
pub struct AcceptedOffer {
    pub id: String,
    pub issuer: String,
    pub credentials: Vec<OfferedCredential>,
}
