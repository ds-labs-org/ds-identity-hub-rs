//! A Contreforts-backed semantic store of credentials accepted through the
//! Storage API (`POST /credentials` on a Credential Service). Public
//! surface (`new`/`store`/`all`/`credentials_of_types`, and
//! `StoredCredentialBatch`'s own fields) is unchanged from this crate's
//! original bare `Mutex<Vec<StoredCredentialBatch>>` - every existing call
//! site in `identity-hub-http` compiles and behaves exactly as before.
//! What changed is what backs it: `InMemoryCredentialStore` now wraps a
//! real, SPARQL-addressable RDF graph
//! ([`identity_hub_graph::CredentialGraph`]) instead of a bare `Vec`, so a
//! stored credential is a real triple, reachable through Contreforts'
//! connector interface (`identity-hub-contreforts`) - see
//! `../../ARCHITECTURE.md`, "Provenance: Contreforts". Still process-lifetime
//! only, by deliberate MVP choice: see `../../ARCHITECTURE.md`, "No durable
//! storage" for why that call is repeated here rather than reconsidered.

use std::sync::Arc;

use identity_hub_graph::{CredentialEntry, CredentialGraph, NewCredentialBatch};

use crate::messages::CredentialContainer;

/// One accepted `CredentialMessage`, kept in full (not decomposed at this
/// layer - decomposition into RDF happens one level down, in
/// [`identity_hub_graph::CredentialGraph::add_batch`]) so the Storage API's
/// own correlation fields (`issuerPid`/`holderPid`) survive for the
/// Presentation API and any future inspection to use.
#[derive(Debug, Clone)]
pub struct StoredCredentialBatch {
    pub issuer_pid: String,
    pub holder_pid: Option<String>,
    pub status: String,
    pub rejection_reason: Option<String>,
    pub credentials: Vec<CredentialContainer>,
}

fn to_graph_entry(container: CredentialContainer) -> CredentialEntry {
    CredentialEntry {
        credential_type: container.credential_type,
        payload: container.payload,
        format: container.format,
    }
}

fn from_graph_entry(entry: CredentialEntry) -> CredentialContainer {
    CredentialContainer {
        credential_type: entry.credential_type,
        payload: entry.payload,
        format: entry.format,
    }
}

/// Append-only, process-lifetime credential store, real RDF-graph-backed
/// acceptance (not a stub): every `CredentialMessage` the Storage API route
/// receives is decomposed into triples and inserted unconditionally, which
/// is what lets the TCK's own `dataspacetck.credentials.correlation.id`
/// pre-load step succeed - see `../../ARCHITECTURE.md`, "What's
/// implemented".
pub struct InMemoryCredentialStore {
    graph: Arc<CredentialGraph>,
}

impl Default for InMemoryCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCredentialStore {
    pub fn new() -> Self {
        Self {
            graph: Arc::new(CredentialGraph::open_in_memory().expect("in-memory RDF store opens")),
        }
    }

    pub fn store(&self, batch: StoredCredentialBatch) {
        self.graph
            .add_batch(NewCredentialBatch {
                issuer_pid: batch.issuer_pid,
                holder_pid: batch.holder_pid,
                status: batch.status,
                rejection_reason: batch.rejection_reason,
                credentials: batch.credentials.into_iter().map(to_graph_entry).collect(),
            })
            .expect("credential batch insert into RDF store");
    }

    pub fn all(&self) -> Vec<StoredCredentialBatch> {
        self.graph
            .batches()
            .expect("credential batch query")
            .into_iter()
            .map(|batch| StoredCredentialBatch {
                issuer_pid: batch.issuer_pid,
                holder_pid: batch.holder_pid,
                status: batch.status,
                rejection_reason: batch.rejection_reason,
                credentials: batch
                    .credentials
                    .into_iter()
                    .map(from_graph_entry)
                    .collect(),
            })
            .collect()
    }

    /// All `ISSUED`-status credential containers whose `credentialType`
    /// appears in `types`, across every accepted batch - the Presentation
    /// API's own lookup for a scope-based `PresentationQueryMessage`.
    pub fn credentials_of_types(&self, types: &[String]) -> Vec<CredentialContainer> {
        self.graph
            .credentials_of_types(types)
            .expect("credential type query")
            .into_iter()
            .map(from_graph_entry)
            .collect()
    }

    /// The underlying RDF graph, shared (not copied) - what lets
    /// `identity-hub-contreforts`'s connector be wired to the exact same
    /// graph this store reads and writes, rather than a separate,
    /// out-of-sync instance. See `../../ARCHITECTURE.md`, "Provenance:
    /// Contreforts".
    pub fn graph(&self) -> Arc<CredentialGraph> {
        self.graph.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(credential_type: &str) -> CredentialContainer {
        CredentialContainer {
            credential_type: credential_type.to_string(),
            payload: serde_json::json!("fake-jws"),
            format: "jwt".to_string(),
        }
    }

    #[test]
    fn stores_and_filters_issued_credentials_by_type() {
        let store = InMemoryCredentialStore::new();
        store.store(StoredCredentialBatch {
            issuer_pid: "issuer-1".to_string(),
            holder_pid: Some("holder-1".to_string()),
            status: "ISSUED".to_string(),
            rejection_reason: None,
            credentials: vec![container("MembershipCredential")],
        });
        store.store(StoredCredentialBatch {
            issuer_pid: "issuer-2".to_string(),
            holder_pid: None,
            status: "REJECTED".to_string(),
            rejection_reason: Some("nope".to_string()),
            credentials: vec![container("SensitiveDataCredential")],
        });

        let found = store.credentials_of_types(&["MembershipCredential".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_type, "MembershipCredential");

        // The rejected batch's credential must never surface, even if its
        // type is requested.
        let none = store.credentials_of_types(&["SensitiveDataCredential".to_string()]);
        assert!(none.is_empty());

        assert_eq!(store.all().len(), 2);
    }
}
