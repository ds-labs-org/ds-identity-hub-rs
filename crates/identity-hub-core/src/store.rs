//! An in-memory store of credentials accepted through the Storage API
//! (`POST /credentials` on a Credential Service). No durability, matching
//! this bootstrap's documented scope (see `../../ARCHITECTURE.md`).

use std::sync::Mutex;

use crate::messages::CredentialContainer;

/// One accepted `CredentialMessage`, kept in full (not decomposed) so the
/// Storage API's own correlation fields (`issuerPid`/`holderPid`) survive
/// for the Presentation API and any future inspection to use.
#[derive(Debug, Clone)]
pub struct StoredCredentialBatch {
    pub issuer_pid: String,
    pub holder_pid: Option<String>,
    pub status: String,
    pub rejection_reason: Option<String>,
    pub credentials: Vec<CredentialContainer>,
}

/// Append-only, process-lifetime credential store. Real acceptance (not a
/// stub): every `CredentialMessage` the Storage API route receives is
/// pushed here unconditionally, which is what lets the TCK's own
/// `dataspacetck.credentials.correlation.id` pre-load step succeed - see
/// `../../ARCHITECTURE.md`, "What's implemented".
#[derive(Default)]
pub struct InMemoryCredentialStore {
    batches: Mutex<Vec<StoredCredentialBatch>>,
}

impl InMemoryCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&self, batch: StoredCredentialBatch) {
        self.batches
            .lock()
            .expect("credential store lock poisoned")
            .push(batch);
    }

    pub fn all(&self) -> Vec<StoredCredentialBatch> {
        self.batches
            .lock()
            .expect("credential store lock poisoned")
            .clone()
    }

    /// All `ISSUED`-status credential containers whose `credentialType`
    /// appears in `types`, across every accepted batch - the Presentation
    /// API's own lookup for a scope-based `PresentationQueryMessage`.
    pub fn credentials_of_types(&self, types: &[String]) -> Vec<CredentialContainer> {
        self.batches
            .lock()
            .expect("credential store lock poisoned")
            .iter()
            .filter(|batch| batch.status == "ISSUED")
            .flat_map(|batch| batch.credentials.iter().cloned())
            .filter(|c| types.iter().any(|t| t == &c.credential_type))
            .collect()
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
