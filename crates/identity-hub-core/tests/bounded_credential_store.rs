//! TDD coverage for the 2026-09-20 independent security audit's
//! unbounded-growth finding (MEDIUM), at the layer the Storage API actually
//! calls: [`InMemoryCredentialStore`].
//!
//! `../../identity-hub-graph/tests/bounded_graph_growth.rs` pins the bound
//! where it has to be enforced (the graph's own insert path). This file pins
//! that the bound is *reachable* through the public surface `POST
//! /credentials` goes through - `InMemoryCredentialStore::store` /
//! `::all` / `::credentials_of_types` - rather than only on a graph a caller
//! would have to construct directly. `identity_hub_http::handlers::storage_write`
//! calls exactly these methods, so this is the shape of the actual exposure.
//!
//! The cap is declared locally, matching
//! `../../identity-hub-graph/tests/bounded_graph_growth.rs`'s
//! `MAX_CREDENTIAL_BATCHES`; the fix is expected to introduce
//! `identity_hub_graph::MAX_CREDENTIAL_BATCHES` as the single source of
//! truth and let this store inherit it rather than growing a second cap of
//! its own.

use identity_hub_core::messages::CredentialContainer;
use identity_hub_core::store::{InMemoryCredentialStore, StoredCredentialBatch};

/// Must match `identity-hub-graph`'s own cap for accepted batches - this
/// store adds no ceiling of its own, it inherits that one.
const MAX_CREDENTIAL_BATCHES: usize = 2048;

/// How far past the cap this test pushes.
const OVERSHOOT: usize = 64;

fn container(credential_type: &str) -> CredentialContainer {
    CredentialContainer {
        credential_type: credential_type.to_string(),
        payload: serde_json::json!("fake-jws"),
        format: "jwt".to_string(),
    }
}

fn batch(issuer_pid: &str) -> StoredCredentialBatch {
    StoredCredentialBatch {
        issuer_pid: issuer_pid.to_string(),
        holder_pid: Some("holder-pid-1".to_string()),
        status: "ISSUED".to_string(),
        rejection_reason: None,
        credentials: vec![container("MembershipCredential")],
    }
}

/// One accepted `CredentialMessage` per `store()` call, kept forever: the
/// Storage API's backing store has no ceiling, so a counterparty that is
/// allowed to write at all is allowed to write without limit.
///
/// Red at the time of writing: the store reports all
/// `MAX_CREDENTIAL_BATCHES + OVERSHOOT` batches.
#[test]
fn credential_store_does_not_grow_without_bound() {
    let store = InMemoryCredentialStore::new();
    for i in 0..(MAX_CREDENTIAL_BATCHES + OVERSHOOT) {
        store.store(batch(&format!("issuer-pid-{i}")));
    }

    let stored = store.all();
    assert!(
        stored.len() <= MAX_CREDENTIAL_BATCHES,
        "the Storage API's backing store must be bounded: after {} accepted CredentialMessages \
         it holds {}, every one ever written (2026-09-20 independent security audit, MEDIUM)",
        MAX_CREDENTIAL_BATCHES + OVERSHOOT,
        stored.len()
    );

    // The guard: whatever is dropped, it is the oldest - the newest write is
    // still there, and still answers the Presentation API's own lookup.
    let newest = format!("issuer-pid-{}", MAX_CREDENTIAL_BATCHES + OVERSHOOT - 1);
    assert!(
        stored.iter().any(|b| b.issuer_pid == newest),
        "the most recently accepted batch must survive whatever bounds the store"
    );
    assert!(
        !store
            .credentials_of_types(&["MembershipCredential".to_string()])
            .is_empty(),
        "the credentials that are still stored must still be findable by type"
    );
}

/// The low-volume guard: at the scale a real exchange (and the real TCK's
/// own Credential-Service setup phase) works at, nothing is evicted and
/// every stored batch still round-trips. Green before and after.
#[test]
fn low_volume_writes_are_all_retained() {
    let store = InMemoryCredentialStore::new();
    for i in 0..16 {
        store.store(batch(&format!("issuer-pid-{i}")));
    }

    let stored = store.all();
    assert_eq!(
        stored.len(),
        16,
        "nothing may be evicted at ordinary volumes"
    );
    assert_eq!(
        stored.first().map(|b| b.issuer_pid.as_str()),
        Some("issuer-pid-0"),
        "the oldest batch of a normal-sized run must still be there, still first"
    );
    assert_eq!(
        store
            .credentials_of_types(&["MembershipCredential".to_string()])
            .len(),
        16
    );
}
