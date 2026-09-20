//! TDD coverage for the 2026-09-20 independent security audit's
//! unbounded-growth finding (MEDIUM), credential-graph half: the third of
//! the three attacker-reachable structures that grow for the lifetime of the
//! process with nothing ever removing anything. (The other two,
//! `AppState::seen_jti` and `AppState::requests`, are pinned by
//! `../../identity-hub-http/tests/bounded_state_growth.rs`.)
//!
//! [`CredentialGraph::add_batch`] and [`CredentialGraph::add_offer`] are
//! append-only: every accepted `CredentialMessage` and every accepted
//! `CredentialOfferMessage` is decomposed into roughly a dozen RDF quads and
//! inserted unconditionally, with no cap, no deduplication, and no eviction.
//! Both are driven directly by remote callers - `add_batch` from the Storage
//! API (`POST /credentials`) via
//! `identity_hub_core::store::InMemoryCredentialStore::store`, `add_offer`
//! from the Credential Offer API (`POST /offers`). The Storage API's
//! deny-by-default trusted-issuer posture (the audit's Storage API HIGH,
//! already fixed) narrows *who* can drive them, not *how much*: one
//! configured, genuinely trusted counterparty - or one whose key has been
//! compromised - can still push this process's in-memory Oxigraph store to
//! whatever size it likes, and each batch costs far more than the request
//! that carried it.
//!
//! The tests assert a bound rather than exhausting memory, for the reasons
//! `../../identity-hub-http/tests/bounded_state_growth.rs`'s module doc
//! comment gives. The caps are declared locally here because no such
//! constant exists in this crate yet - the fix is expected to introduce
//! `identity_hub_graph::MAX_CREDENTIAL_BATCHES` and
//! `identity_hub_graph::MAX_ACCEPTED_OFFERS` with these same values (a cap
//! *smaller* than these still satisfies every assertion here; a larger one
//! does not).
//!
//! What must not regress: the store's actual job for current data. Eviction
//! must be oldest-first, so the most recently accepted batch is still
//! readable back through [`CredentialGraph::batch`] and still answers
//! [`CredentialGraph::credentials_of_types`] (the Presentation API's own
//! lookup), and an ordinary-volume run - anything the real
//! `eclipsedataspacetck/dcp-tck-runtime` produces, which is a handful of
//! batches - must never lose anything at all.

use identity_hub_graph::{
    CredentialEntry, CredentialGraph, NewAcceptedOffer, NewCredentialBatch, OfferedCredential,
};

/// The maximum number of accepted credential batches the graph may hold at
/// once. Generous on purpose: orders of magnitude above anything a real DCP
/// exchange (or a full TCK run) puts in it, while still a fixed ceiling a
/// remote caller cannot push past.
const MAX_CREDENTIAL_BATCHES: usize = 2048;

/// The same ceiling for accepted credential offers, which arrive through a
/// different API but land in the same store.
const MAX_ACCEPTED_OFFERS: usize = 2048;

/// How far past each cap these tests push - enough to cross the boundary,
/// not enough to stress anything.
const OVERSHOOT: usize = 64;

fn entry(credential_type: &str) -> CredentialEntry {
    CredentialEntry {
        credential_type: credential_type.to_string(),
        payload: serde_json::json!("fake-jws"),
        format: "jwt".to_string(),
    }
}

fn batch(issuer_pid: &str) -> NewCredentialBatch {
    NewCredentialBatch {
        issuer_pid: issuer_pid.to_string(),
        holder_pid: Some("holder-pid-1".to_string()),
        status: "ISSUED".to_string(),
        rejection_reason: None,
        credentials: vec![entry("MembershipCredential")],
    }
}

fn offer(issuer: &str) -> NewAcceptedOffer {
    NewAcceptedOffer {
        issuer: issuer.to_string(),
        credentials: vec![OfferedCredential {
            id: "membership-credential".to_string(),
            credential_type: Some("MembershipCredential".to_string()),
        }],
    }
}

/// The headline case for the batch store: every accepted `CredentialMessage`
/// stays in the graph forever, so a counterparty that is allowed to write at
/// all is allowed to write without limit.
///
/// Red at the time of writing: the graph holds all
/// `MAX_CREDENTIAL_BATCHES + OVERSHOOT` batches.
///
/// The remaining assertions are the guard the fix has to respect: eviction
/// must take the *oldest* batches, leaving the most recent one both readable
/// by id and visible to the Presentation API's own type lookup.
#[test]
fn credential_batches_do_not_grow_without_bound() {
    let graph = CredentialGraph::open_in_memory().expect("in-memory RDF store opens");

    let mut ids = Vec::new();
    for i in 0..(MAX_CREDENTIAL_BATCHES + OVERSHOOT) {
        ids.push(
            graph
                .add_batch(batch(&format!("issuer-pid-{i}")))
                .expect("credential batch insert into RDF store"),
        );
    }

    let stored = graph.batches().expect("credential batch query");
    assert!(
        stored.len() <= MAX_CREDENTIAL_BATCHES,
        "the credential graph must be bounded: after {} accepted batches it holds {}, every one \
         ever written, with nothing evicting them - a caller allowed to write at all can grow \
         this process's memory without limit (2026-09-20 independent security audit, MEDIUM)",
        MAX_CREDENTIAL_BATCHES + OVERSHOOT,
        stored.len()
    );

    let newest = ids.last().expect("at least one batch was written");
    assert!(
        graph
            .batch(newest)
            .expect("credential batch lookup")
            .is_some(),
        "the most recently accepted batch must survive whatever bounds the store - eviction is \
         oldest-first, not newest-first and not a wholesale clear"
    );
    assert!(
        !graph
            .credentials_of_types(&["MembershipCredential".to_string()])
            .expect("credential type query")
            .is_empty(),
        "the Presentation API's own lookup must still find the credentials that are still stored"
    );
    let oldest_kept = format!(
        "issuer-pid-{}",
        MAX_CREDENTIAL_BATCHES + OVERSHOOT - stored.len()
    );
    assert_eq!(
        stored.first().map(|b| b.issuer_pid.clone()),
        Some(oldest_kept),
        "what is kept must be the newest contiguous run of batches, in insertion order - the \
         entries that went away must be the oldest ones"
    );
}

/// The same for accepted credential offers, which reach the identical store
/// through a different API (`POST /offers`) and are equally unbounded today.
///
/// Red at the time of writing: the graph holds all
/// `MAX_ACCEPTED_OFFERS + OVERSHOOT` offers.
#[test]
fn accepted_offers_do_not_grow_without_bound() {
    let graph = CredentialGraph::open_in_memory().expect("in-memory RDF store opens");

    let mut ids = Vec::new();
    for i in 0..(MAX_ACCEPTED_OFFERS + OVERSHOOT) {
        ids.push(
            graph
                .add_offer(offer(&format!("did:web:issuer-{i}")))
                .expect("accepted-offer insert into RDF store"),
        );
    }

    let stored = graph.offers().expect("accepted-offer query");
    assert!(
        stored.len() <= MAX_ACCEPTED_OFFERS,
        "accepted credential offers must be bounded: after {} offers the graph holds {}, every \
         one ever received (2026-09-20 independent security audit, MEDIUM)",
        MAX_ACCEPTED_OFFERS + OVERSHOOT,
        stored.len()
    );

    let newest = ids.last().expect("at least one offer was written");
    assert!(
        graph
            .offer(newest)
            .expect("accepted-offer lookup")
            .is_some(),
        "the most recently accepted offer must survive whatever bounds the store"
    );
}

/// The low-volume guard, mirroring
/// `../../identity-hub-http/tests/bounded_state_growth.rs`'s: at the scale a
/// real DCP exchange (and the real TCK) actually works at, nothing is
/// evicted, nothing is reordered, and every field still round-trips. Green
/// before and after - this is what makes the cap a safety valve rather than
/// a behaviour change.
#[test]
fn low_volume_batches_and_offers_are_all_retained() {
    let graph = CredentialGraph::open_in_memory().expect("in-memory RDF store opens");

    let mut batch_ids = Vec::new();
    let mut offer_ids = Vec::new();
    for i in 0..16 {
        batch_ids.push(
            graph
                .add_batch(batch(&format!("issuer-pid-{i}")))
                .expect("credential batch insert into RDF store"),
        );
        offer_ids.push(
            graph
                .add_offer(offer(&format!("did:web:issuer-{i}")))
                .expect("accepted-offer insert into RDF store"),
        );
    }

    let stored = graph.batches().expect("credential batch query");
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
    assert_eq!(graph.offers().expect("accepted-offer query").len(), 16);
    for id in &batch_ids {
        assert!(
            graph.batch(id).expect("credential batch lookup").is_some(),
            "every batch of a normal-sized run stays individually addressable ({id})"
        );
    }
    for id in &offer_ids {
        assert!(
            graph.offer(id).expect("accepted-offer lookup").is_some(),
            "every offer of a normal-sized run stays individually addressable ({id})"
        );
    }
}
