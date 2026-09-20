//! Implements Contreforts' [`ContrefortsConnector`] trait for
//! `identity-hub-graph`'s credential graph, so this project's stored
//! credentials and accepted credential offers are reachable through
//! Contreforts' own connector interface - the semantic-configuration layer
//! this project was asked to use, wired to a graph the project owns itself
//! (see `../../ARCHITECTURE.md`, "Provenance: Contreforts").
//!
//! Contreforts' own domain is business-system sync (ERP, git forges,
//! groupware), not the Dataspace Protocol - its `EntityKind`s, ontology and
//! `pull()`/`since` semantics were designed for that. This connector reuses
//! only the *interface* (the trait, the declaration mechanism), not any of
//! Contreforts' business vocabulary: it mints its own entity kinds
//! ([`STORED_CREDENTIAL_KIND`], [`ACCEPTED_OFFER_KIND`]) and its own
//! namespace in `declaration.ttl`, per the trait's documented extension
//! point (`EntityKind::new`) - exactly the pattern
//! `ds-sql-dps-rs/contreforts-connector` already established for the same
//! reason.

use std::sync::Arc;

use chrono::NaiveDateTime;
use contreforts_core::{ConnectorError, ContrefortsConnector, Document, EntityKind};
use identity_hub_graph::{AcceptedOffer, CredentialBatch, CredentialGraph, CredentialGraphError};

/// An accepted `CredentialMessage` batch (the Storage API's own record).
pub const STORED_CREDENTIAL_KIND: &str = "ds-identity-hub-rs:stored-credential-batch";
/// An accepted `CredentialOfferMessage` (the Credential Offer API's own
/// record).
pub const ACCEPTED_OFFER_KIND: &str = "ds-identity-hub-rs:accepted-offer";

fn to_api_err(e: CredentialGraphError) -> ConnectorError {
    ConnectorError::Api {
        message: e.to_string(),
    }
}

fn batch_document(kind: EntityKind, source: &str, batch: CredentialBatch) -> Document {
    Document {
        name: format!("credential-batch-{}", batch.issuer_pid),
        remote_id: batch.id,
        kind,
        source: source.to_string(),
        modified: None,
        fields: serde_json::json!({
            "issuerPid": batch.issuer_pid,
            "holderPid": batch.holder_pid,
            "status": batch.status,
            "rejectionReason": batch.rejection_reason,
            "credentials": batch.credentials.into_iter().map(|c| serde_json::json!({
                "credentialType": c.credential_type,
                "format": c.format,
                "payload": c.payload,
            })).collect::<Vec<_>>(),
        }),
    }
}

fn offer_document(kind: EntityKind, source: &str, offer: AcceptedOffer) -> Document {
    Document {
        name: format!("credential-offer-{}", offer.issuer),
        remote_id: offer.id,
        kind,
        source: source.to_string(),
        modified: None,
        fields: serde_json::json!({
            "issuer": offer.issuer,
            "credentials": offer.credentials.into_iter().map(|c| serde_json::json!({
                "id": c.id,
                "credentialType": c.credential_type,
            })).collect::<Vec<_>>(),
        }),
    }
}

/// Adapts an `identity_hub_graph::CredentialGraph` to Contreforts' connector
/// interface. Recognises exactly the two entity kinds this project mints
/// ([`STORED_CREDENTIAL_KIND`], [`ACCEPTED_OFFER_KIND`]); any other kind is
/// rejected with [`ConnectorError::UnsupportedKind`], per the trait's own
/// fallback policy (never a silent empty result).
pub struct CredentialGraphConnector {
    graph: Arc<CredentialGraph>,
}

impl CredentialGraphConnector {
    pub fn new(graph: Arc<CredentialGraph>) -> Self {
        Self { graph }
    }
}

#[async_trait::async_trait]
impl ContrefortsConnector for CredentialGraphConnector {
    fn source_name(&self) -> &str {
        "ds-identity-hub-rs"
    }

    fn declaration_ttl(&self) -> &'static str {
        include_str!("declaration.ttl")
    }

    async fn pull(
        &self,
        kind: EntityKind,
        _since: Option<NaiveDateTime>,
    ) -> Result<Vec<Document>, ConnectorError> {
        match kind.as_str() {
            STORED_CREDENTIAL_KIND => {
                let batches = self.graph.batches().map_err(to_api_err)?;
                Ok(batches
                    .into_iter()
                    .map(|b| batch_document(kind.clone(), self.source_name(), b))
                    .collect())
            }
            ACCEPTED_OFFER_KIND => {
                let offers = self.graph.offers().map_err(to_api_err)?;
                Ok(offers
                    .into_iter()
                    .map(|o| offer_document(kind.clone(), self.source_name(), o))
                    .collect())
            }
            other => Err(ConnectorError::UnsupportedKind {
                connector: self.source_name().to_string(),
                kind: other.to_string(),
            }),
        }
    }

    async fn get(&self, kind: EntityKind, remote_id: &str) -> Result<Document, ConnectorError> {
        match kind.as_str() {
            STORED_CREDENTIAL_KIND => {
                let batch = self
                    .graph
                    .batch(remote_id)
                    .map_err(to_api_err)?
                    .ok_or_else(|| ConnectorError::NotFound {
                        kind: kind.as_str().to_string(),
                        id: remote_id.to_string(),
                    })?;
                Ok(batch_document(kind, self.source_name(), batch))
            }
            ACCEPTED_OFFER_KIND => {
                let offer = self
                    .graph
                    .offer(remote_id)
                    .map_err(to_api_err)?
                    .ok_or_else(|| ConnectorError::NotFound {
                        kind: kind.as_str().to_string(),
                        id: remote_id.to_string(),
                    })?;
                Ok(offer_document(kind, self.source_name(), offer))
            }
            other => Err(ConnectorError::UnsupportedKind {
                connector: self.source_name().to_string(),
                kind: other.to_string(),
            }),
        }
    }

    async fn push(&self, doc: &Document) -> Result<Document, ConnectorError> {
        Err(ConnectorError::Unsupported {
            connector: self.source_name().to_string(),
            operation: format!("push (kind: {})", doc.kind),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_hub_graph::{
        CredentialEntry, NewAcceptedOffer, NewCredentialBatch, OfferedCredential,
    };

    fn graph_with_one_batch_and_one_offer() -> Arc<CredentialGraph> {
        let graph = CredentialGraph::open_in_memory().expect("open store");
        graph
            .add_batch(NewCredentialBatch {
                issuer_pid: "issuer-1".to_string(),
                holder_pid: Some("holder-1".to_string()),
                status: "ISSUED".to_string(),
                rejection_reason: None,
                credentials: vec![CredentialEntry {
                    credential_type: "MembershipCredential".to_string(),
                    payload: serde_json::json!("fake-jws"),
                    format: "jwt".to_string(),
                }],
            })
            .expect("add_batch");
        graph
            .add_offer(NewAcceptedOffer {
                issuer: "did:web:issuer.example".to_string(),
                credentials: vec![OfferedCredential {
                    id: "membership-credential".to_string(),
                    credential_type: Some("MembershipCredential".to_string()),
                }],
            })
            .expect("add_offer");
        Arc::new(graph)
    }

    #[tokio::test]
    async fn pull_returns_stored_batches_for_its_own_kind() {
        let connector = CredentialGraphConnector::new(graph_with_one_batch_and_one_offer());
        let docs = connector
            .pull(EntityKind::new(STORED_CREDENTIAL_KIND), None)
            .await
            .expect("pull");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].fields["issuerPid"], "issuer-1");
        assert_eq!(
            docs[0].fields["credentials"][0]["credentialType"],
            "MembershipCredential"
        );
    }

    #[tokio::test]
    async fn pull_returns_accepted_offers_for_its_own_kind() {
        let connector = CredentialGraphConnector::new(graph_with_one_batch_and_one_offer());
        let docs = connector
            .pull(EntityKind::new(ACCEPTED_OFFER_KIND), None)
            .await
            .expect("pull");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].fields["issuer"], "did:web:issuer.example");
    }

    #[tokio::test]
    async fn get_fetches_a_single_batch_by_remote_id() {
        let graph = graph_with_one_batch_and_one_offer();
        let batch_id = graph.batches().expect("batches")[0].id.clone();
        let connector = CredentialGraphConnector::new(graph);

        let doc = connector
            .get(EntityKind::new(STORED_CREDENTIAL_KIND), &batch_id)
            .await
            .expect("get");
        assert_eq!(doc.remote_id, batch_id);
        assert_eq!(doc.fields["status"], "ISSUED");
    }

    #[tokio::test]
    async fn get_errors_not_found_for_an_unknown_remote_id() {
        let connector = CredentialGraphConnector::new(graph_with_one_batch_and_one_offer());
        let err = connector
            .get(EntityKind::new(STORED_CREDENTIAL_KIND), "no-such-id")
            .await
            .expect_err("unknown remote_id must error");
        assert!(matches!(err, ConnectorError::NotFound { .. }));
    }

    #[tokio::test]
    async fn unsupported_kind_errors_naming_kind_and_connector() {
        let connector = CredentialGraphConnector::new(graph_with_one_batch_and_one_offer());

        let err = connector
            .pull(EntityKind::new("customer"), None)
            .await
            .expect_err("a kind this connector does not handle must error");

        match err {
            ConnectorError::UnsupportedKind { connector, kind } => {
                assert_eq!(connector, "ds-identity-hub-rs");
                assert_eq!(kind, "customer");
            }
            other => panic!("expected UnsupportedKind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn push_is_unsupported() {
        let connector = CredentialGraphConnector::new(graph_with_one_batch_and_one_offer());
        let doc = Document {
            name: "n".to_string(),
            remote_id: "r".to_string(),
            kind: EntityKind::new(STORED_CREDENTIAL_KIND),
            source: "s".to_string(),
            modified: None,
            fields: serde_json::json!({}),
        };
        let err = connector
            .push(&doc)
            .await
            .expect_err("push must be unsupported");
        assert!(matches!(err, ConnectorError::Unsupported { .. }));
    }
}
