//! The credential graph: an embedded, physically-local Oxigraph store
//! holding one triple per fact about an accepted `CredentialMessage` batch
//! or an accepted `CredentialOfferMessage` - real RDF triples, addressable
//! by IRI and queryable via SPARQL, not a `Vec`/`HashMap` blob. Follows
//! `ds-sql-dps-rs/config-graph/src/store.rs`'s structure closely: the same
//! open-in-memory constructor, the same "decompose into quads on write,
//! joined-and-`ORDER BY`'d SPARQL query grouped in Rust on read" shape for
//! reconstructing an ordered child collection from blank nodes.
//!
//! ## Why almost everything here is a literal, not a minted IRI
//!
//! Unlike `config-graph` (whose `dataset_id` is an operator-configured,
//! trusted string used to build stable IRIs), the type names flowing
//! through this store can be attacker-influenced: `credentials_of_types`'s
//! `types` argument is ultimately derived from a caller-supplied DCP
//! `scope` string via a regex match (see `identity-hub-http`'s
//! `presentation_query`/`ScopeMatcher`). Minting an IRI from an arbitrary,
//! not-fully-trusted string risks both `IriParseError`s on characters that
//! are not valid in an IRI, and, if ever used to build a query string
//! rather than passed through the typed `Literal`/`NamedNode` constructors,
//! injection into the SPARQL text itself. This store sidesteps both:
//! every batch/credential/offer *attribute* (`issuerPid`, `status`,
//! `credentialType`, the JSON payload, ...) is stored and matched as a
//! plain RDF literal via Oxigraph's typed term constructors, never
//! interpolated as a bare string into a query; only the small, fixed set
//! of vocabulary predicates and classes below (all static Rust string
//! constants this crate controls) ever become `NamedNode`s. The one
//! dynamic filter this store's own SPARQL runs (`ds:status "ISSUED"`) uses
//! a fixed, hardcoded literal - never caller input - for exactly this
//! reason; the caller-supplied `types` list is still checked, but in Rust,
//! after the safe part of the query has already run (see
//! `credentials_of_types`'s own doc comment).

use std::sync::atomic::{AtomicU64, Ordering};

use oxigraph::model::{BlankNode, GraphName, Literal, NamedNode, Quad, Term};
use oxigraph::sparql::{QueryResults, QuerySolution, SparqlEvaluator};
use oxigraph::store::Store;
use uuid::Uuid;

use crate::model::{
    AcceptedOffer, CredentialBatch, CredentialEntry, NewAcceptedOffer, NewCredentialBatch,
    OfferedCredential,
};
use crate::vocab::{DS, VC, ds, rdf, vc, xsd};

#[derive(Debug, thiserror::Error)]
pub enum CredentialGraphError {
    #[error("invalid IRI: {0}")]
    Iri(#[from] oxigraph::model::IriParseError),
    #[error("store error: {0}")]
    Storage(#[from] oxigraph::store::StorageError),
    #[error("SPARQL query failed: {0}")]
    Query(#[from] oxigraph::sparql::QueryEvaluationError),
    #[error("SPARQL query failed to parse: {0}")]
    Syntax(#[from] oxigraph::sparql::SparqlSyntaxError),
}

/// The credential graph: an embedded, in-process Oxigraph store. In-memory
/// and process-lifetime only, by the same deliberate MVP call
/// `ds-sql-dps-rs/config-graph`'s own `open_in_memory` doc comment makes -
/// see `../../../ARCHITECTURE.md`, "No durable storage" for why that call
/// is repeated here rather than reconsidered.
pub struct CredentialGraph {
    store: Store,
    /// Monotonically increasing insertion counter, recorded as `ds:order`
    /// on every batch and offer node so [`Self::batches`]/[`Self::offers`]
    /// can reconstruct insertion order via `ORDER BY` - plain RDF triples
    /// carry no order of their own (see the module doc comment).
    next_order: AtomicU64,
}

fn literal_value(term: &Term) -> Option<String> {
    match term {
        Term::Literal(l) => Some(l.value().to_string()),
        Term::NamedNode(n) => Some(n.as_str().to_string()),
        _ => None,
    }
}

/// Reconstructs a [`CredentialEntry`]'s `payload` from its stored literal:
/// the exact inverse of how [`CredentialGraph::add_batch`] serializes it
/// (see that method's own comment) - a JSON string round-trips back to
/// whatever `serde_json::Value` it originally was (a JSON string literal,
/// object, array, ...), and anything that somehow fails to parse as JSON
/// falls back to a plain JSON string of the raw literal rather than
/// panicking or dropping the credential.
fn decode_payload(literal: String) -> serde_json::Value {
    serde_json::from_str(&literal).unwrap_or(serde_json::Value::String(literal))
}

impl CredentialGraph {
    /// Opens a fresh, empty, in-process store.
    pub fn open_in_memory() -> Result<Self, CredentialGraphError> {
        Ok(Self {
            store: Store::new()?,
            next_order: AtomicU64::new(0),
        })
    }

    fn next_order(&self) -> u64 {
        self.next_order.fetch_add(1, Ordering::SeqCst)
    }

    fn select(&self, query: &str) -> Result<Vec<QuerySolution>, CredentialGraphError> {
        let results = SparqlEvaluator::new()
            .parse_query(query)?
            .on_store(&self.store)
            .execute()?;
        let QueryResults::Solutions(solutions) = results else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for solution in solutions {
            out.push(solution?);
        }
        Ok(out)
    }

    /// Decomposes and inserts one accepted `CredentialMessage` into RDF: a
    /// `ds:CredentialBatch` node carrying the DCP-specific correlation and
    /// status fields (`issuerPid`/`holderPid`/`status`/`rejectionReason` -
    /// wire fields of the Credential Issuance Protocol itself, with no
    /// existing Verifiable Credentials term), linked via `ds:hasCredential`
    /// to one `vc:VerifiableCredential` node per stored container - the one
    /// field with a genuine, real-vocabulary home (see
    /// `../../../ARCHITECTURE.md`, "Provenance: Contreforts", for why
    /// `credentialType`/`payload`/`format` still land in `ds:` rather than
    /// forcing a VC term that doesn't actually fit an opaque, unverified
    /// container). A credential's `payload` (an arbitrary
    /// `serde_json::Value` - a JWS string for `format: "jwt"`, a JSON-LD
    /// document for other formats) is stored as the literal JSON
    /// serialization of that value, so it round-trips losslessly regardless
    /// of shape (see [`decode_payload`]). Returns the batch id the graph
    /// minted, usable with [`Self::batch`] and by
    /// `identity-hub-contreforts`'s connector as a `remote_id`.
    pub fn add_batch(&self, batch: NewCredentialBatch) -> Result<String, CredentialGraphError> {
        let id = Uuid::new_v4().to_string();
        let node = BlankNode::default();
        let order = self.next_order();
        let integer = NamedNode::new(xsd("integer"))?;

        let mut quads = vec![
            Quad::new(
                node.clone(),
                NamedNode::new(rdf("type"))?,
                NamedNode::new(ds("CredentialBatch"))?,
                GraphName::DefaultGraph,
            ),
            Quad::new(
                node.clone(),
                NamedNode::new(ds("batchId"))?,
                Literal::new_simple_literal(&id),
                GraphName::DefaultGraph,
            ),
            Quad::new(
                node.clone(),
                NamedNode::new(ds("order"))?,
                Literal::new_typed_literal(order.to_string(), integer.clone()),
                GraphName::DefaultGraph,
            ),
            Quad::new(
                node.clone(),
                NamedNode::new(ds("issuerPid"))?,
                Literal::new_simple_literal(&batch.issuer_pid),
                GraphName::DefaultGraph,
            ),
            Quad::new(
                node.clone(),
                NamedNode::new(ds("status"))?,
                Literal::new_simple_literal(&batch.status),
                GraphName::DefaultGraph,
            ),
        ];
        if let Some(holder_pid) = &batch.holder_pid {
            quads.push(Quad::new(
                node.clone(),
                NamedNode::new(ds("holderPid"))?,
                Literal::new_simple_literal(holder_pid),
                GraphName::DefaultGraph,
            ));
        }
        if let Some(reason) = &batch.rejection_reason {
            quads.push(Quad::new(
                node.clone(),
                NamedNode::new(ds("rejectionReason"))?,
                Literal::new_simple_literal(reason),
                GraphName::DefaultGraph,
            ));
        }

        for (i, entry) in batch.credentials.iter().enumerate() {
            let cred = BlankNode::default();
            quads.push(Quad::new(
                node.clone(),
                NamedNode::new(ds("hasCredential"))?,
                cred.clone(),
                GraphName::DefaultGraph,
            ));
            quads.push(Quad::new(
                cred.clone(),
                NamedNode::new(rdf("type"))?,
                NamedNode::new(vc("VerifiableCredential"))?,
                GraphName::DefaultGraph,
            ));
            quads.push(Quad::new(
                cred.clone(),
                NamedNode::new(ds("order"))?,
                Literal::new_typed_literal(i.to_string(), integer.clone()),
                GraphName::DefaultGraph,
            ));
            quads.push(Quad::new(
                cred.clone(),
                NamedNode::new(ds("credentialType"))?,
                Literal::new_simple_literal(&entry.credential_type),
                GraphName::DefaultGraph,
            ));
            quads.push(Quad::new(
                cred.clone(),
                NamedNode::new(ds("format"))?,
                Literal::new_simple_literal(&entry.format),
                GraphName::DefaultGraph,
            ));
            quads.push(Quad::new(
                cred,
                NamedNode::new(ds("payload"))?,
                Literal::new_simple_literal(entry.payload.to_string()),
                GraphName::DefaultGraph,
            ));
        }

        for quad in &quads {
            self.store.insert(quad)?;
        }
        Ok(id)
    }

    /// All accepted batches, in insertion order - the SPARQL-backed
    /// equivalent of the original `InMemoryCredentialStore::all()`'s
    /// clone-the-`Vec` semantics. One joined, fully `ORDER BY`'d query
    /// rather than a per-batch follow-up query, for the same reason
    /// `config-graph::ConfigGraph::policy_jsonld` uses one: a blank node's
    /// label in SPARQL query *syntax* is scoped to that query and never
    /// re-addresses a stored blank node by identity, so rows are grouped by
    /// `?batch` term-equality across consecutive, already-`ORDER BY`'d rows
    /// in Rust instead.
    pub fn batches(&self) -> Result<Vec<CredentialBatch>, CredentialGraphError> {
        let query = format!(
            r#"PREFIX ds: <{DS}>
               SELECT ?batch ?border ?batchId ?issuerPid ?holderPid ?status ?rejectionReason ?cred ?corder ?type ?format ?payload WHERE {{
                   ?batch ds:order ?border ; ds:batchId ?batchId ; ds:issuerPid ?issuerPid ; ds:status ?status .
                   OPTIONAL {{ ?batch ds:holderPid ?holderPid }}
                   OPTIONAL {{ ?batch ds:rejectionReason ?rejectionReason }}
                   OPTIONAL {{
                       ?batch ds:hasCredential ?cred .
                       ?cred ds:order ?corder ; ds:credentialType ?type ; ds:format ?format ; ds:payload ?payload .
                   }}
               }} ORDER BY ?border ?corder"#
        );

        let mut out: Vec<(Term, CredentialBatch)> = Vec::new();
        for row in self.select(&query)? {
            let Some(batch_term) = row.get("batch").cloned() else {
                continue;
            };
            let entry = match out.last_mut() {
                Some((last, batch)) if *last == batch_term => batch,
                _ => {
                    out.push((
                        batch_term,
                        CredentialBatch {
                            id: row
                                .get("batchId")
                                .and_then(literal_value)
                                .unwrap_or_default(),
                            issuer_pid: row
                                .get("issuerPid")
                                .and_then(literal_value)
                                .unwrap_or_default(),
                            holder_pid: row.get("holderPid").and_then(literal_value),
                            status: row
                                .get("status")
                                .and_then(literal_value)
                                .unwrap_or_default(),
                            rejection_reason: row.get("rejectionReason").and_then(literal_value),
                            credentials: Vec::new(),
                        },
                    ));
                    &mut out.last_mut().expect("just pushed").1
                }
            };
            if let Some(credential_type) = row.get("type").and_then(literal_value) {
                entry.credentials.push(CredentialEntry {
                    credential_type,
                    format: row
                        .get("format")
                        .and_then(literal_value)
                        .unwrap_or_default(),
                    payload: row
                        .get("payload")
                        .and_then(literal_value)
                        .map(decode_payload)
                        .unwrap_or(serde_json::Value::Null),
                });
            }
        }
        Ok(out.into_iter().map(|(_, batch)| batch).collect())
    }

    /// A single batch by the id [`Self::add_batch`] minted for it, or
    /// `None` if no such batch exists - `identity-hub-contreforts`'s
    /// connector's `get()`.
    pub fn batch(&self, id: &str) -> Result<Option<CredentialBatch>, CredentialGraphError> {
        Ok(self.batches()?.into_iter().find(|b| b.id == id))
    }

    /// All `ISSUED`-status credential containers whose `credentialType`
    /// appears in `types`, across every accepted batch - the SPARQL-backed
    /// equivalent of the original `InMemoryCredentialStore::credentials_of_types`.
    ///
    /// The `ds:status "ISSUED"` filter runs inside SPARQL, against a fixed,
    /// hardcoded literal never influenced by caller input. The `types`
    /// narrowing still runs in Rust afterwards, exactly as the original
    /// in-memory implementation did - see the module doc comment for why
    /// building a dynamic `FILTER ... IN (...)` clause from `types` itself
    /// (which can be derived from a caller-supplied DCP `scope` string) is
    /// deliberately avoided here.
    pub fn credentials_of_types(
        &self,
        types: &[String],
    ) -> Result<Vec<CredentialEntry>, CredentialGraphError> {
        let query = format!(
            r#"PREFIX ds: <{DS}>
               SELECT ?type ?format ?payload WHERE {{
                   ?batch ds:status "ISSUED" ; ds:hasCredential ?cred .
                   ?cred ds:credentialType ?type ; ds:format ?format ; ds:payload ?payload .
               }}"#
        );
        let mut out = Vec::new();
        for row in self.select(&query)? {
            let Some(credential_type) = row.get("type").and_then(literal_value) else {
                continue;
            };
            if !types.iter().any(|t| t == &credential_type) {
                continue;
            }
            out.push(CredentialEntry {
                credential_type,
                format: row
                    .get("format")
                    .and_then(literal_value)
                    .unwrap_or_default(),
                payload: row
                    .get("payload")
                    .and_then(literal_value)
                    .map(decode_payload)
                    .unwrap_or(serde_json::Value::Null),
            });
        }
        Ok(out)
    }

    // ---- Accepted Credential Offers ----

    /// Decomposes and inserts one accepted `CredentialOfferMessage` into
    /// RDF: a `ds:AcceptedCredentialOffer` node carrying the offering
    /// party (`vc:issuer` - a real Verifiable Credentials term that
    /// genuinely fits here, unlike the container-level fields `add_batch`
    /// keeps in `ds:`) and, per offered `CredentialObject`, a small node
    /// recording its catalog id and (when present) credential type.
    pub fn add_offer(&self, offer: NewAcceptedOffer) -> Result<String, CredentialGraphError> {
        let id = Uuid::new_v4().to_string();
        let node = BlankNode::default();
        let order = self.next_order();
        let integer = NamedNode::new(xsd("integer"))?;

        let mut quads = vec![
            Quad::new(
                node.clone(),
                NamedNode::new(rdf("type"))?,
                NamedNode::new(ds("AcceptedCredentialOffer"))?,
                GraphName::DefaultGraph,
            ),
            Quad::new(
                node.clone(),
                NamedNode::new(ds("offerId"))?,
                Literal::new_simple_literal(&id),
                GraphName::DefaultGraph,
            ),
            Quad::new(
                node.clone(),
                NamedNode::new(ds("order"))?,
                Literal::new_typed_literal(order.to_string(), integer.clone()),
                GraphName::DefaultGraph,
            ),
            Quad::new(
                node.clone(),
                NamedNode::new(vc("issuer"))?,
                Literal::new_simple_literal(&offer.issuer),
                GraphName::DefaultGraph,
            ),
        ];
        for (i, credential) in offer.credentials.iter().enumerate() {
            let oc = BlankNode::default();
            quads.push(Quad::new(
                node.clone(),
                NamedNode::new(ds("offersCredential"))?,
                oc.clone(),
                GraphName::DefaultGraph,
            ));
            quads.push(Quad::new(
                oc.clone(),
                NamedNode::new(ds("order"))?,
                Literal::new_typed_literal(i.to_string(), integer.clone()),
                GraphName::DefaultGraph,
            ));
            quads.push(Quad::new(
                oc.clone(),
                NamedNode::new(ds("credentialId"))?,
                Literal::new_simple_literal(&credential.id),
                GraphName::DefaultGraph,
            ));
            if let Some(credential_type) = &credential.credential_type {
                quads.push(Quad::new(
                    oc,
                    NamedNode::new(ds("credentialType"))?,
                    Literal::new_simple_literal(credential_type),
                    GraphName::DefaultGraph,
                ));
            }
        }
        for quad in &quads {
            self.store.insert(quad)?;
        }
        Ok(id)
    }

    /// All accepted offers, in insertion order - see [`Self::batches`] for
    /// the query/grouping pattern this mirrors.
    pub fn offers(&self) -> Result<Vec<AcceptedOffer>, CredentialGraphError> {
        let query = format!(
            r#"PREFIX ds: <{DS}>
               PREFIX vc: <{VC}>
               SELECT ?offer ?border ?offerId ?issuer ?oc ?ocorder ?credentialId ?credentialType WHERE {{
                   ?offer ds:order ?border ; ds:offerId ?offerId ; vc:issuer ?issuer .
                   OPTIONAL {{
                       ?offer ds:offersCredential ?oc .
                       ?oc ds:order ?ocorder ; ds:credentialId ?credentialId .
                       OPTIONAL {{ ?oc ds:credentialType ?credentialType }}
                   }}
               }} ORDER BY ?border ?ocorder"#
        );
        let mut out: Vec<(Term, AcceptedOffer)> = Vec::new();
        for row in self.select(&query)? {
            let Some(offer_term) = row.get("offer").cloned() else {
                continue;
            };
            let entry = match out.last_mut() {
                Some((last, offer)) if *last == offer_term => offer,
                _ => {
                    out.push((
                        offer_term,
                        AcceptedOffer {
                            id: row
                                .get("offerId")
                                .and_then(literal_value)
                                .unwrap_or_default(),
                            issuer: row
                                .get("issuer")
                                .and_then(literal_value)
                                .unwrap_or_default(),
                            credentials: Vec::new(),
                        },
                    ));
                    &mut out.last_mut().expect("just pushed").1
                }
            };
            if let Some(credential_id) = row.get("credentialId").and_then(literal_value) {
                entry.credentials.push(OfferedCredential {
                    id: credential_id,
                    credential_type: row.get("credentialType").and_then(literal_value),
                });
            }
        }
        Ok(out.into_iter().map(|(_, offer)| offer).collect())
    }

    /// A single offer by the id [`Self::add_offer`] minted for it, or
    /// `None` if no such offer exists - `identity-hub-contreforts`'s
    /// connector's `get()`.
    pub fn offer(&self, id: &str) -> Result<Option<AcceptedOffer>, CredentialGraphError> {
        Ok(self.offers()?.into_iter().find(|o| o.id == id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(credential_type: &str) -> CredentialEntry {
        CredentialEntry {
            credential_type: credential_type.to_string(),
            payload: serde_json::json!("fake-jws"),
            format: "jwt".to_string(),
        }
    }

    /// Mirrors `identity-hub-core::store`'s own pre-existing unit test
    /// scenario exactly (store two batches, one ISSUED and one REJECTED;
    /// confirm the rejected batch's credential never surfaces even when its
    /// type is requested) - the SPARQL round trip this graph replaces that
    /// `Vec`-based logic with must reproduce the same behavior.
    #[test]
    fn stores_and_filters_issued_credentials_by_type_via_sparql() {
        let graph = CredentialGraph::open_in_memory().expect("open in-memory store");
        graph
            .add_batch(NewCredentialBatch {
                issuer_pid: "issuer-1".to_string(),
                holder_pid: Some("holder-1".to_string()),
                status: "ISSUED".to_string(),
                rejection_reason: None,
                credentials: vec![entry("MembershipCredential")],
            })
            .expect("add_batch");
        graph
            .add_batch(NewCredentialBatch {
                issuer_pid: "issuer-2".to_string(),
                holder_pid: None,
                status: "REJECTED".to_string(),
                rejection_reason: Some("nope".to_string()),
                credentials: vec![entry("SensitiveDataCredential")],
            })
            .expect("add_batch");

        let found = graph
            .credentials_of_types(&["MembershipCredential".to_string()])
            .expect("credentials_of_types");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_type, "MembershipCredential");
        assert_eq!(found[0].payload, serde_json::json!("fake-jws"));

        // The rejected batch's credential must never surface, even if its
        // type is requested - the SPARQL `ds:status "ISSUED"` filter, not
        // just the Rust-side type check, is what excludes it.
        let none = graph
            .credentials_of_types(&["SensitiveDataCredential".to_string()])
            .expect("credentials_of_types");
        assert!(none.is_empty());

        assert_eq!(graph.batches().expect("batches").len(), 2);
    }

    #[test]
    fn batches_round_trips_every_field_including_optional_ones() {
        let graph = CredentialGraph::open_in_memory().expect("open in-memory store");
        let id = graph
            .add_batch(NewCredentialBatch {
                issuer_pid: "issuer-1".to_string(),
                holder_pid: None,
                status: "REJECTED".to_string(),
                rejection_reason: Some("bad proof".to_string()),
                credentials: vec![],
            })
            .expect("add_batch");

        let batches = graph.batches().expect("batches");
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].id, id);
        assert_eq!(batches[0].issuer_pid, "issuer-1");
        assert_eq!(batches[0].holder_pid, None);
        assert_eq!(batches[0].status, "REJECTED");
        assert_eq!(batches[0].rejection_reason.as_deref(), Some("bad proof"));
        assert!(batches[0].credentials.is_empty());

        let fetched = graph.batch(&id).expect("batch").expect("batch exists");
        assert_eq!(fetched.issuer_pid, "issuer-1");
        assert!(graph.batch("does-not-exist").expect("batch").is_none());
    }

    #[test]
    fn batches_preserve_credential_order_within_a_batch() {
        let graph = CredentialGraph::open_in_memory().expect("open in-memory store");
        graph
            .add_batch(NewCredentialBatch {
                issuer_pid: "issuer-1".to_string(),
                holder_pid: Some("holder-1".to_string()),
                status: "ISSUED".to_string(),
                rejection_reason: None,
                credentials: vec![
                    entry("FirstCredential"),
                    entry("SecondCredential"),
                    entry("ThirdCredential"),
                ],
            })
            .expect("add_batch");

        let batches = graph.batches().expect("batches");
        let types: Vec<&str> = batches[0]
            .credentials
            .iter()
            .map(|c| c.credential_type.as_str())
            .collect();
        assert_eq!(
            types,
            vec!["FirstCredential", "SecondCredential", "ThirdCredential"]
        );
    }

    #[test]
    fn offers_round_trip_issuer_and_offered_credentials_in_order() {
        let graph = CredentialGraph::open_in_memory().expect("open in-memory store");
        let id = graph
            .add_offer(NewAcceptedOffer {
                issuer: "did:web:issuer.example".to_string(),
                credentials: vec![
                    OfferedCredential {
                        id: "membership-credential".to_string(),
                        credential_type: Some("MembershipCredential".to_string()),
                    },
                    OfferedCredential {
                        id: "no-type-credential".to_string(),
                        credential_type: None,
                    },
                ],
            })
            .expect("add_offer");

        let offers = graph.offers().expect("offers");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].id, id);
        assert_eq!(offers[0].issuer, "did:web:issuer.example");
        assert_eq!(offers[0].credentials.len(), 2);
        assert_eq!(offers[0].credentials[0].id, "membership-credential");
        assert_eq!(
            offers[0].credentials[0].credential_type.as_deref(),
            Some("MembershipCredential")
        );
        assert_eq!(offers[0].credentials[1].id, "no-type-credential");
        assert_eq!(offers[0].credentials[1].credential_type, None);

        let fetched = graph.offer(&id).expect("offer").expect("offer exists");
        assert_eq!(fetched.issuer, "did:web:issuer.example");
        assert!(graph.offer("does-not-exist").expect("offer").is_none());
    }

    #[test]
    fn payload_round_trips_arbitrary_json_shapes_not_just_strings() {
        let graph = CredentialGraph::open_in_memory().expect("open in-memory store");
        graph
            .add_batch(NewCredentialBatch {
                issuer_pid: "issuer-1".to_string(),
                holder_pid: Some("holder-1".to_string()),
                status: "ISSUED".to_string(),
                rejection_reason: None,
                credentials: vec![CredentialEntry {
                    credential_type: "JsonLdCredential".to_string(),
                    payload: serde_json::json!({"@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiableCredential"]}),
                    format: "ldp_vc".to_string(),
                }],
            })
            .expect("add_batch");

        let found = graph
            .credentials_of_types(&["JsonLdCredential".to_string()])
            .expect("credentials_of_types");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].payload["type"],
            serde_json::json!(["VerifiableCredential"])
        );
    }
}
