//! Issuer Service governance state: the credential-definition catalog, the
//! holder registry, issued-credential records and the StatusList2021
//! revocation list - everything the Issuer Admin API (`crate::admin`) reads
//! and writes, and that the DCP Credential Request API (`crate::handlers`)
//! consults before accepting a request.
//!
//! The wire shapes here are the governance console's shared contract
//! (`governance/api-contract.md`, section 1), which mirrors Eclipse EDC
//! IdentityHub's Issuer Admin API `v1alpha`. Field names are camelCase and
//! every timestamp is unix seconds.
//!
//! ## Bounded, like everything else attacker-reachable in this process
//!
//! Holders are created by *unauthenticated-ish* traffic (any party that can
//! host a `did:web` document can send a Credential Request), so the
//! registry has a hard cap ([`MAX_HOLDERS`]) and refuses rather than evicts
//! once full: a holder record is a governance decision (approved/rejected),
//! and silently forgetting a rejection would let the rejected party back
//! in. The definition catalog is admin-only but capped all the same
//! ([`MAX_CREDENTIAL_DEFINITIONS`]). Issued-credential records cannot
//! outnumber the status list's bits ([`STATUS_LIST_BITS`]), since every
//! record owns one index for its lifetime.
//!
//! ## Lock order
//!
//! These structures each sit behind their own `std::sync::Mutex` on
//! `AppState`. Whenever more than one is held at once the order is
//! `definitions -> holders -> requests -> issued`; no lock is ever held
//! across an `.await`.

use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::io::Write;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Maximum number of credential definitions in the catalog.
pub const MAX_CREDENTIAL_DEFINITIONS: usize = 256;
/// Maximum number of holder records. A Credential Request from an unknown
/// DID once full is refused `503` (contract: "Holders capped (4096)").
pub const MAX_HOLDERS: usize = 4096;
/// QuerySpec `limit` ceiling: a single page never returns more than this.
pub const MAX_QUERY_LIMIT: usize = 500;
/// QuerySpec `limit` when the body leaves it out (EDC's own default).
pub const DEFAULT_QUERY_LIMIT: usize = 50;
/// More criteria than this in one `filterExpression` is refused `400` - the
/// filter is a linear scan per criterion, so its cost is kept bounded too.
pub const MAX_FILTER_CRITERIA: usize = 16;
/// StatusList2021's minimum (and this hub's only) list size: 16 KiB of bits,
/// large enough that a list does not by itself reveal much about who holds
/// which credential.
pub const STATUS_LIST_BITS: usize = 131_072;
/// The one credential format this hub can sign today.
pub const FORMAT_VC1_0_JWT: &str = "VC1_0_JWT";
/// Default credential validity, seconds.
pub const DEFAULT_VALIDITY_SECS: u64 = 3600;
/// The JSON-LD context that defines `StatusList2021Entry` /
/// `StatusList2021Credential`.
pub const STATUS_LIST_CONTEXT: &str = "https://w3id.org/vc/status-list/2021/v1";
/// Path of the public revocation list (relative to the base URL).
pub const STATUS_LIST_PATH: &str = "/statuslist/revocation";

/// A rule-level error, mapped by the admin API onto its HTTP status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerError {
    /// 400: malformed or invalid input.
    Invalid(String),
    /// 404: no such id.
    NotFound(String),
    /// 409: duplicate or rule violation.
    Conflict(String),
    /// 503: a bounded structure is full.
    Full(String),
}

// ---- credential definitions ----

/// One entry of the credential catalog. Only `id`, `credentialType`,
/// `format` and `validity` drive issuance today; the schema, mappings,
/// rules and attestations are stored and echoed back for console parity
/// with EDC but not evaluated (see `../../ARCHITECTURE.md`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinition {
    pub id: String,
    pub credential_type: String,
    pub format: String,
    pub validity: u64,
    pub json_schema_url: Option<String>,
    pub json_schema: Option<Value>,
    pub mappings: Vec<Value>,
    pub rules: Vec<Value>,
    pub attestations: Vec<Value>,
    pub created_at: u64,
}

/// What a client may send on `POST`/`PUT .../credentialdefinitions`.
/// `createdAt` (and anything unknown) is ignored: the hub owns it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinitionInput {
    pub id: String,
    pub credential_type: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub validity: Option<i64>,
    #[serde(default)]
    pub json_schema_url: Option<String>,
    #[serde(default)]
    pub json_schema: Option<Value>,
    #[serde(default)]
    pub mappings: Option<Vec<Value>>,
    #[serde(default)]
    pub rules: Option<Vec<Value>>,
    #[serde(default)]
    pub attestations: Option<Vec<Value>>,
}

/// `^[A-Za-z][A-Za-z0-9_.-]*$`, hand-rolled: the credential type ends up in
/// a VC `type` array and in DCP scope strings, so it is kept to a plain
/// token.
fn valid_credential_type(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

impl CredentialDefinitionInput {
    /// Validates per the contract and builds the stored definition.
    pub fn into_definition(self, created_at: u64) -> Result<CredentialDefinition, IssuerError> {
        if self.id.trim().is_empty() {
            return Err(IssuerError::Invalid("id must not be empty".into()));
        }
        if !valid_credential_type(&self.credential_type) {
            return Err(IssuerError::Invalid(
                "credentialType must match ^[A-Za-z][A-Za-z0-9_.-]*$".into(),
            ));
        }
        let format = self.format.unwrap_or_else(|| FORMAT_VC1_0_JWT.to_string());
        if format != FORMAT_VC1_0_JWT {
            return Err(IssuerError::Invalid(format!(
                "format '{format}' is not supported; only {FORMAT_VC1_0_JWT}"
            )));
        }
        let validity = match self.validity {
            None => DEFAULT_VALIDITY_SECS,
            Some(v) if v > 0 => v as u64,
            Some(_) => return Err(IssuerError::Invalid("validity must be > 0".into())),
        };
        Ok(CredentialDefinition {
            id: self.id,
            credential_type: self.credential_type,
            format,
            validity,
            json_schema_url: self.json_schema_url,
            json_schema: self.json_schema,
            mappings: self.mappings.unwrap_or_default(),
            rules: self.rules.unwrap_or_default(),
            attestations: self.attestations.unwrap_or_default(),
            created_at,
        })
    }
}

/// The catalog, in insertion order (what `/metadata` lists, seeded entry
/// first).
pub struct DefinitionCatalog {
    definitions: Vec<CredentialDefinition>,
}

impl DefinitionCatalog {
    /// Seeds `membership-credential` / `MembershipCredential` - the one type
    /// this hub hardcoded before the catalog existed, so the DCP TCK and the
    /// OID4VCI tests see exactly what they saw before.
    pub fn seeded(now: u64) -> Self {
        let seed = CredentialDefinitionInput {
            id: "membership-credential".into(),
            credential_type: "MembershipCredential".into(),
            format: None,
            validity: None,
            json_schema_url: None,
            json_schema: None,
            mappings: None,
            rules: None,
            attestations: None,
        }
        .into_definition(now)
        .expect("the seeded definition is valid");
        Self {
            definitions: vec![seed],
        }
    }

    pub fn all(&self) -> &[CredentialDefinition] {
        &self.definitions
    }

    pub fn get(&self, id: &str) -> Option<&CredentialDefinition> {
        self.definitions.iter().find(|d| d.id == id)
    }

    pub fn create(&mut self, definition: CredentialDefinition) -> Result<(), IssuerError> {
        if self.get(&definition.id).is_some() {
            return Err(IssuerError::Conflict(format!(
                "credential definition '{}' already exists",
                definition.id
            )));
        }
        if self.definitions.len() >= MAX_CREDENTIAL_DEFINITIONS {
            return Err(IssuerError::Full(format!(
                "at most {MAX_CREDENTIAL_DEFINITIONS} credential definitions"
            )));
        }
        self.definitions.push(definition);
        Ok(())
    }

    /// Replaces the definition with the same id, keeping its `createdAt`.
    pub fn update(
        &mut self,
        mut definition: CredentialDefinition,
    ) -> Result<CredentialDefinition, IssuerError> {
        let existing = self
            .definitions
            .iter_mut()
            .find(|d| d.id == definition.id)
            .ok_or_else(|| {
                IssuerError::NotFound(format!("no credential definition '{}'", definition.id))
            })?;
        definition.created_at = existing.created_at;
        *existing = definition.clone();
        Ok(definition)
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.definitions.len();
        self.definitions.retain(|d| d.id != id);
        before != self.definitions.len()
    }
}

// ---- holders ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HolderStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Holder {
    pub holder_id: String,
    pub did: String,
    pub name: Option<String>,
    pub properties: Map<String, Value>,
    pub status: HolderStatus,
    pub created_at: u64,
}

/// `POST .../holders` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderRegistration {
    #[serde(default)]
    pub holder_id: Option<String>,
    pub did: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// `PUT .../holders` body: only `name`/`properties` are updatable.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderUpdate {
    pub holder_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// Holder records, keyed by id and indexed by DID, kept in insertion order.
/// Never evicts - see this module's doc comment.
#[derive(Default)]
pub struct HolderRegistry {
    holders: HashMap<String, Holder>,
    by_did: HashMap<String, String>,
    order: Vec<String>,
}

impl HolderRegistry {
    pub fn len(&self) -> usize {
        self.holders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.holders.is_empty()
    }

    pub fn get(&self, holder_id: &str) -> Option<&Holder> {
        self.holders.get(holder_id)
    }

    pub fn get_mut(&mut self, holder_id: &str) -> Option<&mut Holder> {
        self.holders.get_mut(holder_id)
    }

    pub fn by_did(&self, did: &str) -> Option<&Holder> {
        self.by_did.get(did).and_then(|id| self.holders.get(id))
    }

    pub fn all(&self) -> impl Iterator<Item = &Holder> {
        self.order.iter().filter_map(|id| self.holders.get(id))
    }

    /// Inserts a new holder: `409` on a duplicate id or DID, `503` when the
    /// registry is full.
    pub fn insert(&mut self, holder: Holder) -> Result<Holder, IssuerError> {
        if self.holders.contains_key(&holder.holder_id) {
            return Err(IssuerError::Conflict(format!(
                "holder '{}' already exists",
                holder.holder_id
            )));
        }
        if self.by_did.contains_key(&holder.did) {
            return Err(IssuerError::Conflict(format!(
                "a holder with did '{}' already exists",
                holder.did
            )));
        }
        if self.holders.len() >= MAX_HOLDERS {
            return Err(IssuerError::Full(format!(
                "holder registry is full ({MAX_HOLDERS})"
            )));
        }
        self.by_did
            .insert(holder.did.clone(), holder.holder_id.clone());
        self.order.push(holder.holder_id.clone());
        self.holders
            .insert(holder.holder_id.clone(), holder.clone());
        Ok(holder)
    }
}

// ---- issuance processes ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessState {
    /// Waiting for the holder to be approved.
    Submitted,
    /// Delivery in flight.
    Approved,
    Delivered,
    Errored,
    Rejected,
}

impl ProcessState {
    /// The DCP Credential Request Status API's view of this state
    /// (`credential.issuance.protocol.md#credentialstatus`).
    pub fn dcp_status(self) -> &'static str {
        match self {
            ProcessState::Submitted | ProcessState::Approved => "RECEIVED",
            ProcessState::Delivered => "ISSUED",
            ProcessState::Errored | ProcessState::Rejected => "REJECTED",
        }
    }

    /// SUBMITTED and APPROVED still need their credential definitions.
    pub fn is_active(self) -> bool {
        matches!(self, ProcessState::Submitted | ProcessState::Approved)
    }
}

/// One accepted DCP Credential Request. Its `id` is the DCP `issuerPid`
/// (and the `Location: /requests/{id}` the request was answered with).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceProcess {
    pub id: String,
    pub state: ProcessState,
    pub holder_id: String,
    pub holder_did: String,
    pub holder_pid: String,
    pub credential_definitions: Vec<String>,
    pub error_detail: Option<String>,
    pub created_at: u64,
    pub state_timestamp: u64,
    /// The access token the holder put in its own Self-Issued ID Token's
    /// `token` claim, echoed back on delivery per
    /// `credential.issuance.protocol.md` step 7. Never exposed on the admin
    /// API: it is the holder's bearer credential.
    #[serde(skip)]
    pub delivery_bearer: Option<String>,
}

impl IssuanceProcess {
    pub fn transition(&mut self, state: ProcessState, now: u64) {
        self.state = state;
        self.state_timestamp = now;
    }
}

// ---- issued credentials and the status list ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialRecordStatus {
    Active,
    Revoked,
}

/// One credential the hub signed and delivered successfully.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCredential {
    pub id: String,
    pub credential_type: String,
    pub credential_definition_id: String,
    pub holder_id: String,
    pub holder_did: String,
    pub issuance_process_id: String,
    pub format: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: CredentialRecordStatus,
    pub status_list_index: usize,
}

/// A StatusList2021 revocation bitstring: bit `i` is the most significant
/// bit first of byte `i / 8`. Indexes are handed out sequentially and never
/// reused, so a revoked index can never come back as a fresh credential's.
pub struct StatusList {
    bits: Vec<u8>,
    next_index: usize,
    /// The last signed `StatusList2021Credential`, so the public, unauthenticated
    /// endpoint does not gzip and ECDSA-sign on every hit; dropped whenever
    /// a bit changes.
    pub cached_jwt: Option<String>,
}

impl Default for StatusList {
    fn default() -> Self {
        Self {
            bits: vec![0; STATUS_LIST_BITS / 8],
            next_index: 0,
            cached_jwt: None,
        }
    }
}

impl StatusList {
    /// The next unused index, or `None` once all [`STATUS_LIST_BITS`] are
    /// spent (the issuer then refuses to issue rather than reuse one).
    pub fn allocate(&mut self) -> Option<usize> {
        (self.next_index < STATUS_LIST_BITS).then(|| {
            self.next_index += 1;
            self.next_index - 1
        })
    }

    pub fn set(&mut self, index: usize) {
        let mask = 0x80u8 >> (index % 8);
        if self.bits[index / 8] & mask == 0 {
            self.bits[index / 8] |= mask;
            self.cached_jwt = None;
        }
    }

    pub fn is_set(&self, index: usize) -> bool {
        self.bits[index / 8] & (0x80u8 >> (index % 8)) != 0
    }

    /// `encodedList`: GZIP of the bitstring, base64url without padding.
    pub fn encoded(&self) -> String {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&self.bits)
            .expect("writing to an in-memory gzip encoder cannot fail");
        let gzipped = encoder
            .finish()
            .expect("finishing an in-memory gzip encoder cannot fail");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(gzipped)
    }
}

/// Issued-credential records plus the status list their indexes live in.
/// Records are never evicted: one exists per allocated index, so the list's
/// own size bounds them.
#[derive(Default)]
pub struct IssuedCredentials {
    records: HashMap<String, IssuedCredential>,
    order: VecDeque<String>,
    pub status_list: StatusList,
}

impl IssuedCredentials {
    pub fn insert(&mut self, record: IssuedCredential) {
        self.order.push_back(record.id.clone());
        self.records.insert(record.id.clone(), record);
    }

    pub fn get(&self, id: &str) -> Option<&IssuedCredential> {
        self.records.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &IssuedCredential> {
        self.order.iter().filter_map(|id| self.records.get(id))
    }

    /// Marks `id` revoked and sets its status-list bit. Idempotent.
    pub fn revoke(&mut self, id: &str) -> Option<IssuedCredential> {
        let record = self.records.get_mut(id)?;
        record.status = CredentialRecordStatus::Revoked;
        let index = record.status_list_index;
        let snapshot = record.clone();
        self.status_list.set(index);
        Some(snapshot)
    }
}

// ---- QuerySpec ----

/// EDC's QuerySpec, as the contract restricts it: `=` only, on top-level
/// scalar fields of the returned objects.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuerySpec {
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub filter_expression: Option<Vec<Criterion>>,
    #[serde(default)]
    pub sort_field: Option<String>,
    #[serde(default)]
    pub sort_order: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Criterion {
    pub operand_left: String,
    pub operator: String,
    #[serde(default)]
    pub operand_right: Value,
}

/// `=` between a stored field and a filter operand. A string operand also
/// matches a number/boolean field that prints the same (`"7"` matches
/// `7`), since query UIs commonly send every operand as a string.
fn operand_matches(field: Option<&Value>, operand: &Value) -> bool {
    let field = field.unwrap_or(&Value::Null);
    if field == operand {
        return true;
    }
    match (field, operand) {
        (Value::Number(n), Value::String(s)) => n.to_string() == *s,
        (Value::Bool(b), Value::String(s)) => b.to_string() == *s,
        _ => false,
    }
}

fn compare_values(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    match (a, b) {
        (Some(Value::Number(x)), Some(Value::Number(y))) => x
            .as_f64()
            .partial_cmp(&y.as_f64())
            .unwrap_or(Ordering::Equal),
        (Some(Value::String(x)), Some(Value::String(y))) => x.cmp(y),
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x.cmp(y),
        (None | Some(Value::Null), None | Some(Value::Null)) => Ordering::Equal,
        (None | Some(Value::Null), _) => Ordering::Less,
        (_, None | Some(Value::Null)) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

impl QuerySpec {
    /// Filters, sorts (stably, so equal keys keep insertion order) and pages
    /// `items`. `Err` is a `400` message.
    pub fn apply(&self, items: Vec<Value>) -> Result<Vec<Value>, String> {
        let offset = match self.offset {
            None => 0,
            Some(o) if o >= 0 => o as usize,
            Some(_) => return Err("offset must be >= 0".into()),
        };
        let limit = match self.limit {
            None => DEFAULT_QUERY_LIMIT,
            Some(l) if l >= 0 => (l as usize).min(MAX_QUERY_LIMIT),
            Some(_) => return Err("limit must be >= 0".into()),
        };
        let descending = match self.sort_order.as_deref().map(str::to_ascii_uppercase) {
            None => false,
            Some(o) if o == "ASC" => false,
            Some(o) if o == "DESC" => true,
            Some(o) => return Err(format!("sortOrder must be ASC or DESC, not '{o}'")),
        };
        let criteria = self.filter_expression.as_deref().unwrap_or_default();
        if criteria.len() > MAX_FILTER_CRITERIA {
            return Err(format!(
                "at most {MAX_FILTER_CRITERIA} filterExpression criteria"
            ));
        }
        if let Some(c) = criteria.iter().find(|c| c.operator != "=") {
            return Err(format!(
                "operator '{}' is not supported; only '='",
                c.operator
            ));
        }
        let mut matched: Vec<Value> = items
            .into_iter()
            .filter(|item| {
                criteria
                    .iter()
                    .all(|c| operand_matches(item.get(&c.operand_left), &c.operand_right))
            })
            .collect();
        if let Some(field) = &self.sort_field {
            matched.sort_by(|a, b| {
                let ordering = compare_values(a.get(field), b.get(field));
                if descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            });
        } else if descending {
            matched.reverse();
        }
        Ok(matched.into_iter().skip(offset).take(limit).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_list_bits_are_msb_first() {
        let mut list = StatusList::default();
        list.set(0);
        list.set(9);
        assert_eq!(list.bits[0], 0x80);
        assert_eq!(list.bits[1], 0x40);
        assert!(list.is_set(9) && !list.is_set(8));
    }

    #[test]
    fn status_list_allocation_stops_at_capacity() {
        let mut list = StatusList {
            next_index: STATUS_LIST_BITS - 1,
            ..Default::default()
        };
        assert_eq!(list.allocate(), Some(STATUS_LIST_BITS - 1));
        assert_eq!(list.allocate(), None);
    }

    #[test]
    fn credential_type_pattern() {
        for ok in ["A", "Membership.Credential-v1_2", "x"] {
            assert!(valid_credential_type(ok), "{ok}");
        }
        for bad in ["", "1A", "_A", "A B", "A/B", "Ä"] {
            assert!(!valid_credential_type(bad), "{bad}");
        }
    }

    #[test]
    fn string_operands_match_numbers() {
        assert!(operand_matches(Some(&json!(7)), &json!("7")));
        assert!(operand_matches(Some(&json!(7)), &json!(7)));
        assert!(!operand_matches(None, &json!("x")));
    }
}
