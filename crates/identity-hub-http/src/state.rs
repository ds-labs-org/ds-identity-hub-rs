use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::CredentialObject;
use identity_hub_core::scope::ScopeMatcher;
use identity_hub_core::store::InMemoryCredentialStore;
use identity_hub_core::sts::StsConfig;

use crate::config::{Config, Mode};
use crate::outbound::OutboundPolicy;

/// The one host every `host.docker.internal` reference in this process
/// shares - both the static `reqwest` DNS override below and the
/// derived outbound allow-list - so the two can never drift apart. See
/// "A real networking gotcha" in `../../ARCHITECTURE.md` for why this host
/// is resolved at all.
const HOST_DOCKER_INTERNAL: &str = "host.docker.internal";

/// How long this process's shared `reqwest::Client` waits to establish a
/// TCP connection to any outbound destination before giving up - see
/// `../../ARCHITECTURE.md`'s "What's simplified or stubbed" (the outbound
/// timeouts entry) for why these specific values.
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// The total time budget (including connect) for any single outbound
/// request this process's shared `reqwest::Client` makes - covers DID
/// resolution, issued-credential delivery, and the offer-catalog metadata
/// fetch alike, since all three share this one client.
const OUTBOUND_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The maximum number of `jti` values [`AppState::seen_jti`] may remember at
/// once, fixed and oldest-evicted rather than unbounded - 2026-09-20
/// independent security audit, MEDIUM (unbounded process-lifetime growth).
/// See `../../ARCHITECTURE.md`, "What's simplified or stubbed", and
/// `../tests/bounded_state_growth.rs` for why this exact value: generous
/// enough that no real traffic (including a full `dcp-tck-runtime` run)
/// ever reaches it, while still a fixed ceiling an attacker cannot push
/// past.
pub const MAX_SEEN_JTI: usize = 4096;

/// The maximum number of Credential Request records [`AppState::requests`]
/// may track at once, for the same reason as [`MAX_SEEN_JTI`]; smaller
/// because a record is a multi-field struct rather than one short string.
pub const MAX_TRACKED_REQUESTS: usize = 2048;

/// The maximum number of `deliver_issued_credential` delivery tasks allowed
/// to be doing outbound network I/O at once. Unlike [`MAX_SEEN_JTI`] and
/// [`MAX_TRACKED_REQUESTS`] this bounds *concurrency*, not a stored
/// structure's size, and it never changes any protocol-visible response: a
/// Credential Request is still accepted and recorded (and answered `201`)
/// immediately, the cap only serializes how many spawned tasks are
/// concurrently talking to the network.
pub const MAX_IN_FLIGHT_DELIVERIES: usize = 32;

/// A fixed-capacity, insertion-ordered set of previously seen `jti` claims,
/// used for replay protection (`crate::auth::verify_bearer_token`). A plain
/// `HashSet` cannot evict in insertion order, so this pairs one with a
/// `VecDeque` that records arrival order; once `capacity` is exceeded, the
/// oldest entries are evicted first, never the one just inserted.
pub struct SeenJtiCache {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl SeenJtiCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// The number of `jti` values currently remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Records `jti` as seen. Returns `false` if it was already present (a
    /// replay - the caller must reject the request), `true` if this is the
    /// first time it has been seen. On a fresh insert, evicts the oldest
    /// remembered entries, oldest-first, until the cache is back at or under
    /// `capacity` - the entry just inserted is never evicted by this call.
    pub fn insert(&mut self, jti: &str) -> bool {
        if !self.seen.insert(jti.to_string()) {
            return false;
        }
        self.order.push_back(jti.to_string());
        while self.seen.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.seen.remove(&oldest);
                }
                None => break,
            }
        }
        true
    }
}

/// Tracks one accepted `CredentialRequestMessage` on the Issuer Service
/// side, for `GET /requests/<id>` (Credential Request Status API).
pub struct RequestRecord {
    pub issuer_pid: String,
    pub holder_pid: String,
    pub status: String,
}

/// A fixed-capacity, insertion-ordered table of [`RequestRecord`]s, keyed by
/// request id. Same shape as [`SeenJtiCache`]: O(1) lookup by id via the
/// `HashMap`, with a `VecDeque` recording arrival order so eviction, once
/// `capacity` is exceeded, takes the oldest record first.
pub struct RequestTable {
    records: HashMap<String, RequestRecord>,
    order: VecDeque<String>,
    capacity: usize,
}

impl RequestTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            records: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// The number of requests currently tracked.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Records a newly accepted Credential Request under `id`. `id` is
    /// always a freshly minted UUID at every call site, so this never
    /// overwrites an existing entry. If the table is now over `capacity`,
    /// evicts the oldest tracked request(s) first - the one just inserted is
    /// never evicted by this call.
    pub fn insert(&mut self, id: String, record: RequestRecord) {
        self.records.insert(id.clone(), record);
        self.order.push_back(id);
        while self.records.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.records.remove(&oldest);
                }
                None => break,
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<&RequestRecord> {
        self.records.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut RequestRecord> {
        self.records.get_mut(id)
    }
}

/// Shared application state. Deliberately a single struct used by both
/// process modes rather than two entirely separate types - see
/// `../../ARCHITECTURE.md`, "Why one AppState" for why this bootstrap's
/// scope doesn't justify the extra split.
pub struct AppState {
    pub config: Config,
    /// This process's own identity: the Credential Service's `did.holder`
    /// or the Issuer Service's `did.issuer`.
    pub identity: ServiceIdentity,
    /// A second, synthetic identity this process also generates and hosts a
    /// `did:web` document for, used only to sign tokens minted by the
    /// embedded STS - see `identity_hub_core::sts`'s module doc for why this
    /// must be a separate identity from `identity` above.
    pub sts_party: ServiceIdentity,
    pub sts_config: StsConfig,
    pub scope_matcher: ScopeMatcher,
    /// Storage API backing store (Credential Service mode).
    pub store: InMemoryCredentialStore,
    /// In-flight/completed credential requests (Issuer Service mode),
    /// capped at [`MAX_TRACKED_REQUESTS`] with oldest-first eviction - see
    /// `../../ARCHITECTURE.md`, "What's simplified or stubbed" (2026-09-20
    /// independent security audit, MEDIUM). An evicted request's `GET
    /// /requests/<id>` answers `404`, same as an id that never existed; its
    /// in-flight delivery task (if still running) finishes normally and
    /// simply has no record left to update.
    pub requests: Mutex<RequestTable>,
    /// Bounds how many `deliver_issued_credential` delivery tasks may be
    /// doing outbound network I/O at once, to
    /// [`MAX_IN_FLIGHT_DELIVERIES`] - see that constant's own doc comment.
    /// Acquired inside the spawned task itself, never on the request path,
    /// so it changes no protocol-visible response.
    pub delivery_semaphore: tokio::sync::Semaphore,
    /// The one `CredentialObject` this bootstrap's Issuer Service claims to
    /// support - real enough to drive a genuine Issuer Metadata API /
    /// Credential Request API round trip, but a single hardcoded type
    /// rather than a configurable catalog (see `../../ARCHITECTURE.md`).
    pub supported_credential: CredentialObject,
    pub http: reqwest::Client,
    /// Deny-by-default allow-list every outbound request this process makes
    /// to a destination not entirely of its own choosing must be checked
    /// against before the network call happens - see `crate::outbound`'s
    /// module doc comment and this constructor's own comment on how it's
    /// derived.
    pub outbound: OutboundPolicy,
    /// `jti` values already accepted by `crate::auth::verify_bearer_token`,
    /// across every endpoint that calls it - process-lifetime only, per
    /// `../../ARCHITECTURE.md`'s "No durable storage": sufficient to satisfy
    /// this bootstrap's own replay-protection scope without needing a
    /// persisted store, since a real deployment's tokens are short-lived
    /// (5 minutes) relative to any plausible process uptime concern here.
    /// Capped at [`MAX_SEEN_JTI`] with oldest-first eviction (2026-09-20
    /// independent security audit, MEDIUM) - see `../../ARCHITECTURE.md`,
    /// "What's simplified or stubbed".
    pub seen_jti: Mutex<SeenJtiCache>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let identity = ServiceIdentity::new(&config.did_host, config.mode.did_path_segment());
        let sts_party_host = format!("127.0.0.1:{}", config.bind_addr.port());
        let sts_party = ServiceIdentity::new(&sts_party_host, "sts-party");
        let scope_matcher = ScopeMatcher::new(&config.scope_pattern)
            .expect("configured scope pattern is a valid regex");
        let supported_credential = CredentialObject {
            context: None,
            id: "membership-credential".to_string(),
            object_type: "CredentialObject".to_string(),
            credential_type: Some("MembershipCredential".to_string()),
            binding_methods: Some(vec!["did:web".to_string()]),
            credential_schema: None,
            profile: Some("vc10-sl2021/jwt".to_string()),
            issuance_policy: None,
            offer_reason: None,
        };
        let sts_config = StsConfig::new(
            config.sts_client_id.clone(),
            config.sts_client_secret.clone(),
        );
        // `host.docker.internal` always resolves to loopback for this
        // process's own outbound requests - it never means anything else
        // outside a container. This is what lets this process, when run
        // natively alongside a Dockerized `dcp-tck-runtime` container (see
        // `tests/dcp_tck.rs`), resolve `did:web:host.docker.internal%3A<port>:...`
        // identities the TCK hosts and self-references (e.g. its own
        // `issuer`/`verifier` DIDs) via the exact same docker-published port
        // the container itself reaches back through - see
        // `tests/dcp_tck.rs`'s module doc comment for the full networking
        // picture (this "hairpin" round trip is why a single, fixed
        // published port works for both directions rather than needing
        // `host.docker.internal` to be independently resolvable on the bare
        // host). `reqwest::ClientBuilder::resolve` overrides only the IP;
        // the port from the request URL is used unchanged.
        let http = reqwest::Client::builder()
            .connect_timeout(OUTBOUND_CONNECT_TIMEOUT)
            .timeout(OUTBOUND_REQUEST_TIMEOUT)
            .resolve(
                HOST_DOCKER_INTERNAL,
                std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            )
            .build()
            .expect("reqwest client with a static host.docker.internal override builds");

        // The single source of truth for every host this process will ever
        // make an outbound HTTP request to - see `crate::outbound`'s module
        // doc comment for the matching rule and `../../ARCHITECTURE.md`'s
        // "What's simplified or stubbed" for the full derivation reasoning
        // and its one residual limitation (127.0.0.1 staying allow-listed
        // for as long as `sts_party` is bootstrapped there).
        let outbound_hosts = [
            // This service's own externally-advertised did:web host - it
            // must be able to resolve, and be resolved as, itself.
            config
                .did_host
                .split(':')
                .next()
                .unwrap_or(config.did_host.as_str())
                .to_string(),
            // `sts_party` is bootstrapped at exactly this host (see above) -
            // this process must be able to resolve its own STS-party DID.
            "127.0.0.1".to_string(),
            // The exact same host the reqwest DNS override above pins - see
            // `HOST_DOCKER_INTERNAL`'s own doc comment for why this process
            // needs to resolve it at all.
            HOST_DOCKER_INTERNAL.to_string(),
        ]
        .into_iter()
        .chain(config.allowed_outbound_hosts.iter().cloned());
        let outbound = OutboundPolicy::new(outbound_hosts);

        Self {
            config,
            identity,
            sts_party,
            sts_config,
            scope_matcher,
            store: InMemoryCredentialStore::new(),
            requests: Mutex::new(RequestTable::new(MAX_TRACKED_REQUESTS)),
            delivery_semaphore: tokio::sync::Semaphore::new(MAX_IN_FLIGHT_DELIVERIES),
            supported_credential,
            http,
            outbound,
            seen_jti: Mutex::new(SeenJtiCache::new(MAX_SEEN_JTI)),
        }
    }

    pub fn mode(&self) -> Mode {
        self.config.mode
    }

    pub fn base_url(&self) -> String {
        self.config.base_url()
    }
}
