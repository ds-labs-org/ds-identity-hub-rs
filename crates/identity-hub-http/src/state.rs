use std::collections::HashMap;
use std::sync::Mutex;

use identity_hub_core::identity::ServiceIdentity;
use identity_hub_core::messages::CredentialObject;
use identity_hub_core::scope::ScopeMatcher;
use identity_hub_core::store::InMemoryCredentialStore;
use identity_hub_core::sts::StsConfig;

use crate::config::{Config, Mode};

/// Tracks one accepted `CredentialRequestMessage` on the Issuer Service
/// side, for `GET /requests/<id>` (Credential Request Status API).
pub struct RequestRecord {
    pub issuer_pid: String,
    pub holder_pid: String,
    pub status: String,
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
    /// In-flight/completed credential requests (Issuer Service mode).
    pub requests: Mutex<HashMap<String, RequestRecord>>,
    /// The one `CredentialObject` this bootstrap's Issuer Service claims to
    /// support - real enough to drive a genuine Issuer Metadata API /
    /// Credential Request API round trip, but a single hardcoded type
    /// rather than a configurable catalog (see `../../ARCHITECTURE.md`).
    pub supported_credential: CredentialObject,
    pub http: reqwest::Client,
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
            .resolve(
                "host.docker.internal",
                std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            )
            .build()
            .expect("reqwest client with a static host.docker.internal override builds");
        Self {
            config,
            identity,
            sts_party,
            sts_config,
            scope_matcher,
            store: InMemoryCredentialStore::new(),
            requests: Mutex::new(HashMap::new()),
            supported_credential,
            http,
        }
    }

    pub fn mode(&self) -> Mode {
        self.config.mode
    }

    pub fn base_url(&self) -> String {
        self.config.base_url()
    }
}
