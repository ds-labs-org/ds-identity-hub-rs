use std::net::SocketAddr;

use identity_hub_core::scope::DEFAULT_SCOPE_PATTERN;

/// Which of the two roles this process boots as. A Credential Service has
/// both VPP and CIP obligations; a minimal Issuer Service has CIP
/// obligations only - see `../../ARCHITECTURE.md` and the real
/// `eclipse-dataspacetck/dcp-tck`'s own SUT matrix.
/// Default `--admin-bind`: loopback only.
pub const DEFAULT_ADMIN_BIND: &str = "127.0.0.1:8182";
/// Default `--participant-context-id`.
pub const DEFAULT_PARTICIPANT_CONTEXT_ID: &str = "issuer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    CredentialService,
    IssuerService,
}

impl Mode {
    pub fn did_path_segment(self) -> &'static str {
        match self {
            Mode::CredentialService => "credential-service",
            Mode::IssuerService => "issuer-service",
        }
    }
}

/// What happens to a DCP Credential Request from a DID the Issuer Service
/// has no holder record for (`--holder-approval`). See the Issuer Admin API
/// section of `../../README.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum HolderApproval {
    /// The holder is created `approved` and the credential is delivered
    /// immediately - the behaviour the DCP TCK expects, hence the default.
    #[default]
    Auto,
    /// The holder is created `pending`; its requests wait as `SUBMITTED`
    /// until an operator approves or rejects it on the admin API.
    Manual,
}

/// Where to find the dataspace's trusted issuers registry
/// (`--trusted-issuers-registry`; `trusted-issuers-registry` feature).
#[cfg(feature = "trusted-issuers-registry")]
#[derive(Debug, Clone)]
pub struct TrustedIssuersRegistry {
    /// Base URL of the registry's public API (`https://registry.example`);
    /// the snapshot is `{base_url}/v1/snapshot`.
    pub base_url: String,
    /// The registry's own `did:web`, whose DID document holds the key that
    /// signs the snapshot.
    pub did: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    /// The socket this process actually binds and listens on.
    pub bind_addr: SocketAddr,
    /// The `host[:port]` embedded in this service's own `did:web` identity
    /// and advertised as its service endpoint's base URL - must be whatever
    /// a caller (a real verifier/issuer, or the `dcp-tck` container) can
    /// actually reach this process at, e.g. `localhost:8080` for local
    /// development or `host.docker.internal:8080` when a Dockerized TCK
    /// container calls back into a host-run instance of this process (see
    /// `tests/dcp_tck.rs`). Deliberately independent from `bind_addr`'s own
    /// host part, which is usually `0.0.0.0`.
    pub did_host: String,
    /// Hardcoded Secure Token Service client credentials - see
    /// `identity_hub_core::sts`'s module doc for why one hardcoded pair is
    /// sufficient for this bootstrap's scope.
    pub sts_client_id: String,
    pub sts_client_secret: String,
    /// The regex used to extract a requested credential type out of a DCP
    /// scope string (`identity_hub_core::scope::ScopeMatcher`). Defaults to
    /// the same pattern the real `dcp-tck`'s own
    /// `dataspacetck.vc.scope.pattern` defaults to.
    pub scope_pattern: String,
    /// Resolve `did:web` DIDs (and advertise this service's own DID
    /// document / service endpoints) over plain HTTP instead of HTTPS - for
    /// local/test environments only. `base.protocol.md` mandates HTTPS for
    /// a real deployment's base URL.
    pub insecure_http: bool,
    /// Allow-list of caller DIDs trusted to deliver a `CredentialMessage`
    /// (Storage API) or `CredentialOfferMessage` (Credential Offer API) to
    /// this Credential Service - the DCP spec's own "Verify Trust" step,
    /// distinct from (and enforced after) `verify_bearer_token`'s signature/
    /// envelope checks, which only prove a token's `iss` really signed it,
    /// not that this service has any reason to trust that `iss` as *the*
    /// issuer.
    ///
    /// **Deny by default**: empty means no issuer is trusted, so a service
    /// booted with no `--trusted-issuer-did` at all rejects every Storage
    /// API/Credential Offer API write with `401` (2026-09-20 independent
    /// security audit, HIGH - see `crate::auth::check_trusted_issuer`'s doc
    /// comment, `crate::handlers::storage_write`'s doc comment, and
    /// `../../ARCHITECTURE.md`'s "What's simplified or stubbed"). The
    /// opt-in is `--trusted-issuer-did` (repeatable) /
    /// [`Config::with_trusted_issuer_dids`] / the real
    /// `eclipse-dataspacetck/dcp-tck`'s own `dataspacetck.did.issuer`
    /// SUT-configuration property. A small explicit list is sufficient for
    /// this bootstrap's scope rather than a full trust-registry
    /// integration.
    ///
    /// Wired to the real `eclipse-dataspacetck/dcp-tck`'s own SUT
    /// convention for exactly this signal: `dataspacetck.did.issuer`
    /// (`BaseAssembly::parseDid`/`getIssuerDid`, decompiled from
    /// `eclipsedataspacetck/dcp-tck-runtime:latest` to confirm, not
    /// guessed) - see `tests/dcp.tck.properties`, which pins it explicitly,
    /// and `tests/dcp_tck.rs`, which passes the identical value here via
    /// [`Config::with_trusted_issuer_dids`].
    pub trusted_issuer_dids: Vec<String>,
    /// The dataspace's trusted issuers registry
    /// (`ds-trusted-issuers-registry-rs`). When set, it replaces
    /// [`trusted_issuer_dids`](Self::trusted_issuer_dids) as the
    /// "Verify Trust" step: an issuer is trusted for the credential types
    /// its accreditation chain in the registry's signed snapshot covers,
    /// and only for those - see `crate::registry_trust`.
    #[cfg(feature = "trusted-issuers-registry")]
    pub trusted_issuers_registry: Option<TrustedIssuersRegistry>,
    /// Allow-list of `holderPid` correlation ids this Credential Service was
    /// configured to expect on the Storage API (`POST /credentials`) - the
    /// DCP spec's own correlation mechanism between a Credential Request and
    /// the `CredentialMessage`(s) that eventually deliver it, distinct from
    /// (and checked independently of) `trusted_issuer_dids`, which is about
    /// *who* sent the message rather than *which request* it claims to
    /// answer. Empty means no restriction is configured - this bootstrap's
    /// permissive default (see `crate::validation::check_known_holder_pid`
    /// and `../../ARCHITECTURE.md`'s "What's simplified or stubbed"), not a
    /// claim that an empty list is a safe default for a real deployment: a
    /// real Credential Service would populate this from its own
    /// Credential-Request-tracking state as requests come in, which this
    /// bootstrap's Credential Service mode does not yet keep (see
    /// `../../ARCHITECTURE.md`'s "A holder-driven response to a Credential
    /// Offer").
    ///
    /// Wired to the real `eclipse-dataspacetck/dcp-tck`'s own
    /// `dataspacetck.credentials.correlation.id` SUT-configuration property
    /// (`BaseAssembly::getHolderPid`, decompiled from
    /// `eclipsedataspacetck/dcp-tck-runtime:latest` to confirm, not
    /// guessed) - see `tests/dcp.tck.properties`, which pins it explicitly,
    /// and `tests/dcp_tck.rs`, which passes the identical value here via
    /// [`Config::with_known_holder_pids`].
    pub known_holder_pids: Vec<String>,
    /// Operator-supplied extra hosts to add to `state::AppState::new`'s
    /// derived outbound-request allow-list (`outbound::OutboundPolicy`),
    /// on top of the hosts that policy always derives from this service's
    /// own configuration (its own `did_host`, `127.0.0.1`, and
    /// `host.docker.internal`) - see that constructor's own doc comment.
    /// Empty by default: this bootstrap's own configuration is normally
    /// sufficient on its own. Wired to the repeatable `--allow-resolve-host`
    /// CLI flag.
    pub allowed_outbound_hosts: Vec<String>,
    /// OAuth `client_id` the OID4VCI Wallet authenticates as at an issuer's
    /// token endpoint, with an RFC 7523 `private_key_jwt` assertion signed
    /// by this service's own DID key (`kid` = its DID URL). `None` (the
    /// default) keeps the Pre-Authorized Code flow anonymous. Wired to
    /// `--oid4vci-client-id`.
    pub oid4vci_client_id: Option<String>,
    /// Mounts the Wallet's unauthenticated Credential Offer Endpoint,
    /// `GET /oid4vci/wallet/credential_offer` (see `crate::oid4vci`). Off by
    /// default. Wired to `--oid4vci-offer-endpoint`.
    pub oid4vci_offer_endpoint: bool,
    /// Transaction Code that endpoint answers an offer's `tx_code` with,
    /// since nobody is there to type one in. Meant for conformance testing,
    /// where the test issuer's code is known in advance. Wired to
    /// `--oid4vci-offer-tx-code`.
    pub oid4vci_offer_tx_code: Option<String>,
    /// Extra PEM trust anchors for this process's outbound TLS (e.g. a test
    /// issuer's private CA), on top of the built-in web roots. Wired to the
    /// repeatable `--extra-root-cert <path>`.
    pub extra_root_certs: Vec<Vec<u8>>,
    /// Where the Issuer Admin API listens (`--admin-bind`). Loopback by
    /// default: it is an operator surface, never meant to share the public
    /// DCP listener's exposure.
    pub admin_bind: SocketAddr,
    /// Bearer token every Issuer Admin API request must carry
    /// (`--admin-token` / `IDENTITY_HUB_ADMIN_TOKEN`). `None` means no admin
    /// listener at all - deny by default.
    pub admin_token: Option<String>,
    /// The one participant context this single-tenant hub answers to on the
    /// admin API's `{pc}` path segment (`--participant-context-id`).
    pub participant_context_id: String,
    /// `--holder-approval`: see [`HolderApproval`].
    pub holder_approval: HolderApproval,
}

impl Config {
    pub fn scheme(&self) -> &'static str {
        if self.insecure_http { "http" } else { "https" }
    }

    /// This service's own externally reachable base URL - the
    /// `serviceEndpoint` advertised in its DID document's
    /// `CredentialService`/`IssuerService` entry.
    pub fn base_url(&self) -> String {
        format!("{}://{}", self.scheme(), self.did_host)
    }

    pub fn for_test(mode: Mode, bind_addr: SocketAddr, did_host: impl Into<String>) -> Self {
        Self {
            mode,
            bind_addr,
            did_host: did_host.into(),
            sts_client_id: "tck-client".to_string(),
            sts_client_secret: "tck-secret".to_string(),
            scope_pattern: DEFAULT_SCOPE_PATTERN.to_string(),
            insecure_http: true,
            trusted_issuer_dids: Vec::new(),
            #[cfg(feature = "trusted-issuers-registry")]
            trusted_issuers_registry: None,
            known_holder_pids: Vec::new(),
            allowed_outbound_hosts: Vec::new(),
            oid4vci_client_id: None,
            oid4vci_offer_endpoint: false,
            oid4vci_offer_tx_code: None,
            extra_root_certs: Vec::new(),
            admin_bind: DEFAULT_ADMIN_BIND
                .parse()
                .expect("valid default admin bind"),
            admin_token: None,
            participant_context_id: DEFAULT_PARTICIPANT_CONTEXT_ID.to_string(),
            holder_approval: HolderApproval::Auto,
        }
    }

    /// Builder-style setter for
    /// [`trusted_issuers_registry`](Self::trusted_issuers_registry).
    #[cfg(feature = "trusted-issuers-registry")]
    pub fn with_trusted_issuers_registry(
        mut self,
        base_url: impl Into<String>,
        did: impl Into<String>,
    ) -> Self {
        self.trusted_issuers_registry = Some(TrustedIssuersRegistry {
            base_url: base_url.into(),
            did: did.into(),
        });
        self
    }

    /// Builder-style setter for [`trusted_issuer_dids`](Self::trusted_issuer_dids),
    /// so the common case (`for_test`'s permissive empty default) doesn't
    /// need every call site updated just to opt in.
    pub fn with_trusted_issuer_dids(mut self, trusted_issuer_dids: Vec<String>) -> Self {
        self.trusted_issuer_dids = trusted_issuer_dids;
        self
    }

    /// Builder-style setter for [`known_holder_pids`](Self::known_holder_pids),
    /// mirroring [`Config::with_trusted_issuer_dids`].
    pub fn with_known_holder_pids(mut self, known_holder_pids: Vec<String>) -> Self {
        self.known_holder_pids = known_holder_pids;
        self
    }
}
