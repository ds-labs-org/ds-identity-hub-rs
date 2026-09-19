use std::net::SocketAddr;

use identity_hub_core::scope::DEFAULT_SCOPE_PATTERN;

/// Which of the two roles this process boots as. A Credential Service has
/// both VPP and CIP obligations; a minimal Issuer Service has CIP
/// obligations only - see `../../ARCHITECTURE.md` and the real
/// `eclipse-dataspacetck/dcp-tck`'s own SUT matrix.
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
        }
    }
}
