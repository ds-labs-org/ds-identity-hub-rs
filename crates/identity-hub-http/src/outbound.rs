//! Confines every outbound HTTP request this process makes (DID resolution,
//! issued-credential delivery, offer-catalog metadata fetches) to an
//! explicit, deny-by-default host allow-list - see
//! `state::AppState::new`'s own doc comment for exactly which hosts are
//! derived and from where, and `../../ARCHITECTURE.md`'s "What's simplified
//! or stubbed" (the "Outbound request confinement" entry) for the full
//! design and the residual bootstrap limitation it keeps.
//!
//! Matching rule (exactly this, no more): **case-insensitive exact match on
//! the URL's host component; the port is ignored; no wildcard, suffix, or
//! CIDR matching.** Host-granularity (not host:port) is load-bearing here:
//! this crate's own test suite spawns stand-in DID servers on ephemeral
//! loopback ports, and the real `dcp-tck`'s own published port varies
//! between runs too - matching on host:port would make this policy reject
//! every one of those legitimate destinations right along with a real
//! attack.

use reqwest::Url;

#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("outbound host '{0}' is not on this service's allow-list")]
    HostNotAllowed(String),
    #[error("outbound URL scheme '{0}' is not supported (only http/https)")]
    UnsupportedScheme(String),
    #[error("outbound destination is not a usable URL: {0}")]
    Malformed(String),
}

/// A deny-by-default host allow-list. Every outbound request this process
/// makes to a destination not entirely of its own choosing (a caller's own
/// `iss` DID, a requester's own DID document's `serviceEndpoint`, an
/// issuer's own catalog endpoint) must be checked against this **before**
/// the network call happens - see the module doc comment above for the
/// matching rule, and each call site (`auth::verify_bearer_token`,
/// `auth::verify_nested_access_token`, `handlers::try_deliver_issued_credential`,
/// `validation::verify_credential_proofs`,
/// `validation::validate_offer_credentials`) for where.
pub struct OutboundPolicy {
    allowed_hosts: Vec<String>,
}

impl OutboundPolicy {
    /// Builds the policy from a set of hosts (host only, no port), lower-cased
    /// and de-duplicated so `check_url`/`check_did` can do a plain string
    /// comparison.
    pub fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        let mut allowed_hosts: Vec<String> = hosts.into_iter().map(|h| h.to_lowercase()).collect();
        allowed_hosts.sort();
        allowed_hosts.dedup();
        Self { allowed_hosts }
    }

    /// Checks a fully-formed destination URL: the scheme must be `http` or
    /// `https`, and the URL's host component (port ignored - see the module
    /// doc comment) must be on the allow-list.
    pub fn check_url(&self, url: &str) -> Result<(), OutboundError> {
        let parsed = Url::parse(url).map_err(|e| OutboundError::Malformed(e.to_string()))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => return Err(OutboundError::UnsupportedScheme(other.to_string())),
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| OutboundError::Malformed(format!("'{url}' has no host component")))?
            .to_lowercase();
        if self.allowed_hosts.iter().any(|allowed| allowed == &host) {
            Ok(())
        } else {
            Err(OutboundError::HostNotAllowed(host))
        }
    }

    /// Checks a `did:web` DID's implied resolution URL against the
    /// allow-list without resolving it - reuses `dcp_core::did_web_to_url`
    /// (the exact function `dcp_core::resolve_did` itself calls internally)
    /// so this check and the actual resolution can never disagree about
    /// what URL a given DID means.
    pub fn check_did(&self, did: &str, insecure_http: bool) -> Result<(), OutboundError> {
        let url = dcp_core::did_web_to_url(did, insecure_http).map_err(OutboundError::Malformed)?;
        self.check_url(&url)
    }
}
