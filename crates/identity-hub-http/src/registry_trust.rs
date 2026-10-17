//! The "Verify Trust" step backed by the dataspace's trusted issuers
//! registry (`ds-trusted-issuers-registry-rs`), when
//! `Config::trusted_issuers_registry` is set. It replaces the static
//! `--trusted-issuer-did` list: an issuer is trusted for exactly the
//! credential types its accreditation chain in the registry covers, and
//! that is checked for both the caller delivering a message and each
//! delivered credential's own `iss`.
//!
//! The registry is not called per credential. Its signed snapshot
//! (`GET {base}/v1/snapshot`) is fetched, verified against the key in the
//! registry's own `did:web` document (`trusted_issuers_core::verify_snapshot`)
//! and kept, then refetched after a quarter of its lifetime (the registry's
//! own `Cache-Control`), so a suspension reaches this service within about
//! a quarter of the snapshot TTL. Both requests go through
//! [`OutboundPolicy`](crate::outbound::OutboundPolicy) like every other.
//!
//! Fails closed: with no snapshot that verifies and has not expired, nobody
//! is trusted. A failed refresh keeps using the cached snapshot until it
//! expires, so a registry outage shorter than the TTL changes nothing.
//!
//! Behind the `trusted-issuers-registry` Cargo feature (off by default).
//! Without it only [`check_issuer`] remains, and it always uses the static
//! list.

#[cfg(feature = "trusted-issuers-registry")]
use std::sync::Arc;

#[cfg(feature = "trusted-issuers-registry")]
use dcp_core::now_secs;
#[cfg(feature = "trusted-issuers-registry")]
use tokio::sync::Mutex;
#[cfg(feature = "trusted-issuers-registry")]
use trusted_issuers_core::{TrustList, snapshot_kid, verify_snapshot};

use crate::auth::{AuthError, check_trusted_issuer};
#[cfg(feature = "trusted-issuers-registry")]
use crate::config::TrustedIssuersRegistry;
use crate::state::AppState;

#[cfg(feature = "trusted-issuers-registry")]
/// Refetch a snapshot this long before it expires at the latest.
pub const REFRESH_MARGIN_SECS: u64 = 30;

#[cfg(feature = "trusted-issuers-registry")]
/// Whether a snapshot fetched at `fetched_at` and valid from `iat` to `exp`
/// should be refetched at `now`: once a quarter of its lifetime has passed
/// since the fetch, or within [`REFRESH_MARGIN_SECS`] of its expiry.
pub fn needs_refresh(fetched_at: u64, iat: u64, exp: u64, now: u64) -> bool {
    let lifetime = exp.saturating_sub(iat);
    now >= fetched_at.saturating_add(lifetime / 4) || now.saturating_add(REFRESH_MARGIN_SECS) >= exp
}

#[cfg(feature = "trusted-issuers-registry")]
struct Cached {
    list: Arc<TrustList>,
    fetched_at: u64,
}

#[cfg(feature = "trusted-issuers-registry")]
/// The registry this service trusts, and its last verified snapshot.
pub struct RegistryTrust {
    pub source: TrustedIssuersRegistry,
    cached: Mutex<Option<Cached>>,
}

#[cfg(feature = "trusted-issuers-registry")]
impl RegistryTrust {
    pub fn new(source: TrustedIssuersRegistry) -> Self {
        Self {
            source,
            cached: Mutex::new(None),
        }
    }

    /// The current trust list: the cached snapshot while it is fresh,
    /// otherwise a newly fetched and verified one (the lock makes
    /// concurrent callers share one fetch). A failed fetch falls back to the
    /// cached snapshot until it expires.
    async fn trust_list(&self, state: &AppState) -> Result<Arc<TrustList>, String> {
        let mut cached = self.cached.lock().await;
        let now = now_secs();
        if let Some(c) = cached.as_ref()
            && !needs_refresh(c.fetched_at, c.list.iat, c.list.exp, now)
        {
            return Ok(c.list.clone());
        }
        match self.fetch(state, now).await {
            Ok(list) => {
                let list = Arc::new(list);
                *cached = Some(Cached {
                    list: list.clone(),
                    fetched_at: now,
                });
                Ok(list)
            }
            Err(e) => match cached.as_ref() {
                Some(c) if now < c.list.exp => {
                    tracing::warn!(error = %e, "trusted issuers registry refresh failed; using the cached snapshot until it expires");
                    Ok(c.list.clone())
                }
                _ => Err(e),
            },
        }
    }

    async fn fetch(&self, state: &AppState, now: u64) -> Result<TrustList, String> {
        let url = format!("{}/v1/snapshot", self.source.base_url.trim_end_matches('/'));
        state
            .outbound
            .check_url(&url)
            .map_err(|e| format!("{url}: {e}"))?;
        let response = state
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("GET {url}: {}", response.status()));
        }
        let token = response
            .text()
            .await
            .map_err(|e| format!("GET {url}: {e}"))?;
        let did = &self.source.did;
        state
            .outbound
            .check_did(did, state.config.insecure_http)
            .map_err(|e| format!("{did}: {e}"))?;
        let doc = dcp_core::resolve_did(&state.http, did, state.config.insecure_http)
            .await
            .map_err(|e| format!("resolving {did}: {e}"))?;
        let kid = snapshot_kid(token.trim()).map_err(|e| e.to_string())?;
        let key = dcp_core::find_verifying_key(&doc, &kid).map_err(|e| e.to_string())?;
        verify_snapshot(token.trim(), did, &key, now).map_err(|e| e.to_string())
    }

    /// Whether `iss` may issue every one of `credential_types` now. With no
    /// type to check, `iss` must be trusted for at least one type it is
    /// listed for.
    pub async fn check(
        &self,
        state: &AppState,
        iss: &str,
        credential_types: &[String],
    ) -> Result<(), AuthError> {
        let list = self
            .trust_list(state)
            .await
            .map_err(AuthError::TrustRegistryUnavailable)?;
        let now = now_secs();
        if credential_types.is_empty() {
            let trusted_for_something = list.registry().get(iss).is_some_and(|record| {
                record
                    .credential_types
                    .iter()
                    .any(|t| list.check(iss, t, now).trusted)
            });
            return if trusted_for_something {
                Ok(())
            } else {
                Err(AuthError::UntrustedIssuer(iss.to_string()))
            };
        }
        for credential_type in credential_types {
            let decision = list.check(iss, credential_type, now);
            if !decision.trusted {
                return Err(AuthError::NotTrustedForType {
                    issuer: iss.to_string(),
                    credential_type: credential_type.clone(),
                    reason: decision.reason.unwrap_or_default(),
                });
            }
        }
        Ok(())
    }
}

/// The "Verify Trust" step for `iss` and the credential types at stake:
/// the registry when one is configured, otherwise the static
/// `--trusted-issuer-did` list (which ignores the types).
pub async fn check_issuer(
    state: &AppState,
    iss: &str,
    credential_types: &[String],
) -> Result<(), AuthError> {
    #[cfg(feature = "trusted-issuers-registry")]
    if let Some(registry) = &state.registry_trust {
        return registry.check(state, iss, credential_types).await;
    }
    #[cfg(not(feature = "trusted-issuers-registry"))]
    let _ = credential_types;
    check_trusted_issuer(
        &serde_json::json!({ "iss": iss }),
        &state.config.trusted_issuer_dids,
    )
}

/// Whether issuers are trusted through a registry (so each delivered
/// credential's own issuer is checked too); always `false` without the
/// `trusted-issuers-registry` feature.
pub fn registry_configured(state: &AppState) -> bool {
    #[cfg(feature = "trusted-issuers-registry")]
    return state.registry_trust.is_some();
    #[cfg(not(feature = "trusted-issuers-registry"))]
    {
        let _ = state;
        false
    }
}

#[cfg(feature = "trusted-issuers-registry")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_are_refreshed_after_a_quarter_of_their_lifetime() {
        // A 600 s snapshot fetched at its issue time.
        assert!(!needs_refresh(1000, 1000, 1600, 1149));
        assert!(needs_refresh(1000, 1000, 1600, 1150));
        // Fetched late (from a cache): still at most a quarter after the fetch,
        // and never closer than the margin to its expiry.
        assert!(!needs_refresh(1500, 1000, 1600, 1500));
        assert!(needs_refresh(1500, 1000, 1600, 1600 - REFRESH_MARGIN_SECS));
        // Expired.
        assert!(needs_refresh(1000, 1000, 1600, 2000));
    }
}
