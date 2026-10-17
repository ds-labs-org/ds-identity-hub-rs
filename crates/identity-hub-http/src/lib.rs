//! axum HTTP surface for `ds-identity-hub-rs`. See `../../ARCHITECTURE.md`
//! for scope, and `tests/dcp_tck.rs` for the real, official `dcp-tck`
//! conformance test this crate is checked against.

mod admin;
pub mod auth;
pub mod config;
mod handlers;
pub mod issuer;
pub mod oid4vci;
pub mod outbound;
pub mod registry_trust;
pub mod state;
pub mod validation;

use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;

pub use config::{Config, Mode};
pub use state::AppState;

/// Builds the full application: state plus router, not yet bound to a
/// socket.
pub fn build(config: Config) -> (Arc<AppState>, Router) {
    let state = Arc::new(AppState::new(config));
    let router = handlers::router(state.clone());
    (state, router)
}

/// Builds the Issuer Admin API router (see `admin`), to be served on its
/// own listener (`Config::admin_bind`). `None` - no admin surface at all -
/// unless this is an Issuer Service *and* a non-empty admin token is
/// configured: deny by default.
pub fn build_admin(state: &Arc<AppState>) -> Option<Router> {
    let has_token = state
        .config
        .admin_token
        .as_deref()
        .is_some_and(|t| !t.is_empty());
    (state.mode() == Mode::IssuerService && has_token).then(|| admin::router(state.clone()))
}

/// Binds `config.bind_addr` and serves `router` until the process is
/// stopped (or, in a test, until the returned future is dropped/aborted).
pub async fn serve(config: &Config, router: Router) -> std::io::Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, router).await
}
