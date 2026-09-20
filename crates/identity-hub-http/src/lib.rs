//! axum HTTP surface for `ds-identity-hub-rs`. See `../../ARCHITECTURE.md`
//! for scope, and `tests/dcp_tck.rs` for the real, official `dcp-tck`
//! conformance test this crate is checked against.

pub mod auth;
pub mod config;
mod handlers;
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

/// Binds `config.bind_addr` and serves `router` until the process is
/// stopped (or, in a test, until the returned future is dropped/aborted).
pub async fn serve(config: &Config, router: Router) -> std::io::Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, router).await
}
