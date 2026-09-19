//! Domain types for `ds-identity-hub-rs`: DID document / service-identity
//! construction, DCP wire-message shapes for the Verifiable Presentation
//! Protocol and Credential Issuance Protocol, an in-memory accepted-
//! credential store, a scope-to-credential-type matcher, and a minimal
//! in-memory Secure Token Service. Built on
//! [`ds-dcp-core-rs`](https://github.com/ds-labs-org/ds-dcp-core-rs)'s
//! role-agnostic compact-JWS and `did:web` primitives (re-exported here as
//! `dcp_core`, matching that crate's own `[lib] name`).
//!
//! See `../../ARCHITECTURE.md` for what this bootstrap implements, stubs,
//! and leaves out of scope.

pub mod identity;
pub mod messages;
pub mod scope;
pub mod store;
pub mod sts;

/// Re-exported so downstream crates (`identity-hub-http`) depend on this
/// crate alone for both the domain types defined here and the primitives
/// they're built on.
pub use dcp_core;
