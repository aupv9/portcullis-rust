//! `portcullis-nft` — the **only** crate that touches netfilter (TDD §6).
//!
//! It provides:
//! - [`FirewallBackend`]: the narrow, object-safe port over netfilter, plus an
//!   in-memory [`MockBackend`] for unit tests / host smoke runs (§5.5, §7.9).
//! - [`ruleset`]: a pure builder for the base `table inet wifihub` ruleset as
//!   `nft -j` JSON and an equivalent script (§7.1).
//! - [`NftJsonBackend`]: the production adapter that drives `nft -j` via
//!   `tokio::process::Command` (§5.5).
//! - The single-owner [writer actor](writer): [`WriterHandle`] (which implements
//!   [`portcullis_types::RulesetWriter`]) and [`spawn`] serialize all mutations
//!   and never fail open (§7.9, §11).
//!
//! Everything here imports shared types from `portcullis_types`; this crate
//! never redefines the contract.

#![forbid(unsafe_code)]

pub mod backend;
pub mod nftables_json;
pub mod ruleset;
pub mod writer;

pub use backend::{FirewallBackend, MockBackend, MockOp};
pub use nftables_json::{parse_auth_set, NftJsonBackend};
pub use ruleset::{build_base_ruleset, build_base_script};
pub use writer::{spawn, spawn_with_capacity, WriterHandle};
