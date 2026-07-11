//! Per-session byte accounting for the `portcullis` enforcement engine
//! (TDD §7.6, §7.7).
//!
//! This crate implements the [`CounterSource`] port (re-exported from
//! `portcullis-types`) on top of conntrack, runs the periodic metering loop that
//! pushes raw absolute counters into a [`MeteringSink`], and provides the
//! optional Phase-2 bandwidth [`Shaper`].
//!
//! Boundaries (do not blur):
//! - Accounting reports **raw absolute** per-MAC counters. Delta computation,
//!   re-baselining on restart, INTERIM emission and **quota enforcement** all
//!   live in the session layer behind [`MeteringSink`] (TDD §7.6/§7.7).
//! - On a counter-source error the loop logs and skips the tick — it never
//!   crashes the daemon and never fabricates data. The kernel set-element
//!   `timeout` is the backstop that still expires sessions (TDD §11, no
//!   fail-open).
//! - The only kernel-touching parts (`conntrack -L`, `tc`, hostapd via `ubus`)
//!   are behind traits and shell out via `tokio::process::Command`; tests use
//!   mocks.

#![forbid(unsafe_code)]

mod conntrack;
mod deauth;
mod metering;
mod mock;
mod reaper;
mod shaper;

// Re-export the port we implement so downstream code can refer to it via this
// crate, and the sink/resolver ports we consume.
pub use portcullis_types::{
    CounterSource, Deauthenticator, FlowReaper, MeteringSink, NeighResolver, NoopDeauth,
    NoopReaper, NoopShaper, Shaper,
};

pub use conntrack::{parse_conntrack, ConntrackCli, ConntrackReader, ConntrackSource};
pub use deauth::UbusDeauth;
pub use metering::{run_metering_loop, DEFAULT_INTERVAL};
pub use mock::MockCounterSource;
pub use reaper::{reap_orphan_flows, run_reap_loop, ConntrackReaper};
pub use shaper::TcShaper;
