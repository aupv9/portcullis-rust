//! CP-managed wireless provisioning for the `portcullis` engine (P-W1) — the
//! ISOLATED subsystem that renders an arbitrary set of owned SSIDs from a
//! control-plane push, so one push sets up the network(s) AND (for gated SSIDs)
//! the captive.
//!
//! ## What this crate is (and is NOT)
//! - It renders ONLY sections it owns — every one named `pc_<slug>_*` and stamped
//!   `option owner 'portcullis-wireless'` — NOT arbitrary UCI, NOT an RMS/openwisp
//!   whole-router manager. It NEVER touches `network.lan` / br-lan, admin config,
//!   `wan`, or the enforcement `inet wifihub` table (that lives in
//!   `portcullis-nft`, untouched); a reserved denylist enforces this.
//! - It applies + reloads via explicit-argv shell-out to the on-device
//!   `uci` / `wifi` / `/etc/init.d/*` binaries — NEVER `sh -c` — behind the
//!   [`CommandRunner`] seam so tests assert the exact argv + order.
//!
//! ## Fail-OPEN (the ONE exception)
//! Enforcement is fail-CLOSED; this subsystem is deliberately fail-OPEN. It
//! manages router *config*, not enforcement, and a CGNAT router has no inbound
//! rescue for a bad apply — so every apply is held under a LOCAL commit-confirm
//! watchdog: the control plane must send a confirm within the window or the
//! engine rolls back to the pre-apply snapshot on its own. Kernel-as-truth means
//! a provision fault (or a full daemon crash) never drops an authorized client.
//!
//! ## No flash writes (guardrail)
//! The snapshot + pending marker live under `/tmp/portcullis/provision/` (tmpfs)
//! only — a power cycle wipes them, which is correct (`uci`'s committed state is
//! then the truth and there is no confirm left to honour).
//!
//! ## Shape
//! Mirrors the nft writer actor: a cloneable [`ProvisionHandle`] (implements
//! [`portcullis_types::Provisioner`]) sends commands over an mpsc to one owner
//! task ([`run_provision_subsystem`]); that task emits `WirelessStatus` upward on
//! an mpsc the composition root fans into outbound `EngineFrame`s.

#![forbid(unsafe_code)]

pub mod device_obs;
pub mod handle;
pub mod liveness;
pub mod runner;
pub mod sm;
pub mod uci;

pub use device_obs::{
    run_device_obs_poller, AssocEntry, DEFAULT_DEVICE_POLL_INTERVAL, DEVICE_REPORT_BUFFER,
};
pub use handle::{run_provision_subsystem, run_provision_subsystem_with_policy, ProvisionHandle};
pub use liveness::{
    poll_once, run_liveness_poller, DEFAULT_POLL_INTERVAL, LIVENESS_BUFFER, MIN_POLL_INTERVAL_SECS,
};
pub use runner::{CommandRunner, ProcessRunner};
pub use sm::{derive_gated_from_uci, read_committed_gated, ProvisionMachine, DEFAULT_STATE_DIR};
pub use uci::{parse_gated_bridges_from_uci, render_wireless, validate_wireless, UciCmd};
