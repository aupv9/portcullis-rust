//! Hotspot-network provisioning for the `portcullis` engine (P0.5) — the
//! ISOLATED subsystem that CREATES the hotspot interface enforcement then scopes
//! to, so one control-plane push sets up the network AND the captive.
//!
//! See `docs/design/hotspot-service-plan.md` §P0.5 for the authoritative design.
//!
//! ## What this crate is (and is NOT)
//! - It renders a FIXED allowlist of four owned UCI sections
//!   (`network.br_hotspot`, `network.hotspot`, `wireless.wifi_hotspot`,
//!   `dhcp.hotspot`) — NOT arbitrary UCI, NOT an RMS/openwisp whole-router
//!   manager. It NEVER touches `network.lan` / br-lan, admin config, or the
//!   enforcement `inet wifihub` table (that lives in `portcullis-nft`, untouched).
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
//! task ([`run_provision_subsystem`]); that task emits [`ProvisionStatus`] upward
//! on an mpsc the composition root fans into outbound `EngineFrame`s.

#![forbid(unsafe_code)]

pub mod handle;
pub mod runner;
pub mod sm;
pub mod uci;

pub use handle::{run_provision_subsystem, ProvisionHandle};
pub use runner::{CommandRunner, ProcessRunner};
pub use sm::{ProvisionMachine, DEFAULT_STATE_DIR};
pub use uci::{render_teardown, render_uci, validate, UciCmd, OWNED};
