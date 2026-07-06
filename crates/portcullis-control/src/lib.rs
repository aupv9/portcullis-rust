//! `portcullis-control` — the engine's control-plane edge (TDD §7.5, §13).
//!
//! Because sites sit behind carrier-grade NAT the engine is the gRPC **client**:
//! it dials the control plane and holds the long-lived `Attach` bidirectional
//! stream (see `docs/design/cgnat-bidi-control-channel.md`). This crate:
//! - exposes the generated proto contract at [`pb`] (`wifihub.enforcement.v1`);
//! - bridges the wire types <-> `portcullis_types` domain types in [`convert`]
//!   (pure, unit-tested, rejects invalid input — never fails open);
//! - drives the outbound control channel in [`channel`]: dial + reconnect,
//!   dispatch inbound commands to an injected `Arc<dyn Enforcer>`, and pump
//!   `SessionEvent`s back to the control plane;
//! - fans `SessionEvent`s through a **bounded** broadcast, with [`GrpcEventSink`]
//!   implementing `portcullis_types::EventSink` so `portcullis-session` can emit
//!   into it (§11: bounded RAM, slow consumers drop oldest, enforcement never
//!   blocks);
//! - enforces **mutual TLS** ([`transport::client_tls_config`] /
//!   [`transport::connect`]): the engine presents a per-store client cert and
//!   verifies the control plane's server cert against a pinned CA (§13).
//!
//! The [`EnforcementService`] server + [`transport::serve`] are retained for the
//! on-net / dev unary path only.

#![forbid(unsafe_code)]

pub mod pb {
    #![allow(clippy::all)]
    // Generated ahead-of-time by Buf (buf.yaml + buf.gen.yaml at core/portcullis-rust)
    // and committed under src/gen; regenerate with `buf generate`. Only the prost
    // file is included — it self-includes the companion .tonic.rs at its end, so
    // the tonic client/server land in THIS module and their `super::` message
    // references resolve to the prost messages here.
    include!("gen/wifihub.enforcement.v1.rs");
}

pub mod channel;
pub mod convert;
pub mod service;
pub mod transport;

pub use channel::{run as run_control_channel, ControlChannelConfig};
pub use service::{EnforcementService, GrpcEventSink, DEFAULT_EVENT_BUFFER};
pub use transport::{build_server, client_tls_config, connect, serve, tls_config};
