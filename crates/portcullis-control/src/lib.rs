//! `portcullis-control` — the tonic gRPC **Enforcement** server (TDD §7.5, §13).
//!
//! This crate is the control-plane edge of the engine. It:
//! - exposes the generated proto contract at [`pb`] (`wifihub.enforcement.v1`);
//! - bridges the wire types <-> `portcullis_types` domain types in [`convert`]
//!   (pure, unit-tested, rejects invalid input — never fails open);
//! - serves the [`pb::enforcement_server::Enforcement`] service via
//!   [`EnforcementService`], backed by an injected `Arc<dyn Enforcer>`;
//! - fans `SessionEvent`s to streaming clients through a **bounded** broadcast,
//!   with [`GrpcEventSink`] implementing `portcullis_types::EventSink` so
//!   `portcullis-session` can emit into it (§11: bounded RAM, slow consumers
//!   drop oldest, enforcement never blocks);
//! - serves over the **WireGuard overlay** ([`transport::serve`]): the server
//!   binds only on the WG interface, and WireGuard's peer authentication +
//!   encryption is the authorization gate (§13). See [`transport`] for why
//!   app-layer mTLS was dropped (no MIPS-capable production crypto provider).
//!
//! The composition root (`portcullis-engined`) constructs the
//! `(EnforcementService, GrpcEventSink)` pair, hands the sink to the session
//! layer, and calls [`transport::serve`] on the WireGuard address.

#![forbid(unsafe_code)]

pub mod pb {
    #![allow(clippy::all)]
    tonic::include_proto!("wifihub.enforcement.v1");
}

pub mod convert;
pub mod service;
pub mod transport;

pub use service::{EnforcementService, GrpcEventSink, DEFAULT_EVENT_BUFFER};
pub use transport::{build_server, serve};
