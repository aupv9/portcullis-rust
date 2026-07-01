//! The gRPC server builder (TDD §7.5, §13).
//!
//! ## Auth model — WireGuard IS the gate
//! The Enforcement service runs over the WireGuard overlay and reachability on
//! that overlay is the authorization boundary. WireGuard gives mutual
//! authentication (each peer holds the other's public key), confidentiality and
//! integrity between exactly the engine and the control plane. The server binds
//! **only** on the WireGuard interface address (the caller's `addr`), so a host
//! that is not an authenticated WG peer cannot reach enforcement at all.
//!
//! App-layer mTLS was dropped on purpose: rustls' only pure-Rust crypto provider
//! is alpha-grade, and its C/asm providers (`ring`, `aws-lc-rs`) do not build for
//! the MIPS routers in the fleet (RUTM11 = mipsel). WireGuard already provides an
//! authenticated, encrypted channel between the two intended peers, so it is the
//! single, sufficient gate for this point-to-point control link.

use portcullis_types::{Error, Result};
use tonic::transport::server::Router;
use tonic::transport::Server;

use crate::pb::enforcement_server::{Enforcement, EnforcementServer};

/// Assemble a tonic [`Server`] with the Enforcement service into a ready-to-
/// `serve` [`Router`].
///
/// The caller drives it with `.serve(addr).await` so the composition root
/// (`portcullis-engined`) can attach graceful-shutdown signals.
pub fn build_server<S>(service: S) -> Router
where
    S: Enforcement,
{
    Server::builder().add_service(EnforcementServer::new(service))
}

/// Bind `addr` and serve `service` until the process is killed.
///
/// `addr` MUST be the WireGuard interface address (never `0.0.0.0`): reachability
/// over the WG overlay is the authorization gate (§13), so binding on any other
/// interface would expose enforcement to unauthenticated hosts.
pub async fn serve<S>(addr: std::net::SocketAddr, service: S) -> Result<()>
where
    S: Enforcement,
{
    build_server(service)
        .serve(addr)
        .await
        .map_err(|e| Error::Io(format!("gRPC server error: {e}")))
}
