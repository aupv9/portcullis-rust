//! mTLS configuration and the gRPC server builder (TDD §13).
//!
//! ## Auth model — mTLS is the gate, WireGuard is defence in depth
//! The Enforcement service runs over the WireGuard overlay, but reachability on
//! that overlay is **not** the authorization gate. The gate is **mutual TLS**:
//! [`tls_config`] installs a client-CA root via [`ServerTlsConfig::client_ca_root`],
//! which makes tonic *require and verify* a client certificate on every
//! connection. The engine therefore accepts grants only from a peer presenting
//! a certificate chaining to the control-plane CA. A host that merely sits on
//! the WireGuard network but lacks a valid client cert is rejected at the TLS
//! handshake — WireGuard narrows the network, mTLS authenticates the principal.
//!
//! Cert/key material is provisioned per store at first boot (never baked into
//! the `.ipk`); files must be `0600` and owned by the daemon user (§13).

use portcullis_types::{Error, Result};
use tonic::transport::server::Router;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::pb::enforcement_server::{Enforcement, EnforcementServer};

/// Build a mutual-TLS server config.
///
/// - `server_cert` / `server_key`: PEM bytes for the engine's own leaf identity.
/// - `client_ca`: PEM bytes of the CA that signs control-plane client certs.
///   Installing it via `client_ca_root` makes the client certificate
///   **mandatory** — there is no anonymous path.
///
/// Returns a [`ServerTlsConfig`] ready to hand to [`serve`]. This does no I/O
/// and binds no socket; it only parses/assembles the TLS material, so it is
/// cheap and unit-testable (a full cert E2E handshake is out of scope here —
/// see the module test note).
pub fn tls_config(
    server_cert: &[u8],
    server_key: &[u8],
    client_ca: &[u8],
) -> Result<ServerTlsConfig> {
    if server_cert.is_empty() || server_key.is_empty() {
        return Err(Error::Config("server certificate/key must not be empty".into()));
    }
    if client_ca.is_empty() {
        // No client CA => mTLS cannot be enforced. Refuse rather than silently
        // fall back to server-only TLS (that would be a fail-open auth hole).
        return Err(Error::Config(
            "client CA is required for mutual TLS (no anonymous control-plane access)".into(),
        ));
    }

    let identity = Identity::from_pem(server_cert, server_key);
    let client_ca = Certificate::from_pem(client_ca);

    Ok(ServerTlsConfig::new()
        .identity(identity)
        // REQUIRE + verify a client cert chaining to this CA. This is the auth
        // gate; without it tonic would accept any (or no) client cert.
        .client_ca_root(client_ca))
}

/// Assemble a tonic [`Server`] with the given mTLS config and Enforcement
/// service into a ready-to-`serve` [`Router`].
///
/// The caller drives it with `.serve(addr).await`. We return the `Router`
/// rather than awaiting here so the composition root (`portcullis-engined`) can
/// attach graceful-shutdown signals.
///
/// Errors only on TLS-config application; the actual bind/serve happens when
/// the returned future is awaited by the caller.
pub fn build_server<S>(service: S, tls: ServerTlsConfig) -> Result<Router>
where
    S: Enforcement,
{
    let mut server = Server::builder()
        .tls_config(tls)
        .map_err(|e| Error::Config(format!("invalid TLS config: {e}")))?;

    Ok(server.add_service(EnforcementServer::new(service)))
}

/// Bind `addr` and serve `service` over mutual TLS until the process is killed.
///
/// This is the production entrypoint; it binds a socket, so it is exercised by
/// integration/E2E rather than unit tests. The gRPC port must be bound only on
/// the WireGuard interface by the caller's `addr` (§13) — combined with the
/// mandatory client cert from [`tls_config`], an off-overlay or
/// cert-less peer cannot reach enforcement.
pub async fn serve<S>(
    addr: std::net::SocketAddr,
    service: S,
    tls: ServerTlsConfig,
) -> Result<()>
where
    S: Enforcement,
{
    build_server(service, tls)?
        .serve(addr)
        .await
        .map_err(|e| Error::Io(format!("gRPC server error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_rejects_missing_client_ca() {
        // No fail-open: refuse to build a config that would allow anonymous
        // (non-mutually-authenticated) clients.
        let err = tls_config(b"cert", b"key", b"").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn tls_config_rejects_empty_identity() {
        assert!(tls_config(b"", b"key", b"ca").is_err());
        assert!(tls_config(b"cert", b"", b"ca").is_err());
    }

    #[test]
    fn tls_config_builds_with_all_material() {
        // Smoke test: with cert + key + client CA present we get a config back.
        // (PEM bytes here are placeholders — tonic parses lazily at serve time;
        // a full handshake/cert-rejection E2E is out of scope for this unit
        // test and lives in the netns/integration suite.)
        let cfg = tls_config(b"server-cert-pem", b"server-key-pem", b"client-ca-pem");
        assert!(cfg.is_ok());
    }
}
