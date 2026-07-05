//! mTLS configuration and the gRPC transport builders (TDD §13).
//!
//! ## Connection direction (CGNAT)
//! Sites sit behind carrier-grade NAT, so the engine cannot be reached inbound.
//! The engine is therefore the gRPC **client**: [`client_tls_config`] +
//! [`connect`] dial the control plane over mutual TLS and the
//! [`crate::channel`] driver holds the long-lived `Connect` bidi stream. The
//! server helpers ([`tls_config`], [`serve`]) are retained for the on-net/dev
//! unary path only.
//!
//! ## Auth model — mTLS is the gate
//! Reachability is not the authorization gate; **mutual TLS** is. When dialing,
//! the engine presents its per-store **client** certificate and verifies the
//! control plane's **server** certificate against a pinned CA
//! ([`client_tls_config`]). When serving (dev path), [`tls_config`] installs a
//! client-CA root via [`ServerTlsConfig::client_ca_root`], making a client
//! certificate mandatory. Either way, a peer without a valid cert chaining to
//! the expected CA is rejected at the TLS handshake.
//!
//! Cert/key material is provisioned per store at first boot (never baked into
//! the `.ipk`); files must be `0600` and owned by the daemon user (§13).

use std::time::Duration;

use portcullis_types::{Error, Result};
use tonic::transport::server::Router;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};

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
/// On-net / dev entrypoint (the production path is the engine dialing out via
/// [`connect`]). It binds a socket, so it is exercised by integration/E2E rather
/// than unit tests. Combined with the mandatory client cert from [`tls_config`],
/// a cert-less peer cannot reach enforcement.
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

/// Build a mutual-TLS **client** config for dialing the control plane.
///
/// - `client_cert` / `client_key`: PEM bytes for the engine's own per-store leaf
///   identity (this is what the control plane maps to a `store_id`).
/// - `server_ca`: PEM bytes of the CA that signs the control plane's server
///   cert; the engine verifies the CP against it. Required — refusing to build
///   without it avoids silently trusting any server (a fail-open auth hole).
/// - `server_name`: expected server name (SNI / cert CN·SAN). When empty, tonic
///   derives it from the endpoint URI.
///
/// Does no I/O and opens no socket; only assembles TLS material.
pub fn client_tls_config(
    client_cert: &[u8],
    client_key: &[u8],
    server_ca: &[u8],
    server_name: &str,
) -> Result<ClientTlsConfig> {
    if client_cert.is_empty() || client_key.is_empty() {
        return Err(Error::Config("client certificate/key must not be empty".into()));
    }
    if server_ca.is_empty() {
        return Err(Error::Config(
            "control-plane server CA is required (refusing to trust any server)".into(),
        ));
    }

    let identity = Identity::from_pem(client_cert, client_key);
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(server_ca))
        .identity(identity);
    if !server_name.trim().is_empty() {
        tls = tls.domain_name(server_name.trim().to_string());
    }
    Ok(tls)
}

/// Dial `endpoint` (e.g. `https://cp.example:8443`) over mutual TLS and return a
/// connected [`Channel`] ready to build an `EnforcementClient` on.
///
/// HTTP/2 keepalive is enabled with `keepalive` and kept alive while idle so the
/// carrier CGNAT mapping for this outbound connection stays fresh; without it a
/// silent idle timeout would drop the control channel with no local signal.
pub async fn connect(
    endpoint: &str,
    tls: ClientTlsConfig,
    keepalive: Duration,
) -> Result<Channel> {
    let ep = Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| Error::Config(format!("invalid control_endpoint '{endpoint}': {e}")))?
        .tls_config(tls)
        .map_err(|e| Error::Config(format!("invalid client TLS config: {e}")))?
        .http2_keep_alive_interval(keepalive)
        .keep_alive_while_idle(true)
        .connect_timeout(Duration::from_secs(10));

    ep.connect()
        .await
        .map_err(|e| Error::ControlPlaneUnreachable(format!("dial {endpoint}: {e}")))
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

    #[test]
    fn client_tls_config_rejects_missing_server_ca() {
        // No fail-open: refuse to dial without a CA to verify the CP against.
        let err = client_tls_config(b"cert", b"key", b"", "cp").unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn client_tls_config_rejects_empty_identity() {
        assert!(client_tls_config(b"", b"key", b"ca", "cp").is_err());
        assert!(client_tls_config(b"cert", b"", b"ca", "cp").is_err());
    }

    #[test]
    fn client_tls_config_builds_with_all_material() {
        assert!(client_tls_config(b"client-cert", b"client-key", b"cp-ca", "cp").is_ok());
        // Empty server_name is allowed (derived from the endpoint by tonic).
        assert!(client_tls_config(b"client-cert", b"client-key", b"cp-ca", "").is_ok());
    }

    #[tokio::test]
    async fn connect_rejects_malformed_endpoint() {
        let tls = client_tls_config(b"c", b"k", b"ca", "cp").unwrap();
        let err = connect("not a url", tls, Duration::from_secs(20)).await.unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }
}
