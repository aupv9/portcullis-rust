//! The single-owner writer actor (TDD §7.9).
//!
//! All nftables mutations are serialized through one task that owns the
//! `Box<dyn FirewallBackend>`. Callers hold a cheap [`WriterHandle`] (Clone),
//! send a [`Command`] over an `mpsc`, and await a `oneshot` reply. Because there
//! is exactly one consumer of the channel, every mutation is applied in order
//! and atomically — nft transactions cannot race.
//!
//! No fail-open (G2 / §11): on a backend error the actor retries the operation
//! **once**; if it still fails, the error is propagated as
//! [`Error::NftTransaction`]. The actor never flushes, never silently succeeds.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use portcullis_types::{
    AuthElement, Error, MacAddr, Metric, MetricsSink, NoopMetrics, Result, RulesetWriter,
};
use tokio::sync::{mpsc, oneshot};

use crate::backend::FirewallBackend;

/// Default bound on the command channel. Small: per-store grant/revoke churn is
/// a handful per minute (§14), so a tiny buffer is plenty and keeps RAM low.
const DEFAULT_CHANNEL_CAP: usize = 64;

/// A command sent to the writer actor, carrying its reply channel.
enum Command {
    EnsureBase(oneshot::Sender<Result<()>>),
    AddAuth {
        mac: MacAddr,
        ttl: Duration,
        reply: oneshot::Sender<Result<()>>,
    },
    DelAuth {
        mac: MacAddr,
        reply: oneshot::Sender<Result<()>>,
    },
    ListAuth(oneshot::Sender<Result<Vec<AuthElement>>>),
    SetGatedIfaces {
        ifaces: Vec<String>,
        reply: oneshot::Sender<Result<()>>,
    },
    AddGarden {
        ips: Vec<std::net::IpAddr>,
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Cloneable handle to the writer actor. Implements [`RulesetWriter`].
#[derive(Clone)]
pub struct WriterHandle {
    tx: mpsc::Sender<Command>,
}

impl WriterHandle {
    /// Send a command and await its reply, mapping a dropped actor to an error
    /// (never fail open: a dead writer is a transaction failure).
    async fn call<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T>>) -> Command,
    ) -> Result<T> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(make(reply_tx))
            .await
            .map_err(|_| Error::NftTransaction("writer actor is gone".into()))?;
        reply_rx
            .await
            .map_err(|_| Error::NftTransaction("writer actor dropped reply".into()))?
    }
}

#[async_trait]
impl RulesetWriter for WriterHandle {
    async fn ensure_base(&self) -> Result<()> {
        self.call(Command::EnsureBase).await
    }

    async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()> {
        self.call(|reply| Command::AddAuth { mac, ttl, reply }).await
    }

    async fn del_auth(&self, mac: MacAddr) -> Result<()> {
        self.call(|reply| Command::DelAuth { mac, reply }).await
    }

    async fn list_auth(&self) -> Result<Vec<AuthElement>> {
        self.call(Command::ListAuth).await
    }

    async fn set_gated_ifaces(&self, ifaces: Vec<String>) -> Result<()> {
        self.call(|reply| Command::SetGatedIfaces { ifaces, reply }).await
    }

    async fn add_garden(&self, ips: &[std::net::IpAddr]) -> Result<()> {
        let ips = ips.to_vec();
        self.call(|reply| Command::AddGarden { ips, reply }).await
    }
}

/// Spawn the writer actor over `backend`, returning a [`WriterHandle`] and the
/// actor's `JoinHandle`. The actor runs until all handles are dropped.
pub fn spawn(
    backend: Box<dyn FirewallBackend>,
) -> (WriterHandle, tokio::task::JoinHandle<()>) {
    spawn_full(backend, DEFAULT_CHANNEL_CAP, Arc::new(NoopMetrics))
}

/// As [`spawn`], with an explicit channel capacity.
pub fn spawn_with_capacity(
    backend: Box<dyn FirewallBackend>,
    capacity: usize,
) -> (WriterHandle, tokio::task::JoinHandle<()>) {
    spawn_full(backend, capacity, Arc::new(NoopMetrics))
}

/// As [`spawn`], with a metrics recorder so transaction failures increment
/// `nft_txn_errors_total` (TDD §12).
pub fn spawn_with_metrics(
    backend: Box<dyn FirewallBackend>,
    metrics: Arc<dyn MetricsSink>,
) -> (WriterHandle, tokio::task::JoinHandle<()>) {
    spawn_full(backend, DEFAULT_CHANNEL_CAP, metrics)
}

fn spawn_full(
    backend: Box<dyn FirewallBackend>,
    capacity: usize,
    metrics: Arc<dyn MetricsSink>,
) -> (WriterHandle, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    let actor = WriterActor { backend, rx, metrics };
    let join = tokio::spawn(actor.run());
    (WriterHandle { tx }, join)
}

/// The actor: single owner of the backend, single consumer of the channel.
struct WriterActor {
    backend: Box<dyn FirewallBackend>,
    rx: mpsc::Receiver<Command>,
    metrics: Arc<dyn MetricsSink>,
}

impl WriterActor {
    async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                Command::EnsureBase(reply) => {
                    let r = retry_once(|| self.backend.ensure_base()).await;
                    self.count_err(&r);
                    let _ = reply.send(r);
                }
                Command::AddAuth { mac, ttl, reply } => {
                    let r = retry_once(|| self.backend.add_auth(mac, ttl)).await;
                    self.count_err(&r);
                    let _ = reply.send(r);
                }
                Command::DelAuth { mac, reply } => {
                    let r = retry_once(|| self.backend.del_auth(mac)).await;
                    self.count_err(&r);
                    let _ = reply.send(r);
                }
                Command::ListAuth(reply) => {
                    let r = retry_once(|| self.backend.list_auth()).await;
                    self.count_err(&r);
                    let _ = reply.send(r);
                }
                Command::SetGatedIfaces { ifaces, reply } => {
                    let r = retry_once(|| self.backend.set_gated_ifaces(ifaces.clone())).await;
                    self.count_err(&r);
                    let _ = reply.send(r);
                }
                Command::AddGarden { ips, reply } => {
                    // add_garden is itself fail-open per element (Ok even when an
                    // individual ipset add fails), so retry_once here just covers a
                    // transient whole-call spawn error; a genuine failure is not a
                    // fail-closed enforcement fault.
                    let r = retry_once(|| self.backend.add_garden(&ips)).await;
                    self.count_err(&r);
                    let _ = reply.send(r);
                }
            }
        }
    }

    /// Record a transaction failure (after the single retry) as `nft_txn_errors`.
    fn count_err<T>(&self, r: &Result<T>) {
        if r.is_err() {
            self.metrics.incr(Metric::NftTxnError);
        }
    }
}

/// Run `op` once; on `Err`, retry exactly one more time. If the retry also
/// fails, normalize the error to [`Error::NftTransaction`] and return it
/// (§11: retry once, then propagate — never fail open).
async fn retry_once<T, F, Fut>(mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    match op().await {
        Ok(v) => Ok(v),
        Err(first) => {
            tracing::warn!(
                target: "portcullis_nft",
                error = %first,
                "nft mutation failed; retrying once"
            );
            match op().await {
                Ok(v) => Ok(v),
                Err(second) => Err(Error::NftTransaction(format!(
                    "operation failed after retry: {second}"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{MockBackend, MockOp};
    use std::sync::Arc;

    // We need a shared MockBackend for assertions, but spawn() takes ownership.
    // Wrap it: a thin newtype that delegates to an Arc<MockBackend>.
    struct SharedMock(Arc<MockBackend>);

    #[async_trait]
    impl FirewallBackend for SharedMock {
        async fn ensure_base(&self) -> Result<()> {
            self.0.ensure_base().await
        }
        async fn add_auth(&self, mac: MacAddr, ttl: Duration) -> Result<()> {
            self.0.add_auth(mac, ttl).await
        }
        async fn del_auth(&self, mac: MacAddr) -> Result<()> {
            self.0.del_auth(mac).await
        }
        async fn list_auth(&self) -> Result<Vec<AuthElement>> {
            self.0.list_auth().await
        }
    }

    #[tokio::test]
    async fn grant_records_add_auth() {
        let mock = Arc::new(MockBackend::new());
        let (h, _join) = spawn(Box::new(SharedMock(mock.clone())));
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();

        h.add_auth(mac, Duration::from_secs(1800)).await.unwrap();

        assert_eq!(
            mock.ops(),
            vec![MockOp::AddAuth {
                mac,
                ttl: Duration::from_secs(1800)
            }]
        );
        assert_eq!(mock.auth_len(), 1);
    }

    #[tokio::test]
    async fn revoke_records_del_auth() {
        let mock = Arc::new(MockBackend::new());
        let (h, _join) = spawn(Box::new(SharedMock(mock.clone())));
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();

        h.add_auth(mac, Duration::from_secs(1800)).await.unwrap();
        h.del_auth(mac).await.unwrap();

        assert_eq!(
            mock.ops(),
            vec![
                MockOp::AddAuth { mac, ttl: Duration::from_secs(1800) },
                MockOp::DelAuth { mac },
            ]
        );
        assert_eq!(mock.auth_len(), 0);
    }

    #[tokio::test]
    async fn list_auth_roundtrips_through_actor() {
        let mock = Arc::new(MockBackend::new());
        let (h, _join) = spawn(Box::new(SharedMock(mock.clone())));
        let m1: MacAddr = "00:00:00:00:00:01".parse().unwrap();
        let m2: MacAddr = "00:00:00:00:00:02".parse().unwrap();

        h.ensure_base().await.unwrap();
        h.add_auth(m1, Duration::from_secs(1000)).await.unwrap();
        h.add_auth(m2, Duration::from_secs(2000)).await.unwrap();

        let listed = h.list_auth().await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].mac, m1);
        assert_eq!(listed[1].mac, m2);
        // remaining is roughly the ttl (just set), bounded by it.
        assert!(listed[0].remaining <= Duration::from_secs(1000));
        assert!(listed[1].remaining <= Duration::from_secs(2000));
    }

    #[tokio::test]
    async fn mutations_are_serialized_in_send_order() {
        // Fire many adds concurrently from clones; the actor must apply them
        // one at a time. We assert all landed and the set size is correct.
        let mock = Arc::new(MockBackend::new());
        let (h, _join) = spawn(Box::new(SharedMock(mock.clone())));

        let mut tasks = Vec::new();
        for i in 0..50u8 {
            let h = h.clone();
            tasks.push(tokio::spawn(async move {
                let mac = MacAddr::new([0, 0, 0, 0, 0, i]);
                h.add_auth(mac, Duration::from_secs(60)).await.unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        let ops = mock.ops();
        assert_eq!(ops.len(), 50);
        assert!(ops.iter().all(|o| matches!(o, MockOp::AddAuth { .. })));
        assert_eq!(mock.auth_len(), 50);
    }

    #[tokio::test]
    async fn retry_once_recovers_from_a_single_failure() {
        // Fail exactly once: the op should succeed on the retry.
        let mock = Arc::new(MockBackend::failing(1));
        let (h, _join) = spawn(Box::new(SharedMock(mock.clone())));
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();

        // first add: first attempt fails, retry succeeds.
        h.add_auth(mac, Duration::from_secs(30)).await.unwrap();
        assert_eq!(mock.auth_len(), 1);
    }

    #[tokio::test]
    async fn two_failures_propagate_as_nft_transaction_error() {
        // Fail twice: the op fails on attempt 1 and on the single retry ->
        // error propagates, no fail-open.
        let mock = Arc::new(MockBackend::failing(2));
        let (h, _join) = spawn(Box::new(SharedMock(mock.clone())));
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();

        let err = h.add_auth(mac, Duration::from_secs(30)).await.unwrap_err();
        assert!(matches!(err, Error::NftTransaction(_)), "got {err:?}");
        // Nothing was applied: fail closed.
        assert_eq!(mock.auth_len(), 0);
    }

    #[tokio::test]
    async fn set_gated_ifaces_routes_through_actor() {
        // Confirms the SetGatedIfaces command plumbing (handle -> actor -> backend).
        // The MockBackend uses the FirewallBackend default (no-op Ok).
        let mock = Arc::new(MockBackend::new());
        let (h, _join) = spawn(Box::new(SharedMock(mock.clone())));
        h.set_gated_ifaces(vec!["br-public".to_string()]).await.unwrap();
    }

    #[tokio::test]
    async fn handle_after_actor_drop_errors_not_panics() {
        let mock = Arc::new(MockBackend::new());
        let (h, join) = spawn(Box::new(SharedMock(mock.clone())));
        // Drop our only spawn-side ref by aborting the actor.
        join.abort();
        let _ = join.await;
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        let err = h.add_auth(mac, Duration::from_secs(30)).await.unwrap_err();
        assert!(matches!(err, Error::NftTransaction(_)));
    }
}
