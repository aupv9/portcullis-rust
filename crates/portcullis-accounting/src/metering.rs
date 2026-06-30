//! The periodic metering loop (TDD §7.6).
//!
//! Every `interval` (default 15 s, matching openNDS's proven cadence) the loop
//! snapshots the [`CounterSource`] and hands the **raw absolute** counters to the
//! [`MeteringSink`]. The accounting crate does NOT compute deltas, re-baseline,
//! or enforce quota — that all lives in the session layer behind `MeteringSink`
//! (TDD §7.6/§7.7). Accounting just reports what conntrack says.
//!
//! Failure behaviour (TDD §11, no fail-open): if the source errors or the sink
//! errors on a tick, we **log and skip** that tick, then keep looping. The
//! kernel set-element `timeout` is the backstop that expires sessions even if
//! accounting is blind, so a stalled counter never strands a client and never
//! crashes the daemon. We never fabricate counters.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use portcullis_types::{CounterSource, MeteringSink};
use tokio::time::{interval_at, Instant, MissedTickBehavior};

/// Default poll cadence (TDD §7.6, `accounting_interval '15'`).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(15);

/// Run the metering loop until `shutdown` resolves.
///
/// - `source`: where raw counters come from (conntrack in prod, mock in tests).
/// - `sink`:   the SessionManager's [`MeteringSink`]; applies deltas + quota.
/// - `interval`: poll cadence; pass [`DEFAULT_INTERVAL`] for the §7.6 default.
/// - `shutdown`: any future; when it resolves the loop returns cleanly.
///
/// The first tick fires immediately so accounting establishes a baseline at
/// startup (the session layer re-baselines from this; it must not assume zero).
pub async fn run_metering_loop<F>(
    source: Arc<dyn CounterSource>,
    sink: Arc<dyn MeteringSink>,
    interval: Duration,
    shutdown: F,
) where
    F: Future<Output = ()>,
{
    // Fire the first tick right away, then every `interval`. If a tick is slow
    // (e.g. a long conntrack dump) we skip missed ticks rather than bursting.
    let mut ticker = interval_at(Instant::now(), interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::debug!("metering loop shutting down");
                return;
            }
            _ = ticker.tick() => {
                meter_once(source.as_ref(), sink.as_ref()).await;
            }
        }
    }
}

/// One iteration: snapshot the source, push to the sink. Errors on either side
/// are logged and swallowed so the loop survives (TDD §11). Factored out so the
/// graceful-skip behaviour is directly testable.
async fn meter_once(source: &dyn CounterSource, sink: &dyn MeteringSink) {
    let snapshot = match source.snapshot().await {
        Ok(s) => s,
        Err(e) => {
            // Counter source unavailable: TTL in the kernel is the backstop.
            // Skip this tick; do not crash, do not fabricate.
            tracing::warn!(error = %e, "counter source error; skipping tick");
            return;
        }
    };

    let n = snapshot.len();
    if let Err(e) = sink.apply_counters(snapshot).await {
        tracing::warn!(error = %e, "metering sink rejected snapshot; skipping tick");
        return;
    }
    tracing::trace!(clients = n, "applied counter snapshot");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockCounterSource;
    use async_trait::async_trait;
    use portcullis_types::{Counters, Error, MacAddr, Result};
    use std::sync::Mutex;
    use tokio::sync::Notify;

    /// Capturing sink: records every snapshot it receives.
    #[derive(Default)]
    struct CapturingSink {
        applied: Mutex<Vec<Vec<(MacAddr, Counters)>>>,
        fail_once: Mutex<bool>,
    }
    #[async_trait]
    impl MeteringSink for CapturingSink {
        async fn apply_counters(&self, snapshot: Vec<(MacAddr, Counters)>) -> Result<()> {
            let mut fail = self.fail_once.lock().unwrap();
            if *fail {
                *fail = false;
                return Err(Error::Other("sink boom".into()));
            }
            self.applied.lock().unwrap().push(snapshot);
            Ok(())
        }
    }

    fn sample() -> Vec<(MacAddr, Counters)> {
        vec![(
            "aa:bb:cc:dd:ee:ff".parse().unwrap(),
            Counters { bytes_in: 100, bytes_out: 50 },
        )]
    }

    #[tokio::test(start_paused = true)]
    async fn loop_applies_snapshot_each_tick_and_stops_on_shutdown() {
        let source = Arc::new(MockCounterSource::constant(sample()));
        let sink = Arc::new(CapturingSink::default());
        let stop = Arc::new(Notify::new());

        let s2 = sink.clone();
        let src2 = source.clone();
        let stop2 = stop.clone();
        let handle = tokio::spawn(async move {
            run_metering_loop(
                src2,
                s2,
                Duration::from_secs(15),
                async move { stop2.notified().await },
            )
            .await;
        });

        // First tick is immediate; advance to let it run.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(16)).await; // second tick
        tokio::time::advance(Duration::from_secs(16)).await; // third tick
        tokio::task::yield_now().await;

        stop.notify_one();
        handle.await.unwrap();

        let applied = sink.applied.lock().unwrap();
        assert!(applied.len() >= 2, "expected several ticks, got {}", applied.len());
        // Each captured snapshot is the raw absolute counters from the source.
        assert_eq!(applied[0], sample());
    }

    #[tokio::test(start_paused = true)]
    async fn source_error_tick_is_skipped_and_loop_continues() {
        let source = Arc::new(MockCounterSource::default());
        // tick 1: ok, tick 2: error, tick 3: ok (then exhausted -> repeats last)
        source.push_snapshot(sample());
        source.push_error("conntrack unavailable");
        source.push_snapshot(sample());

        let sink = Arc::new(CapturingSink::default());
        let stop = Arc::new(Notify::new());

        let s2 = sink.clone();
        let src2 = source.clone();
        let stop2 = stop.clone();
        let handle = tokio::spawn(async move {
            run_metering_loop(
                src2,
                s2,
                Duration::from_secs(15),
                async move { stop2.notified().await },
            )
            .await;
        });

        tokio::task::yield_now().await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(16)).await;
            tokio::task::yield_now().await;
        }
        stop.notify_one();
        handle.await.unwrap();

        // The error tick produced no apply, but the loop kept going and applied
        // the surrounding good ticks. It must have called snapshot at least 3x
        // (proving it did not stop on the error) and applied at least twice.
        assert!(source.call_count() >= 3, "loop stopped early: {}", source.call_count());
        assert!(
            sink.applied.lock().unwrap().len() >= 2,
            "good ticks should still apply despite the error tick"
        );
    }

    #[tokio::test]
    async fn sink_error_is_swallowed() {
        let source = MockCounterSource::constant(sample());
        let sink = CapturingSink::default();
        *sink.fail_once.lock().unwrap() = true;

        // Single iteration: sink fails, must not panic / propagate.
        meter_once(&source, &sink).await;
        assert!(sink.applied.lock().unwrap().is_empty());

        // Next iteration succeeds.
        meter_once(&source, &sink).await;
        assert_eq!(sink.applied.lock().unwrap().len(), 1);
    }
}
