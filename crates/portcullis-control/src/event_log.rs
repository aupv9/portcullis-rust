//! Bounded, replayable in-RAM event log (at-least-once event delivery, §7.6).
//!
//! Replaces the fire-and-forget broadcast fan-out: every emitted
//! [`SessionEvent`] gets a monotonic sequence number (per engine boot) and is
//! retained in a bounded ring until evicted by newer events. `StreamEvents`
//! subscribers replay from a control-plane-persisted cursor
//! (`StreamReq.resume_after_seq`), so a CP outage shorter than the buffer
//! window loses nothing; a longer one is *detected* (seq gap) instead of
//! silently swallowed.
//!
//! RAM-only by design (§5.4 no-NAND): a daemon restart starts a new `boot_id`
//! epoch and the CP resets its cursor from `GetEngineInfo`.

use std::collections::VecDeque;
use std::sync::Mutex;

use portcullis_types::SessionEvent;
use tokio::sync::watch;

struct Inner {
    /// (seq, event), oldest first. len <= capacity.
    buf: VecDeque<(u64, SessionEvent)>,
    /// Sequence the next pushed event receives (starts at 1).
    next_seq: u64,
}

/// Bounded ring of sequenced events + a watch channel for tailing subscribers.
pub struct EventLog {
    inner: Mutex<Inner>,
    /// Latest assigned seq (0 = none yet). Streams wait on this to tail.
    latest: watch::Sender<u64>,
    boot_id: String,
    capacity: usize,
}

impl EventLog {
    /// `capacity` is the replay depth in events (clamped to >= 1). The
    /// `boot_id` is minted here — random enough to never repeat across
    /// restarts of one router (nanos + pid), without pulling in an RNG dep.
    pub fn new(capacity: usize) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let boot_id = format!("{nanos:x}-{:x}", std::process::id());
        EventLog {
            inner: Mutex::new(Inner { buf: VecDeque::new(), next_seq: 1 }),
            latest: watch::Sender::new(0),
            boot_id,
            capacity: capacity.max(1),
        }
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Append an event, assign its seq, evict the oldest past capacity, wake
    /// tailing streams. Never blocks, never fails (§11).
    pub fn push(&self, event: SessionEvent) -> u64 {
        let seq = {
            let mut inner = self.inner.lock().expect("event log mutex poisoned");
            let seq = inner.next_seq;
            inner.next_seq += 1;
            inner.buf.push_back((seq, event));
            while inner.buf.len() > self.capacity {
                inner.buf.pop_front();
            }
            seq
        };
        self.latest.send_replace(seq);
        seq
    }

    /// Every retained event with seq > `after`, oldest first.
    pub fn snapshot_after(&self, after: u64) -> Vec<(u64, SessionEvent)> {
        let inner = self.inner.lock().expect("event log mutex poisoned");
        inner.buf.iter().filter(|(s, _)| *s > after).cloned().collect()
    }

    /// Oldest retained seq (0 = log empty).
    pub fn oldest_seq(&self) -> u64 {
        let inner = self.inner.lock().expect("event log mutex poisoned");
        inner.buf.front().map(|(s, _)| *s).unwrap_or(0)
    }

    /// Latest assigned seq (0 = nothing emitted this boot).
    pub fn latest_seq(&self) -> u64 {
        *self.latest.borrow()
    }

    /// Watch the latest seq — tailing streams await changes on this.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.latest.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_types::{EventKind, SessionId};

    fn ev(n: u8) -> SessionEvent {
        SessionEvent {
            session_id: SessionId(format!("s-{n}").into()),
            mac: format!("aa:bb:cc:dd:ee:{n:02x}").parse().unwrap(),
            kind: EventKind::Granted,
            bytes_in: 0,
            bytes_out: 0,
            ts_unix: 0,
        }
    }

    #[test]
    fn seq_is_monotonic_from_one() {
        let log = EventLog::new(8);
        assert_eq!(log.latest_seq(), 0);
        assert_eq!(log.oldest_seq(), 0);
        assert_eq!(log.push(ev(1)), 1);
        assert_eq!(log.push(ev(2)), 2);
        assert_eq!(log.latest_seq(), 2);
        assert_eq!(log.oldest_seq(), 1);
    }

    #[test]
    fn eviction_advances_oldest_but_not_seq() {
        let log = EventLog::new(2);
        for n in 1..=5u8 {
            log.push(ev(n));
        }
        assert_eq!(log.latest_seq(), 5);
        assert_eq!(log.oldest_seq(), 4); // 1..3 evicted
        let snap = log.snapshot_after(0);
        assert_eq!(snap.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test]
    fn snapshot_after_filters_by_cursor() {
        let log = EventLog::new(8);
        for n in 1..=4u8 {
            log.push(ev(n));
        }
        let snap = log.snapshot_after(2);
        assert_eq!(snap.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![3, 4]);
        assert!(log.snapshot_after(4).is_empty());
    }

    #[tokio::test]
    async fn subscribe_wakes_on_push() {
        let log = EventLog::new(8);
        let mut rx = log.subscribe();
        log.push(ev(1));
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow_and_update(), 1);
    }
}
