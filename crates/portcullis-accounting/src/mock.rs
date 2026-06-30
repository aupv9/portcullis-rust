//! Test double for [`CounterSource`].
//!
//! Not gated behind `#[cfg(test)]` so other crates' tests (and the engine's
//! integration harness) can wire a deterministic counter source without a kernel.

use std::sync::Mutex;

use async_trait::async_trait;
use portcullis_types::{Counters, Error, MacAddr, Result};

use crate::CounterSource;

/// One programmed reply: either a snapshot to return, or an error to raise.
enum Tick {
    Snapshot(Vec<(MacAddr, Counters)>),
    Err(String),
}

/// A scriptable [`CounterSource`]. Each `snapshot()` consumes the next queued
/// tick; once the script is exhausted it keeps returning the last snapshot
/// (or an empty snapshot if none was ever set). This lets a test drive several
/// loop iterations, including an injected error tick.
pub struct MockCounterSource {
    script: Mutex<std::collections::VecDeque<Tick>>,
    last: Mutex<Vec<(MacAddr, Counters)>>,
    /// Count of snapshot() calls, for assertions.
    calls: Mutex<usize>,
}

impl Default for MockCounterSource {
    fn default() -> Self {
        MockCounterSource {
            script: Mutex::new(Default::default()),
            last: Mutex::new(Vec::new()),
            calls: Mutex::new(0),
        }
    }
}

impl MockCounterSource {
    /// A source that always returns `snapshot` on every tick.
    pub fn constant(snapshot: Vec<(MacAddr, Counters)>) -> Self {
        let m = MockCounterSource::default();
        *m.last.lock().unwrap() = snapshot;
        m
    }

    /// Queue a snapshot to be returned on a future tick.
    pub fn push_snapshot(&self, snapshot: Vec<(MacAddr, Counters)>) {
        self.script.lock().unwrap().push_back(Tick::Snapshot(snapshot));
    }

    /// Queue an error to be returned on a future tick (to exercise graceful skip).
    pub fn push_error(&self, msg: impl Into<String>) {
        self.script.lock().unwrap().push_back(Tick::Err(msg.into()));
    }

    /// How many times `snapshot()` has been called.
    pub fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

#[async_trait]
impl CounterSource for MockCounterSource {
    async fn snapshot(&self) -> Result<Vec<(MacAddr, Counters)>> {
        *self.calls.lock().unwrap() += 1;
        let next = self.script.lock().unwrap().pop_front();
        match next {
            Some(Tick::Snapshot(s)) => {
                *self.last.lock().unwrap() = s.clone();
                Ok(s)
            }
            Some(Tick::Err(m)) => Err(Error::Counter(m)),
            None => Ok(self.last.lock().unwrap().clone()),
        }
    }
}
