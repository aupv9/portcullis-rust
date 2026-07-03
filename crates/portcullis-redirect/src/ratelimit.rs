//! Per-source token-bucket rate limiting (TDD §13: "rate-limit per source MAC").
//!
//! The redirect responder is reachable by any unauthenticated client, so a
//! single host hammering `:8080` must not be able to drive unbounded `ip neigh`
//! fork/execs or CPU. This is a simple in-memory token bucket keyed by source
//! IP (we rate-limit *before* the neigh lookup, so the MAC isn't known yet — IP
//! is the only key available at admission, and it's the same scarce resource).
//!
//! Bounded by design:
//! * the map is capped at `max_keys`; once full, *new* keys are admitted at a
//!   degraded fixed allowance rather than letting an attacker spraying random
//!   source IPs grow the map without limit (anti-memory-exhaustion);
//! * idle buckets are pruned opportunistically.
//!
//! Time is injected (`now`) so the logic is deterministic and unit-testable
//! without sleeping. The struct is `Send + Sync` via an internal `Mutex`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Configuration for the bucket. `capacity` tokens, refilled at
/// `refill_per_sec`, one token spent per admitted request.
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub capacity: f64,
    pub refill_per_sec: f64,
    /// Hard cap on distinct tracked source IPs (anti-exhaustion).
    pub max_keys: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        // ~5 req burst, 1 req/s sustained — generous for legit CPD probes,
        // crippling for a flood. 10k keys ≈ a busy store's worst case.
        Self { capacity: 5.0, refill_per_sec: 1.0, max_keys: 10_000 }
    }
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token-bucket rate limiter keyed by source IP.
pub struct RateLimiter {
    cfg: RateLimitConfig,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Requests denied by this limiter since boot (any deny path), the
    /// `redirect_rejections_total` counter in `GetMetrics`.
    rejections: AtomicU64,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self { cfg, buckets: Mutex::new(HashMap::new()), rejections: AtomicU64::new(0) }
    }

    /// Count (and report) one denied request.
    fn reject(&self) -> bool {
        self.rejections.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Admit (and charge) one request from `ip` at time `now`. Returns `true`
    /// if allowed, `false` if the source is over its rate.
    ///
    /// `now` is injected for testability; the live caller passes `Instant::now()`
    /// via [`RateLimiter::check`].
    pub fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        // A poisoned mutex (a prior panic while holding it) must fail *closed*:
        // deny rather than propagate a panic up the request path.
        let mut map = match self.buckets.lock() {
            Ok(g) => g,
            Err(_) => return self.reject(),
        };

        // Opportunistic prune of fully-refilled, idle buckets to bound memory.
        if map.len() >= self.cfg.max_keys {
            let cap = self.cfg.capacity;
            let refill = self.cfg.refill_per_sec;
            map.retain(|_, b| {
                let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
                let refilled = (b.tokens + elapsed * refill).min(cap);
                // Drop buckets that have fully refilled (idle clients).
                refilled < cap
            });
        }

        // If still at the cap and this is a brand-new key, deny without
        // inserting — an attacker spraying random IPs can't grow the map.
        if !map.contains_key(&ip) && map.len() >= self.cfg.max_keys {
            return self.reject();
        }

        let bucket = map.entry(ip).or_insert(Bucket { tokens: self.cfg.capacity, last: now });

        // Refill based on elapsed time (saturating: a non-monotonic clock or a
        // future `last` can't produce a negative delta).
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.cfg.refill_per_sec).min(self.cfg.capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            self.reject()
        }
    }

    /// Convenience wrapper using the real clock.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// Current number of tracked keys (for tests / metrics).
    pub fn tracked_keys(&self) -> usize {
        self.buckets.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Total requests this limiter has denied since boot.
    pub fn rejections_total(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allows_burst_then_blocks() {
        let rl = RateLimiter::new(RateLimitConfig { capacity: 3.0, refill_per_sec: 1.0, max_keys: 100 });
        let t0 = Instant::now();
        let a = ip("10.0.0.1");
        assert!(rl.check_at(a, t0));
        assert!(rl.check_at(a, t0));
        assert!(rl.check_at(a, t0));
        // Fourth in the same instant is over capacity.
        assert!(!rl.check_at(a, t0));
    }

    #[test]
    fn rejections_are_counted_across_deny_paths() {
        let rl = RateLimiter::new(RateLimitConfig { capacity: 1.0, refill_per_sec: 0.0, max_keys: 1 });
        let t0 = Instant::now();
        assert_eq!(rl.rejections_total(), 0);

        // Admitted request: not counted.
        assert!(rl.check_at(ip("10.0.0.1"), t0));
        assert_eq!(rl.rejections_total(), 0);

        // Out of tokens: counted.
        assert!(!rl.check_at(ip("10.0.0.1"), t0));
        assert_eq!(rl.rejections_total(), 1);

        // New key past max_keys (anti-spray deny): counted too.
        assert!(!rl.check_at(ip("10.0.0.2"), t0));
        assert_eq!(rl.rejections_total(), 2);
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(RateLimitConfig { capacity: 1.0, refill_per_sec: 1.0, max_keys: 100 });
        let t0 = Instant::now();
        let a = ip("10.0.0.2");
        assert!(rl.check_at(a, t0));
        assert!(!rl.check_at(a, t0));
        // After 1s, one token is back.
        assert!(rl.check_at(a, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn distinct_ips_have_independent_buckets() {
        let rl = RateLimiter::new(RateLimitConfig { capacity: 1.0, refill_per_sec: 0.0, max_keys: 100 });
        let t0 = Instant::now();
        assert!(rl.check_at(ip("10.0.0.1"), t0));
        assert!(rl.check_at(ip("10.0.0.2"), t0));
        assert!(!rl.check_at(ip("10.0.0.1"), t0));
    }

    #[test]
    fn map_is_bounded_against_random_ip_spray() {
        let rl = RateLimiter::new(RateLimitConfig { capacity: 1.0, refill_per_sec: 0.0, max_keys: 4 });
        let t0 = Instant::now();
        // Spray more distinct IPs than max_keys; with refill 0 none free up.
        for i in 0..1000u32 {
            let octets = i.to_be_bytes();
            let addr = IpAddr::from([10, octets[1], octets[2], octets[3]]);
            let _ = rl.check_at(addr, t0);
        }
        assert!(rl.tracked_keys() <= 4, "map grew to {}", rl.tracked_keys());
    }

    #[test]
    fn saturating_clock_does_not_panic() {
        let rl = RateLimiter::new(RateLimitConfig::default());
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(10);
        let a = ip("10.0.0.3");
        // Charge at a later time, then a strictly earlier time (clock went
        // backwards): must not panic or under/overflow.
        assert!(rl.check_at(a, later));
        let _ = rl.check_at(a, t0);
    }
}
