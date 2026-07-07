//! Per-IP sliding-window rate limiter. `SlidingWindowLimiter` holds the
//! shared state (a `Mutex<HashMap<IpAddr, Vec<Instant>>>`); `check` contains
//! the actual decision logic and takes `now` as a parameter so it is
//! unit-testable without real sleeps.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A simple in-memory sliding-window rate limiter: at most `limit` requests
/// per IP per rolling `window`. Fine for a single-process, self-hosted
/// share server; not meant to survive a restart or scale across processes.
pub struct SlidingWindowLimiter {
    window: Duration,
    limit: u32,
    hits: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl SlidingWindowLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            window,
            limit,
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Records a request from `ip` at the current time and returns whether
    /// it is allowed (true) or should be rejected as over the limit (false).
    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let entry = hits.entry(ip).or_default();
        let allowed = check(entry, now, self.limit, self.window);
        if allowed {
            entry.push(now);
        }
        allowed
    }
}

/// Pure decision: given the timestamps of previous requests in `history`,
/// the current time `now`, the `limit`, and the sliding `window`, returns
/// whether one more request right now would be allowed. Also prunes
/// `history` of entries that have aged out of the window, so the caller's
/// storage does not grow unbounded.
pub fn check(history: &mut Vec<Instant>, now: Instant, limit: u32, window: Duration) -> bool {
    history.retain(|&t| now.duration_since(t) <= window);
    (history.len() as u32) < limit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit() {
        let mut history = Vec::new();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(check(&mut history, now, 5, Duration::from_secs(60)));
            history.push(now);
        }
        // the 6th request within the same instant should be rejected
        assert!(!check(&mut history, now, 5, Duration::from_secs(60)));
    }

    #[test]
    fn old_entries_age_out_of_the_window() {
        let mut history = Vec::new();
        let t0 = Instant::now();
        history.push(t0);
        history.push(t0);
        let later = t0 + Duration::from_secs(120);
        // window is 60s, so both old entries should have aged out by
        // `later`, freeing up the full budget again (and `check` prunes
        // them from `history` as a side effect).
        assert!(check(&mut history, later, 1, Duration::from_secs(60)));
        assert!(history.is_empty(), "aged-out entries should be pruned");
    }

    #[test]
    fn limiter_end_to_end_blocks_after_limit() {
        let limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn limiter_tracks_ips_independently() {
        let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60));
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(limiter.allow(a));
        assert!(!limiter.allow(a));
        // different IP has its own independent budget
        assert!(limiter.allow(b));
    }

    #[test]
    fn zero_limit_always_rejects() {
        let mut history = Vec::new();
        let now = Instant::now();
        assert!(!check(&mut history, now, 0, Duration::from_secs(60)));
    }
}
