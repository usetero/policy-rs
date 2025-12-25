//! Rate limiting for policy evaluation.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// State for a single rate limiter.
#[derive(Debug)]
struct RateLimiterState {
    /// The start of the current window.
    window_start: Instant,
    /// Number of items allowed in the current window.
    count: u64,
    /// Maximum items per window.
    limit: u64,
    /// Window duration.
    window: Duration,
}

impl RateLimiterState {
    fn new(limit: u64, window: Duration) -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
            limit,
            window,
        }
    }

    /// Check if an item should be allowed and update the counter.
    fn check(&mut self) -> bool {
        let now = Instant::now();

        // Check if we need to start a new window
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.count = 0;
        }

        if self.count < self.limit {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

/// Manager for rate limiters across multiple policies.
#[derive(Debug, Default)]
pub struct RateLimiters {
    /// Rate limiter state per policy ID.
    limiters: RwLock<HashMap<String, RateLimiterState>>,
}

impl RateLimiters {
    /// Create a new rate limiter manager.
    pub fn new() -> Self {
        Self {
            limiters: RwLock::new(HashMap::new()),
        }
    }

    /// Check if an item should be allowed for the given policy.
    ///
    /// This will create a new rate limiter if one doesn't exist.
    pub fn check(&self, policy_id: &str, limit: u64, window: Duration) -> bool {
        let mut limiters = self.limiters.write().unwrap();

        let state = limiters
            .entry(policy_id.to_string())
            .or_insert_with(|| RateLimiterState::new(limit, window));

        // Update limit/window if they've changed
        if state.limit != limit || state.window != window {
            *state = RateLimiterState::new(limit, window);
        }

        state.check()
    }

    /// Remove rate limiters for policies that no longer exist.
    pub fn cleanup(&self, active_policy_ids: &[&str]) {
        let mut limiters = self.limiters.write().unwrap();
        limiters.retain(|id, _| active_policy_ids.contains(&id.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiters = RateLimiters::new();
        let window = Duration::from_secs(60);

        // Should allow up to limit
        assert!(limiters.check("policy-1", 3, window));
        assert!(limiters.check("policy-1", 3, window));
        assert!(limiters.check("policy-1", 3, window));

        // Should deny after limit
        assert!(!limiters.check("policy-1", 3, window));
        assert!(!limiters.check("policy-1", 3, window));
    }

    #[test]
    fn rate_limiter_separate_policies() {
        let limiters = RateLimiters::new();
        let window = Duration::from_secs(60);

        // Each policy has its own limit
        assert!(limiters.check("policy-1", 1, window));
        assert!(!limiters.check("policy-1", 1, window));

        assert!(limiters.check("policy-2", 1, window));
        assert!(!limiters.check("policy-2", 1, window));
    }

    #[test]
    fn rate_limiter_cleanup() {
        let limiters = RateLimiters::new();
        let window = Duration::from_secs(60);

        limiters.check("policy-1", 10, window);
        limiters.check("policy-2", 10, window);
        limiters.check("policy-3", 10, window);

        // Cleanup removes inactive policies
        limiters.cleanup(&["policy-1", "policy-3"]);

        let inner = limiters.limiters.read().unwrap();
        assert!(inner.contains_key("policy-1"));
        assert!(!inner.contains_key("policy-2"));
        assert!(inner.contains_key("policy-3"));
    }
}
