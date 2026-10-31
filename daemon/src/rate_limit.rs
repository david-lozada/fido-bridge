use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Sliding-window rate limiter for authentication attempts.
pub struct RateLimiter {
    window: Duration,
    max: usize,
    hits: VecDeque<Instant>,
    outstanding: bool,
}

impl RateLimiter {
    pub fn new(max_per_window: usize, window: Duration) -> Self {
        Self {
            window,
            max: max_per_window,
            hits: VecDeque::new(),
            outstanding: false,
        }
    }

    pub fn default_auth() -> Self {
        Self::new(30, Duration::from_secs(5 * 60))
    }

    fn prune(&mut self) {
        let cutoff = Instant::now() - self.window;
        while self.hits.front().is_some_and(|t| *t < cutoff) {
            self.hits.pop_front();
        }
    }

    pub fn has_outstanding(&self) -> bool {
        self.outstanding
    }

    pub fn begin(&mut self) -> Result<(), ()> {
        self.prune();
        if self.outstanding {
            return Err(());
        }
        if self.hits.len() >= self.max {
            return Err(());
        }
        self.hits.push_back(Instant::now());
        self.outstanding = true;
        Ok(())
    }

    pub fn end(&mut self) {
        self.outstanding = false;
    }
}
