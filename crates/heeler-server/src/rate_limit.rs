//! Token-bucket rate limiting with bounded memory.
//!
//! Two layers: a per-client bucket keyed by source IP and an optional global
//! bucket. All interval arithmetic uses the monotonic clock (`Instant`),
//! never wall time. Token counts are integers scaled by 10⁶
//! ("micro-tokens") — no floating point in the packet path.
//!
//! Memory is bounded: at most `max_client_entries` client buckets are
//! tracked. When the table is full and expired entries cannot be evicted,
//! new clients are refused (fail closed) — an attacker who fills the table
//! with spoofed sources degrades service for new clients but cannot make
//! Heeler amplify or grow without bound. Idle entries are removed by a
//! periodic [`RateLimiter::sweep`] driven from the server's housekeeping
//! task (a single task, never one per client).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Scaling factor: one request costs 10⁶ micro-tokens.
const MICRO: u64 = 1_000_000;
/// A Kiss-o'-Death is suggested for the first limited packet and then every
/// N-th, so a client hammering the server does not receive a full 1:1
/// stream of KoD responses.
const KOD_INTERVAL: u32 = 8;

/// Limiter settings (see `[rate_limit]` in the configuration).
#[derive(Debug, Clone)]
pub struct RateLimitSettings {
    /// Master switch.
    pub enabled: bool,
    /// Sustained per-client requests per second.
    pub requests_per_second: u32,
    /// Per-client burst size.
    pub burst: u32,
    /// Sustained global requests per second (0 disables the global bucket).
    pub global_requests_per_second: u32,
    /// Global burst size.
    pub global_burst: u32,
    /// Idle entries expire after this duration.
    pub client_entry_ttl: Duration,
    /// Maximum tracked clients.
    pub max_client_entries: usize,
}

/// The outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// Within limits; answer the request.
    Allowed,
    /// The client exceeded its bucket. `send_kod` is true for the first
    /// limited packet and then every 8th, throttling KoD reflection.
    LimitedPerClient {
        /// Whether a RATE Kiss-o'-Death should be sent (policy permitting).
        send_kod: bool,
    },
    /// The global bucket is exhausted. Always a silent drop: KoD under
    /// global overload would answer a flood with a packet per packet.
    LimitedGlobal,
    /// The client table is full and nothing could be evicted; new clients
    /// are refused. Always a silent drop.
    TableFull,
}

struct TokenBucket {
    micro_tokens: u64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst: u32, now: Instant) -> Self {
        Self {
            micro_tokens: u64::from(burst) * MICRO,
            last_refill: now,
        }
    }

    /// Refills for elapsed time and tries to spend one token.
    fn try_take(&mut self, rate_per_second: u32, burst: u32, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        // rate tokens/s == rate micro-tokens/µs; 128-bit to avoid overflow.
        let refill = (elapsed.as_nanos() * u128::from(rate_per_second) / 1000) as u64;
        self.micro_tokens = self
            .micro_tokens
            .saturating_add(refill)
            .min(u64::from(burst) * MICRO);
        if self.micro_tokens >= MICRO {
            self.micro_tokens -= MICRO;
            true
        } else {
            false
        }
    }
}

struct ClientEntry {
    bucket: TokenBucket,
    last_seen: Instant,
    limited_count: u32,
}

struct LimiterState {
    clients: HashMap<IpAddr, ClientEntry>,
    global: TokenBucket,
    last_forced_sweep: Instant,
}

/// The rate limiter. One instance per server; internally synchronised.
pub struct RateLimiter {
    settings: RateLimitSettings,
    state: Mutex<LimiterState>,
}

impl RateLimiter {
    /// Creates a limiter with `now` as the initial monotonic reference.
    #[must_use]
    pub fn new(settings: RateLimitSettings, now: Instant) -> Self {
        let global = TokenBucket::new(settings.global_burst, now);
        Self {
            settings,
            state: Mutex::new(LimiterState {
                clients: HashMap::new(),
                global,
                last_forced_sweep: now,
            }),
        }
    }

    /// Checks one request from `source` at monotonic time `now`.
    pub fn check(&self, source: IpAddr, now: Instant) -> RateDecision {
        if !self.settings.enabled {
            return RateDecision::Allowed;
        }
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if self.settings.global_requests_per_second > 0
            && !state.global.try_take(
                self.settings.global_requests_per_second,
                self.settings.global_burst,
                now,
            )
        {
            return RateDecision::LimitedGlobal;
        }

        if let Some(entry) = state.clients.get_mut(&source) {
            entry.last_seen = now;
            return if entry.bucket.try_take(
                self.settings.requests_per_second,
                self.settings.burst,
                now,
            ) {
                entry.limited_count = 0;
                RateDecision::Allowed
            } else {
                let send_kod = entry.limited_count % KOD_INTERVAL == 0;
                entry.limited_count = entry.limited_count.wrapping_add(1);
                RateDecision::LimitedPerClient { send_kod }
            };
        }

        // New client. Enforce the table bound, evicting expired entries at
        // most once per second so a full table cannot force an O(n) scan
        // per packet.
        if state.clients.len() >= self.settings.max_client_entries {
            if now.saturating_duration_since(state.last_forced_sweep) >= Duration::from_secs(1) {
                state.last_forced_sweep = now;
                let ttl = self.settings.client_entry_ttl;
                state
                    .clients
                    .retain(|_, entry| now.saturating_duration_since(entry.last_seen) < ttl);
            }
            if state.clients.len() >= self.settings.max_client_entries {
                return RateDecision::TableFull;
            }
        }

        // First packet from this client spends one token from a full burst.
        let mut bucket = TokenBucket::new(self.settings.burst, now);
        let allowed = bucket.try_take(self.settings.requests_per_second, self.settings.burst, now);
        state.clients.insert(
            source,
            ClientEntry {
                bucket,
                last_seen: now,
                limited_count: 0,
            },
        );
        debug_assert!(allowed, "a fresh bucket always has a token");
        RateDecision::Allowed
    }

    /// Removes entries idle longer than the TTL. Called from the server's
    /// single housekeeping task.
    pub fn sweep(&self, now: Instant) {
        let ttl = self.settings.client_entry_ttl;
        if let Ok(mut state) = self.state.lock() {
            state
                .clients
                .retain(|_, entry| now.saturating_duration_since(entry.last_seen) < ttl);
        }
    }

    /// Number of currently tracked client entries (for metrics).
    #[must_use]
    pub fn active_entries(&self) -> usize {
        self.state.lock().map(|s| s.clients.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> RateLimitSettings {
        RateLimitSettings {
            enabled: true,
            requests_per_second: 4,
            burst: 8,
            global_requests_per_second: 0,
            global_burst: 0,
            client_entry_ttl: Duration::from_secs(600),
            max_client_entries: 100,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_then_limited() {
        let t0 = Instant::now();
        let limiter = RateLimiter::new(settings(), t0);
        for i in 0..8 {
            assert_eq!(
                limiter.check(ip("10.0.0.1"), t0),
                RateDecision::Allowed,
                "request {i} should pass within burst"
            );
        }
        assert_eq!(
            limiter.check(ip("10.0.0.1"), t0),
            RateDecision::LimitedPerClient { send_kod: true }
        );
        // Subsequent limited packets suppress the KoD until the interval.
        for _ in 0..(KOD_INTERVAL - 1) {
            assert_eq!(
                limiter.check(ip("10.0.0.1"), t0),
                RateDecision::LimitedPerClient { send_kod: false }
            );
        }
        assert_eq!(
            limiter.check(ip("10.0.0.1"), t0),
            RateDecision::LimitedPerClient { send_kod: true }
        );
    }

    #[test]
    fn refill_restores_tokens() {
        let t0 = Instant::now();
        let limiter = RateLimiter::new(settings(), t0);
        for _ in 0..8 {
            limiter.check(ip("10.0.0.1"), t0);
        }
        assert!(matches!(
            limiter.check(ip("10.0.0.1"), t0),
            RateDecision::LimitedPerClient { .. }
        ));
        // After 1 s at 4 req/s, 4 tokens are back.
        let t1 = t0 + Duration::from_secs(1);
        for i in 0..4 {
            assert_eq!(
                limiter.check(ip("10.0.0.1"), t1),
                RateDecision::Allowed,
                "refilled request {i}"
            );
        }
        assert!(matches!(
            limiter.check(ip("10.0.0.1"), t1),
            RateDecision::LimitedPerClient { .. }
        ));
    }

    #[test]
    fn clients_are_independent() {
        let t0 = Instant::now();
        let limiter = RateLimiter::new(settings(), t0);
        for _ in 0..8 {
            limiter.check(ip("10.0.0.1"), t0);
        }
        assert!(matches!(
            limiter.check(ip("10.0.0.1"), t0),
            RateDecision::LimitedPerClient { .. }
        ));
        assert_eq!(limiter.check(ip("10.0.0.2"), t0), RateDecision::Allowed);
        assert_eq!(
            limiter.check(ip("2001:db8::1"), t0),
            RateDecision::Allowed
        );
    }

    #[test]
    fn global_bucket_limits_everything() {
        let mut s = settings();
        s.global_requests_per_second = 2;
        s.global_burst = 2;
        let t0 = Instant::now();
        let limiter = RateLimiter::new(s, t0);
        assert_eq!(limiter.check(ip("10.0.0.1"), t0), RateDecision::Allowed);
        assert_eq!(limiter.check(ip("10.0.0.2"), t0), RateDecision::Allowed);
        assert_eq!(
            limiter.check(ip("10.0.0.3"), t0),
            RateDecision::LimitedGlobal
        );
    }

    #[test]
    fn table_bound_fails_closed_and_recovers_via_ttl() {
        let mut s = settings();
        s.max_client_entries = 2;
        s.client_entry_ttl = Duration::from_secs(10);
        let t0 = Instant::now();
        let limiter = RateLimiter::new(s, t0);
        assert_eq!(limiter.check(ip("10.0.0.1"), t0), RateDecision::Allowed);
        assert_eq!(limiter.check(ip("10.0.0.2"), t0), RateDecision::Allowed);
        assert_eq!(limiter.check(ip("10.0.0.3"), t0), RateDecision::TableFull);
        assert_eq!(limiter.active_entries(), 2);
        // After the TTL the forced sweep frees room for new clients.
        let t1 = t0 + Duration::from_secs(11);
        assert_eq!(limiter.check(ip("10.0.0.3"), t1), RateDecision::Allowed);
    }

    #[test]
    fn sweep_expires_idle_entries() {
        let t0 = Instant::now();
        let limiter = RateLimiter::new(settings(), t0);
        limiter.check(ip("10.0.0.1"), t0);
        limiter.check(ip("10.0.0.2"), t0 + Duration::from_secs(500));
        assert_eq!(limiter.active_entries(), 2);
        limiter.sweep(t0 + Duration::from_secs(700));
        assert_eq!(limiter.active_entries(), 1);
    }

    #[test]
    fn disabled_limiter_allows_everything() {
        let mut s = settings();
        s.enabled = false;
        let t0 = Instant::now();
        let limiter = RateLimiter::new(s, t0);
        for _ in 0..10_000 {
            assert_eq!(limiter.check(ip("10.0.0.1"), t0), RateDecision::Allowed);
        }
        assert_eq!(limiter.active_entries(), 0);
    }

    #[test]
    fn tokens_never_exceed_burst() {
        let t0 = Instant::now();
        let limiter = RateLimiter::new(settings(), t0);
        limiter.check(ip("10.0.0.1"), t0);
        // A long idle period must not accumulate more than `burst` tokens.
        let t1 = t0 + Duration::from_secs(3600);
        let mut allowed = 0;
        for _ in 0..100 {
            if limiter.check(ip("10.0.0.1"), t1) == RateDecision::Allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 8);
    }
}
