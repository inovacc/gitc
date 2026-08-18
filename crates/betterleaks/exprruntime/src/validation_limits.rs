//! Port of Go `internal/exprruntime/validation_limits.go` — the outbound-request
//! governor for secret validation.
//!
//! Validation makes REAL requests to a provider to ask whether a secret is
//! live. A scan of a large monorepo can hold thousands of candidate secrets, so
//! without a governor betterleaks becomes an unintentional load generator
//! pointed at someone else's API — and gets the user rate-limited or blocked.
//! This module is what stops that.
//!
//! Three independent limits, each disabled by a zero value:
//!
//! * **`max_requests_per_target`** — a lifetime budget per target ORIGIN
//!   (`scheme://host[:port]`). Once spent, further requests to that origin are
//!   refused and the finding comes back `needs_validation` with the reason,
//!   rather than silently unvalidated;
//! * **`requests_per_second`** — an aggregate rate across everything;
//! * **`requests_per_second_by_rule`** — an exact per-rule-ID rate that
//!   COMPOSES with the aggregate rather than replacing it.
//!
//! ## Why the scheduler looks like this
//!
//! [`ValidationRequestLimiter::wait`] recomputes from scratch on each pass and
//! reserves nothing ahead. Go's comment says why: reserving a future slot would
//! let one slow rule park a claim on global capacity that unrelated rules could
//! otherwise use. The loop is the price of not having that head-of-line block.
//!
//! ## Time is injected
//!
//! Everything is expressed in nanoseconds from a [`Clock`], so the rate limiter
//! is testable without sleeping through a real second — the same seam the retry
//! client uses. A test that must sleep to prove a rate limit works is a test
//! nobody runs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Go `time.Duration` as nanoseconds, matching the rest of the port.
pub type Nanos = i64;

const NANOS_PER_SECOND: f64 = 1_000_000_000.0;

/// A monotonic clock, injected so the limiter is testable.
pub trait Clock: Send + Sync {
    /// Nanoseconds from an arbitrary fixed origin. Only differences matter.
    fn now_nanos(&self) -> Nanos;
    /// Block for `d`. A test clock advances its virtual time instead.
    fn sleep(&self, d: Duration);
}

/// The real clock.
pub struct SystemClock {
    origin: std::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock {
            origin: std::time::Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now_nanos(&self) -> Nanos {
        self.origin.elapsed().as_nanos() as Nanos
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Go `ValidationRequestLimits`. A zero value disables that limit.
#[derive(Debug, Clone, Default)]
pub struct ValidationRequestLimits {
    pub max_requests_per_target: i64,
    pub requests_per_second: f64,
    pub requests_per_second_by_rule: HashMap<String, f64>,
}

/// Go `ValidationRequestLimitHit` — a request refused before it left the
/// process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationRequestLimitHit {
    pub rule_id: String,
    pub target: String,
    pub max_requests: i64,
    pub requests_sent: i64,
}

impl std::fmt::Display for ValidationRequestLimitHit {
    /// Go `(*ValidationRequestLimitError).Error`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "validation request limit reached for {} ({} requests sent, maximum {})",
            self.target, self.requests_sent, self.max_requests
        )
    }
}

/// Go `validationRequestInterval` — turn a rate into a minimum gap.
///
/// Returns `Ok(0)` for a rate of 0, which means "no limit" and is NOT an error.
/// That distinction is what lets a caller leave one of the three limits unset.
pub fn validation_request_interval(rps: f64) -> Result<Nanos, String> {
    if rps.is_nan() || rps.is_infinite() || rps < 0.0 {
        return Err("must be a finite non-negative number".to_string());
    }
    if rps == 0.0 {
        return Ok(0);
    }
    let seconds = 1.0 / rps;
    if seconds > i64::MAX as f64 / NANOS_PER_SECOND {
        return Err("is too small to represent".to_string());
    }
    let interval = (seconds * NANOS_PER_SECOND) as Nanos;
    if interval <= 0 {
        // Reached when the rate is so large that the gap rounds to zero.
        return Err("is too large to represent".to_string());
    }
    Ok(interval)
}

/// Go `validationRequestLimiter`.
///
/// `Debug` is hand-written because the injected `Box<dyn Clock>` is not
/// `Debug`; without it, `unwrap_err()` on a construction failure will not
/// compile. The counters are summarised rather than dumped — a target map from
/// a real scan is long and says nothing useful in a panic message.
pub struct ValidationRequestLimiter {
    max_requests_per_target: i64,
    global_interval: Nanos,
    rule_intervals: HashMap<String, Nanos>,
    state: Mutex<LimiterState>,
    clock: Box<dyn Clock>,
}

#[derive(Default)]
struct LimiterState {
    requests_by_target: HashMap<String, i64>,
    global_next: Nanos,
    rule_next: HashMap<String, Nanos>,
}

impl std::fmt::Debug for ValidationRequestLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let targets = self
            .state
            .lock()
            .map(|s| s.requests_by_target.len())
            .unwrap_or(0);
        f.debug_struct("ValidationRequestLimiter")
            .field("max_requests_per_target", &self.max_requests_per_target)
            .field("global_interval", &self.global_interval)
            .field("rules_rated", &self.rule_intervals.len())
            .field("targets_seen", &targets)
            .finish()
    }
}

impl ValidationRequestLimiter {
    /// Go `newValidationRequestLimiter`.
    ///
    /// Returns `Ok(None)` when every limit is disabled — Go returns a nil
    /// limiter there, and a nil limiter is the "no governor" fast path. An
    /// empty-but-present limiter would cost a lock per request for nothing.
    pub fn new(
        cfg: &ValidationRequestLimits,
        clock: Box<dyn Clock>,
    ) -> Result<Option<ValidationRequestLimiter>, String> {
        if cfg.max_requests_per_target < 0 {
            return Err("validation maximum requests must be non-negative".to_string());
        }

        let global_interval = validation_request_interval(cfg.requests_per_second)
            .map_err(|e| format!("validation requests per second: {e}"))?;

        let mut rule_intervals = HashMap::new();
        // Sorted so a config with several bad rules reports the same one every
        // run — a HashMap would pick an arbitrary victim.
        let mut raw: Vec<(&String, &f64)> = cfg.requests_per_second_by_rule.iter().collect();
        raw.sort_by(|a, b| a.0.cmp(b.0));
        for (raw_rule_id, rps) in raw {
            let rule_id = raw_rule_id.trim();
            if rule_id.is_empty() {
                return Err("validation rule request rate has an empty rule ID".to_string());
            }
            let interval = validation_request_interval(*rps).map_err(|e| {
                format!("validation requests per second for rule {rule_id:?}: {e}")
            })?;
            if interval == 0 {
                // A per-rule rate of zero would silently mean "unlimited" for
                // that rule, which is the opposite of what someone typing
                // `--validation-rule-rps rule=0` intends.
                return Err(format!(
                    "validation requests per second for rule {rule_id:?} must be greater than zero"
                ));
            }
            rule_intervals.insert(rule_id.to_string(), interval);
        }

        if cfg.max_requests_per_target == 0 && global_interval == 0 && rule_intervals.is_empty() {
            return Ok(None);
        }

        Ok(Some(ValidationRequestLimiter {
            max_requests_per_target: cfg.max_requests_per_target,
            global_interval,
            rule_intervals,
            state: Mutex::new(LimiterState::default()),
            clock,
        }))
    }

    /// Go `wait` — block until both the global and the exact-rule rate have a
    /// slot available NOW.
    ///
    /// Nothing is reserved for the future: a slow rule must not be able to park
    /// a claim on global capacity that unrelated rules could use.
    pub fn wait(&self, rule_id: &str) {
        let rule_interval = self.rule_intervals.get(rule_id).copied().unwrap_or(0);
        if self.global_interval == 0 && rule_interval == 0 {
            return;
        }

        loop {
            let now = self.clock.now_nanos();
            let send_at = {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let mut send_at = now;
                if self.global_interval > 0 && state.global_next > send_at {
                    send_at = state.global_next;
                }
                if rule_interval > 0 {
                    let next = state.rule_next.get(rule_id).copied().unwrap_or(0);
                    if next > send_at {
                        send_at = next;
                    }
                }
                if send_at <= now {
                    if self.global_interval > 0 {
                        state.global_next = now + self.global_interval;
                    }
                    if rule_interval > 0 {
                        state.rule_next.insert(rule_id.to_string(), now + rule_interval);
                    }
                    return;
                }
                send_at
            };

            let gap = (send_at - now).max(0) as u64;
            self.clock.sleep(Duration::from_nanos(gap));
        }
    }

    /// Go `admit` — consume one unit of the target's budget, or report the hit.
    pub fn admit(&self, rule_id: &str, target: &str) -> Option<ValidationRequestLimitHit> {
        if self.max_requests_per_target == 0 {
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = self.limit_hit_locked(&state, rule_id, target) {
            return Some(hit);
        }
        *state.requests_by_target.entry(target.to_string()).or_insert(0) += 1;
        None
    }

    /// Go `limitHit` — check WITHOUT consuming, so the transport can refuse
    /// before it waits out a rate limit it will not be allowed to use.
    pub fn limit_hit(&self, rule_id: &str, target: &str) -> Option<ValidationRequestLimitHit> {
        if self.max_requests_per_target == 0 {
            return None;
        }
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.limit_hit_locked(&state, rule_id, target)
    }

    fn limit_hit_locked(
        &self,
        state: &LimiterState,
        rule_id: &str,
        target: &str,
    ) -> Option<ValidationRequestLimitHit> {
        let sent = state.requests_by_target.get(target).copied().unwrap_or(0);
        if sent >= self.max_requests_per_target {
            return Some(ValidationRequestLimitHit {
                rule_id: rule_id.to_string(),
                target: target.to_string(),
                max_requests: self.max_requests_per_target,
                requests_sent: sent,
            });
        }
        None
    }
}

/// Go `validationRequestTarget` — the ORIGIN a budget is charged against.
///
/// Normalised so that `https://api.example.com`, `https://API.example.com` and
/// `https://api.example.com:443` are one target rather than three, which is
/// what makes a per-target budget mean anything. The default port is dropped
/// for its scheme only.
///
/// Takes the parsed pieces rather than a URL type so this crate needs no URL
/// dependency; the caller already has them.
pub fn validation_request_target(scheme: &str, hostname: &str, port: &str, raw_host: &str) -> String {
    let scheme = scheme.to_lowercase();
    let hostname = hostname.to_lowercase();
    let mut port = port.to_string();
    if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
        port.clear();
    }

    let mut host = hostname.clone();
    if !port.is_empty() {
        host = join_host_port(&hostname, &port);
    } else if hostname.contains(':') {
        // A bare IPv6 literal must be bracketed or the result is ambiguous.
        host = format!("[{hostname}]");
    }
    if host.is_empty() {
        host = raw_host.to_lowercase();
    }
    if scheme.is_empty() {
        return host;
    }
    format!("{scheme}://{host}")
}

/// Go `net.JoinHostPort` — brackets an IPv6 literal, leaves anything else.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Go `validationTimeoutBudget` — provider-active time shared across every hop
/// of ONE redirect chain.
///
/// The subtlety worth keeping: rate-limit WAITING does not consume the budget.
/// Go moves the timeout off `http.Client` for exactly this reason — a client
/// timeout starts before the round trip and would charge queue time to the
/// provider, so a heavily rate-limited scan would time out requests that the
/// provider answered promptly.
pub struct ValidationTimeoutBudget {
    remaining: Mutex<Nanos>,
}

impl ValidationTimeoutBudget {
    pub fn new(timeout: Nanos) -> Option<ValidationTimeoutBudget> {
        if timeout <= 0 {
            return None;
        }
        Some(ValidationTimeoutBudget {
            remaining: Mutex::new(timeout),
        })
    }

    pub fn has_remaining(&self) -> bool {
        *self.remaining.lock().unwrap_or_else(|e| e.into_inner()) > 0
    }

    pub fn remaining(&self) -> Nanos {
        *self.remaining.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Charge `elapsed` to the budget, never below zero (Go's `max(0, ...)`).
    pub fn charge(&self, elapsed: Nanos) {
        let mut remaining = self.remaining.lock().unwrap_or_else(|e| e.into_inner());
        *remaining = (*remaining - elapsed).max(0);
    }
}

#[cfg(test)]
mod tests;
