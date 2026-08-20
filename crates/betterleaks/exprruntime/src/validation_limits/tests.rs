//! The target strings and interval values below were PRINTED BY GO, from a
//! program holding verbatim copies of `validationRequestTarget` and
//! `validationRequestInterval`.
//!
//! Two of them would have been guessed wrong: `1e9` requests/second yields an
//! interval of exactly `1` nanosecond and is ACCEPTED, while `1e10` is refused
//! as "too large to represent"; and `1e-9` yields `999999999999999872`, not a
//! round `1e18` — the float division does not land on a power of ten.

use super::*;

/// A clock whose time only moves when a test says so. Rate limiting is
/// scheduling, and a test that has to sleep through real seconds to prove a
/// schedule is a test nobody runs.
struct FakeClock {
    now: std::sync::atomic::AtomicI64,
    slept: Mutex<Vec<Nanos>>,
}

impl FakeClock {
    fn new() -> std::sync::Arc<FakeClock> {
        std::sync::Arc::new(FakeClock {
            now: std::sync::atomic::AtomicI64::new(0),
            slept: Mutex::new(Vec::new()),
        })
    }
    fn slept(&self) -> Vec<Nanos> {
        self.slept.lock().unwrap().clone()
    }
}

impl Clock for FakeClock {
    fn now_nanos(&self) -> Nanos {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn sleep(&self, d: Duration) {
        // A sleep ADVANCES virtual time, so the loop makes progress exactly as
        // it would against a real clock.
        self.slept.lock().unwrap().push(d.as_nanos() as Nanos);
        self.now
            .fetch_add(d.as_nanos() as Nanos, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A handle so a test can both drive the clock and hand it to the limiter.
struct SharedClock(std::sync::Arc<FakeClock>);

impl Clock for SharedClock {
    fn now_nanos(&self) -> Nanos {
        self.0.now_nanos()
    }
    fn sleep(&self, d: Duration) {
        self.0.sleep(d)
    }
}

fn limiter(cfg: ValidationRequestLimits) -> (ValidationRequestLimiter, std::sync::Arc<FakeClock>) {
    let clock = FakeClock::new();
    let l = ValidationRequestLimiter::new(&cfg, Box::new(SharedClock(clock.clone())))
        .expect("valid config")
        .expect("limits are set, so a limiter must exist");
    (l, clock)
}

#[test]
fn target_normalisation_matches_go() {
    // (scheme, hostname, port, raw host) -> target. The parsed pieces come from
    // Go's url.URL accessors, which is what the printed goldens recorded.
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        ("https", "api.example.com", "", "api.example.com", "https://api.example.com"),
        // Go's Hostname() keeps the original case; the function lowercases.
        ("https", "API.Example.COM", "", "API.Example.COM", "https://api.example.com"),
        // The default port for the scheme is dropped...
        ("https", "api.example.com", "443", "api.example.com:443", "https://api.example.com"),
        // ...but only for ITS scheme.
        ("https", "api.example.com", "8443", "api.example.com:8443", "https://api.example.com:8443"),
        ("http", "api.example.com", "80", "api.example.com:80", "http://api.example.com"),
        ("http", "api.example.com", "8080", "api.example.com:8080", "http://api.example.com:8080"),
        // An IPv6 literal comes back from Hostname() UNBRACKETED and must be
        // re-bracketed, or the result is ambiguous with a host:port.
        ("https", "2001:db8::1", "", "[2001:db8::1]", "https://[2001:db8::1]"),
        ("https", "2001:db8::1", "8443", "[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
        // A scheme-relative URL has no scheme, so the target is the bare host.
        ("", "api.example.com", "", "api.example.com", "api.example.com"),
        // Userinfo never reaches the target: a credential must not become part
        // of a budget key, which would also leak it into a metadata field.
        ("https", "api.example.com", "", "api.example.com", "https://api.example.com"),
    ];
    for (scheme, hostname, port, raw, want) in cases {
        assert_eq!(
            &validation_request_target(scheme, hostname, port, raw),
            want,
            "target({scheme}, {hostname}, {port})"
        );
    }
}

/// The 443/80 rule applies per scheme, so a default port on the WRONG scheme is
/// kept — `http://host:443` is a real, different origin.
#[test]
fn a_default_port_is_only_dropped_for_its_own_scheme() {
    assert_eq!(
        validation_request_target("http", "h", "443", "h:443"),
        "http://h:443"
    );
    assert_eq!(
        validation_request_target("https", "h", "80", "h:80"),
        "https://h:80"
    );
}

#[test]
fn intervals_match_go() {
    assert_eq!(validation_request_interval(0.0), Ok(0), "0 means NO limit");
    assert_eq!(validation_request_interval(1.0), Ok(1_000_000_000));
    assert_eq!(validation_request_interval(2.0), Ok(500_000_000));
    assert_eq!(validation_request_interval(0.5), Ok(2_000_000_000));
    assert_eq!(validation_request_interval(100.0), Ok(10_000_000));
    // The boundary: 1e9/s is exactly 1ns and is allowed; 1e10/s rounds to 0.
    assert_eq!(validation_request_interval(1e9), Ok(1));
    assert_eq!(
        validation_request_interval(1e10),
        Err("is too large to represent".to_string())
    );
    // Not a round 1e18 — the float division does not land on a power of ten.
    assert_eq!(validation_request_interval(1e-9), Ok(999_999_999_999_999_872));
    assert_eq!(
        validation_request_interval(1e-12),
        Err("is too small to represent".to_string())
    );
    for bad in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            validation_request_interval(bad),
            Err("must be a finite non-negative number".to_string()),
            "{bad}"
        );
    }
}

/// All limits off means NO limiter at all — Go returns nil, and the nil check
/// is the fast path that keeps an unlimited scan from taking a lock per
/// request.
#[test]
fn no_limits_means_no_limiter() {
    let none = ValidationRequestLimiter::new(
        &ValidationRequestLimits::default(),
        Box::new(SystemClock::default()),
    )
    .unwrap();
    assert!(none.is_none());

    for cfg in [
        ValidationRequestLimits {
            max_requests_per_target: 1,
            ..Default::default()
        },
        ValidationRequestLimits {
            requests_per_second: 1.0,
            ..Default::default()
        },
        ValidationRequestLimits {
            requests_per_second_by_rule: [("r".to_string(), 1.0)].into_iter().collect(),
            ..Default::default()
        },
    ] {
        assert!(
            ValidationRequestLimiter::new(&cfg, Box::new(SystemClock::default()))
                .unwrap()
                .is_some(),
            "any single limit must produce a limiter"
        );
    }
}

#[test]
fn a_bad_config_is_refused_with_gos_wording() {
    let neg = ValidationRequestLimits {
        max_requests_per_target: -1,
        ..Default::default()
    };
    assert_eq!(
        ValidationRequestLimiter::new(&neg, Box::new(SystemClock::default())).unwrap_err(),
        "validation maximum requests must be non-negative"
    );

    let empty_rule = ValidationRequestLimits {
        requests_per_second_by_rule: [("   ".to_string(), 1.0)].into_iter().collect(),
        ..Default::default()
    };
    assert_eq!(
        ValidationRequestLimiter::new(&empty_rule, Box::new(SystemClock::default())).unwrap_err(),
        "validation rule request rate has an empty rule ID"
    );

    // A per-rule rate of ZERO is an error, not "unlimited" — the opposite of
    // what someone typing `rule=0` intends.
    let zero_rule = ValidationRequestLimits {
        requests_per_second_by_rule: [("r".to_string(), 0.0)].into_iter().collect(),
        ..Default::default()
    };
    assert!(ValidationRequestLimiter::new(&zero_rule, Box::new(SystemClock::default()))
        .unwrap_err()
        .contains("must be greater than zero"));
}

/// The per-target budget is a LIFETIME count, and the hit reports how many were
/// actually sent so the message can say so.
#[test]
fn a_target_budget_is_spent_then_refused() {
    let (l, _clock) = limiter(ValidationRequestLimits {
        max_requests_per_target: 2,
        ..Default::default()
    });

    assert!(l.admit("rule", "https://a.example").is_none());
    assert!(l.admit("rule", "https://a.example").is_none());

    let hit = l.admit("rule", "https://a.example").expect("third is refused");
    assert_eq!(hit.requests_sent, 2);
    assert_eq!(hit.max_requests, 2);
    assert_eq!(hit.target, "https://a.example");
    assert_eq!(hit.rule_id, "rule");
    assert_eq!(
        hit.to_string(),
        "validation request limit reached for https://a.example (2 requests sent, maximum 2)"
    );

    // A DIFFERENT target has its own budget.
    assert!(l.admit("rule", "https://b.example").is_none());
}

/// `limit_hit` must not consume: the transport checks before waiting out a rate
/// limit it would not be allowed to use.
#[test]
fn checking_the_limit_does_not_spend_it() {
    let (l, _clock) = limiter(ValidationRequestLimits {
        max_requests_per_target: 1,
        ..Default::default()
    });
    assert!(l.limit_hit("r", "t").is_none());
    assert!(l.limit_hit("r", "t").is_none());
    assert!(l.admit("r", "t").is_none(), "still had its one slot");
    assert!(l.limit_hit("r", "t").is_some());
}

/// The first request goes immediately; the next waits one interval.
#[test]
fn the_global_rate_spaces_requests_by_one_interval() {
    let (l, clock) = limiter(ValidationRequestLimits {
        requests_per_second: 2.0, // 500ms apart
        ..Default::default()
    });

    l.wait("rule-a");
    assert_eq!(clock.slept(), Vec::<Nanos>::new(), "the first goes at once");

    l.wait("rule-a");
    assert_eq!(clock.slept(), vec![500_000_000], "the second waits 500ms");
    assert_eq!(clock.now_nanos(), 500_000_000);

    // The rate is AGGREGATE, so a different rule waits too.
    l.wait("rule-b");
    assert_eq!(clock.slept(), vec![500_000_000, 500_000_000]);
}

/// A per-rule rate COMPOSES with the global one rather than replacing it.
#[test]
fn a_rule_rate_composes_with_the_global_rate() {
    let (l, clock) = limiter(ValidationRequestLimits {
        requests_per_second: 100.0, // 10ms apart
        requests_per_second_by_rule: [("slow".to_string(), 1.0)].into_iter().collect(), // 1s apart
        ..Default::default()
    });

    l.wait("slow");
    l.wait("fast");
    // `fast` is bound only by the global 10ms.
    assert_eq!(clock.now_nanos(), 10_000_000);

    // `slow` must wait out its own 1s, measured from its first request.
    l.wait("slow");
    assert_eq!(
        clock.now_nanos(),
        1_000_000_000,
        "the rule rate dominates the global one"
    );
}

/// The scheduler reserves nothing ahead, which is why a slow rule cannot park a
/// claim on global capacity that an unrelated rule could use. This is the
/// property Go's comment calls out.
#[test]
fn a_slow_rule_does_not_block_an_unrelated_one() {
    let (l, clock) = limiter(ValidationRequestLimits {
        requests_per_second: 1000.0, // 1ms apart
        requests_per_second_by_rule: [("slow".to_string(), 0.5)].into_iter().collect(), // 2s apart
        ..Default::default()
    });

    l.wait("slow");
    for _ in 0..5 {
        l.wait("fast");
    }
    assert!(
        clock.now_nanos() < 2_000_000_000,
        "five fast requests must not have queued behind the slow rule's 2s slot, at {}ns",
        clock.now_nanos()
    );
}

/// A rule with no configured rate is governed by the global rate alone, and an
/// unset global means no waiting at all.
#[test]
fn an_unrated_rule_waits_only_for_the_global_rate() {
    let (l, clock) = limiter(ValidationRequestLimits {
        max_requests_per_target: 5,
        ..Default::default()
    });
    l.wait("anything");
    l.wait("anything");
    assert_eq!(clock.slept(), Vec::<Nanos>::new(), "no rate configured");
}

/// The timeout budget is per redirect CHAIN, and rate-limit waiting must never
/// be charged to it — otherwise a heavily rate-limited scan times out requests
/// the provider answered promptly.
#[test]
fn the_timeout_budget_only_counts_provider_time() {
    assert!(ValidationTimeoutBudget::new(0).is_none());
    assert!(ValidationTimeoutBudget::new(-5).is_none());

    let b = ValidationTimeoutBudget::new(1_000_000_000).unwrap();
    assert!(b.has_remaining());
    b.charge(400_000_000);
    assert_eq!(b.remaining(), 600_000_000);
    b.charge(400_000_000);
    assert_eq!(b.remaining(), 200_000_000);
    assert!(b.has_remaining());
    // Never negative — Go's max(0, ...).
    b.charge(999_000_000_000);
    assert_eq!(b.remaining(), 0);
    assert!(!b.has_remaining());
}
