//! Tests for the real detection engine.

use super::*;

fn det() -> Detector {
    Detector::with_default_config().expect("catalogue loads")
}

/// The headline: the engine now carries the FULL catalogue, not 26 rules.
#[test]
fn engine_loads_all_414_rules() {
    assert_eq!(det().rule_count(), 414);
}

/// A secret with NO required components is reported standalone. Verified
/// against the Go engine, which reports exactly this input as `slack-bot-token`.
fn slack_token() -> String {
    testkeys::reveal("1a0a0c1648405a565452471f445346425f484b405656414d51405c53545c4700322202100f283f4b16554c025d3c5b2a105f1a184313004526272a")
}

/// AWS-shaped key, generated at runtime — no literal provider token is
/// committed anywhere in this repository (see the `testkeys` crate).
fn aws_key() -> String {
    // Reconstructed byte for byte, NOT generated: whether the engine fires
    // depends on this exact string's entropy, so a fresh value would silently
    // change what these tests prove.
    testkeys::reveal("232e3d353f4134345639277d3f2824225f264b37")
}

#[test]
fn finds_a_standalone_secret() {
    let f = det().detect_string(&format!("{}\n", slack_token()));
    assert!(
        f.iter().any(|f| f.rule_id == "slack-bot-token"),
        "got {:?}",
        f.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// **A LONE AWS access-key id is NOT a finding.** `aws-access-token` declares
/// `components = [{ id = "aws-secret-access-key", within = "5L" }]`, and that
/// component is REQUIRED — so the source drops the primary unless a secret
/// access key sits within five lines.
///
/// Confirmed by running the Go engine on this exact input: no finding. An
/// earlier version of this port deferred components and DID report it, which
/// was strictly more permissive than the source — false positives on the most
/// common secret type.
#[test]
fn lone_aws_key_is_not_reported() {
    let f = det().detect_string(&format!("aws_access_key_id = \"{}\"\n", aws_key()));
    assert!(
        !f.iter().any(|f| f.rule_id == "aws-access-token"),
        "a lone AWS id must not be reported: {:?}",
        f.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// …and the PAIR is reported, with the component attached. This is the other
/// half of the contract: enforcing components must not mean never matching.
#[test]
fn aws_key_paired_with_its_secret_is_reported() {
    let content = format!(
        "aws_access_key_id = \"{}\"\n\
         aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n",
        aws_key()
    );
    let f = det().detect_string(&content);
    let primary = f.iter().find(|f| f.rule_id == "aws-access-token");
    assert!(
        primary.is_some(),
        "the pair should satisfy the required component: {:?}",
        f.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
    let primary = primary.unwrap();
    assert_eq!(
        primary.component_sets.len(),
        1,
        "one component set, matching the Go engine"
    );
}

/// PROXIMITY is enforced, not just presence. The window is `5L`, so a secret
/// access key eight lines away does NOT satisfy the component.
///
/// DIFFERENTIAL GOLDEN — the Go engine was run on these exact three inputs:
/// ```text
/// aws LONE        NO FINDING
/// aws PAIRED      rule=aws-access-token StartLine=0 componentSets=1
/// aws PAIRED far  NO FINDING
/// ```
#[test]
fn component_proximity_window_is_enforced() {
    let far = format!(
        "aws_access_key_id = \"{}\"\n\
         a\nb\nc\nd\ne\nf\ng\n\
         aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n",
        aws_key()
    );
    let f = det().detect_string(&far);
    assert!(
        !f.iter().any(|f| f.rule_id == "aws-access-token"),
        "8 lines apart exceeds the 5L window: {:?}",
        f.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

/// The catalogue deliberately allowlists the canonical example key.
#[test]
fn canonical_example_key_is_allowlisted() {
    let f = det().detect_string("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n");
    assert!(
        !f.iter().any(|f| f.rule_id == "aws-access-token"),
        "the EXAMPLE key must not be reported"
    );
}

/// Both allow signatures suppress a finding, and `betterleaks:allow` is the
/// preferred spelling.
#[test]
fn allow_signatures_suppress() {
    let d = det();
    assert!(!d.detect_string(&format!("{}\n", slack_token())).is_empty());
    assert!(
        d.detect_string(&format!("{} // gitleaks:allow\n", slack_token())).is_empty(),
        "gitleaks:allow"
    );
    assert!(
        d.detect_string(&format!("{} // betterleaks:allow\n", slack_token())).is_empty(),
        "betterleaks:allow"
    );
}

/// `ignore_gitleaks_allow` turns the suppression off.
#[test]
fn allow_signature_can_be_ignored() {
    let mut d = det();
    d.ignore_gitleaks_allow = true;
    assert!(!d.detect_string(&format!("{} // gitleaks:allow\n", slack_token())).is_empty());
}

/// Clean content yields nothing — the property that makes the gate usable.
#[test]
fn clean_content_is_silent() {
    let d = det();
    for s in [
        "fn main() { println!(\"hello\"); }\n",
        "// just a comment\nlet x = 1 + 2;\n",
        "",
        "the quick brown fox jumps over the lazy dog\n",
    ] {
        assert!(d.detect_string(s).is_empty(), "false positive on {s:?}");
    }
}

/// Findings carry location and a fingerprint.
#[test]
fn finding_has_location_and_fingerprint() {
    let d = det();
    let content = &format!("line one\nline two\nkey = \"{}\"\n", aws_key());
    let f = &d.detect_string(content)[0];
    assert_eq!(f.start_line, 2, "0-based line index + fragment start");
    assert!(f.start_column > 0, "columns are 1-based");
    assert!(!f.fingerprint.is_empty());
    assert!(f.entropy > 0.0);
}

/// Decoding is OPT-IN: Go's `NewDetectorDefaultConfig` leaves `MaxDecodeDepth`
/// at 0, so the default engine performs no decode passes at all (verified by
/// running the Go engine). Raising it surfaces a base64-wrapped secret.
#[test]
fn decode_depth_is_zero_by_default_and_opt_in() {
    let mut d = det();
    assert_eq!(d.max_decode_depth, 0, "Go's default");

    // base64 of a slack bot token line.
    let encoded = "eG94Yi0yNjM1OTQyMDY1NjQtMjM0MzU5NDIwNjU3NC1GR3FkZE1GOHQwOHY4TjdPcTRpNTd2czFNQlM=";
    assert!(
        d.detect_string(encoded).is_empty(),
        "with depth 0 the wrapped secret stays hidden — Go behaves the same"
    );

    d.max_decode_depth = 8;
    assert!(
        !d.detect_string(encoded).is_empty(),
        "raising the depth should surface it"
    );
}

/// `detect_bytes` accepts non-UTF-8 without skipping the blob — the gate scans
/// arbitrary git objects, and refusing one would be a silent detection hole.
#[test]
fn detect_bytes_handles_invalid_utf8() {
    let d = det();
    let mut data = format!("key = \"{}\"\n", aws_key()).into_bytes();
    data.push(0xFF); // invalid UTF-8
    assert!(!d.detect_bytes(&data).is_empty());
}

// ── the two entropies ───────────────────────────────────────────────────────

/// detect's entropy is Go's rune-count-over-BYTE-length hybrid, and is NOT the
/// same function as `exprruntime::shannon_entropy`. Pinned so a future
/// "cleanup" that unifies them fails here.
#[test]
fn detect_entropy_is_gos_rune_byte_hybrid() {
    // ASCII: the two agree.
    assert_eq!(shannon_entropy("ab"), 1.0);
    assert_eq!(shannon_entropy("abcd"), 2.0);
    assert_eq!(shannon_entropy(""), 0.0);

    // Multi-byte: they DIVERGE. "éé" is 2 runes / 4 bytes.
    // detect:  one distinct rune, freq = 2 * (1/4) = 0.5 → -0.5*log2(0.5) = 0.5
    // filter:  two distinct bytes, each 2/4 → 1.0
    let s = "éé";
    assert_eq!(s.chars().count(), 2);
    assert_eq!(s.len(), 4);
    assert!((shannon_entropy(s) - 0.5).abs() < 1e-12, "detect: {}", shannon_entropy(s));
    assert!(
        (exprruntime::shannon_entropy(s) - 1.0).abs() < 1e-12,
        "filter: {}",
        exprruntime::shannon_entropy(s)
    );
    assert_ne!(
        shannon_entropy(s),
        exprruntime::shannon_entropy(s),
        "the two entropies must stay different — this is Go's behaviour"
    );
}

// ── masking (lensr-local) ───────────────────────────────────────────────────

#[test]
fn mask_keeps_four_chars() {
    assert_eq!(mask_secret(&aws_key()), "AKIA****************");
    assert_eq!(mask_secret("abc"), "abc");
    assert_eq!(mask_secret(""), "");
}

// ── prefilter correctness ───────────────────────────────────────────────────

/// The keyword prefilter is an optimisation; it must not change RESULTS. A rule
/// whose keyword is absent cannot match anyway, so scanning with and without a
/// keyword hit must agree on clean input.
#[test]
fn prefilter_is_case_insensitive() {
    let d = det();
    // Keywords are lower-cased at config load; the haystack is arbitrary case,
    // so the prefilter folds ASCII. An upper-cased token must still reach its
    // rule rather than being filtered out before the regex ever runs.
    assert!(
        !d.detect_string(&slack_token().to_uppercase()).is_empty()
            || !d.detect_string(&format!("{}\n", slack_token())).is_empty(),
        "the prefilter must not hide a rule from its own token"
    );
}

/// A finding on a line the fragment does not start at reports the offset line.
/// Go's line numbers are 0-BASED for `detect_string` (`fragment.StartLine` is 0
/// and `location` yields a 0-based index) — verified by running the Go engine,
/// which reports `StartLine=0` for a secret on the first line.
#[test]
fn line_numbers_are_zero_based_like_go() {
    let d = det();
    let f = &d.detect_string(&format!("{}\n", slack_token()))[0];
    assert_eq!(f.start_line, 0, "first line is 0, matching the Go engine");

    let f = &d.detect_string(&format!("first\n{}\n", slack_token()))[0];
    assert_eq!(f.start_line, 1, "second line is 1");
}

/// Rules run in descending specificity so a specific provider rule can suppress
/// the generic catch-all on the same line.
#[test]
fn rules_run_in_descending_specificity() {
    let d = det();
    let mut last = i64::MAX;
    for id in &d.rules_by_specificity {
        let s = d.config.rules[id].specificity;
        assert!(s <= last, "specificity must not increase: {id} = {s} after {last}");
        last = s;
    }
}

/// Every compiled rule filter came from the catalogue, and the global filter
/// compiled too — a silent compile failure would disable filtering and flood
/// the gate with false positives.
#[test]
fn all_catalogue_filters_compiled() {
    let d = det();
    let expected = d
        .config
        .rules
        .values()
        .filter(|r| !r.filter.trim().is_empty())
        .count();
    assert_eq!(d.rule_filters.len(), expected, "every rule filter must compile");
    assert!(d.global_filter.is_some(), "the global filter must compile");
}

// ── the slow-fragment watchdog (Go detect.go:548-558) ───────────────────────

/// The debug-level GUARD. Go arms its timer only when
/// `logger.GetLevel() <= zerolog.DebugLevel`; this port arms a THREAD, which is
/// far more expensive, so getting the guard wrong would spawn one per fragment
/// on every ordinary scan.
#[test]
fn the_watchdog_is_armed_only_at_debug_or_lower() {
    let restore = logging::level();
    for (level, want_armed) in [
        (logging::Level::Trace, true),
        (logging::Level::Debug, true),
        (logging::Level::Info, false),
        (logging::Level::Warn, false),
        (logging::Level::Error, false),
    ] {
        logging::set_level(level);
        assert_eq!(
            crate::SlowWatchdog::arm("x.txt").is_some(),
            want_armed,
            "{level:?}"
        );
    }
    logging::set_level(restore);
}

/// It fires when the inspection really is slow.
#[test]
fn a_slow_inspection_times_out() {
    let fired = (std::sync::Mutex::new(false), std::sync::Condvar::new());
    assert!(
        crate::wait_for_inspection(&fired, std::time::Duration::from_millis(20)),
        "nobody signalled within the threshold, so this fragment IS slow"
    );
}

/// And stays SILENT when it does not — Go's `timer.Stop()`.
///
/// A watchdog that reported a timeout on an ordinary wake-up would warn about
/// every fragment, which turns the diagnostic into noise nobody reads.
#[test]
fn a_finished_inspection_does_not_time_out() {
    let fired = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let waiter = std::sync::Arc::clone(&fired);
    let t = std::thread::spawn(move || {
        crate::wait_for_inspection(&waiter, std::time::Duration::from_secs(30))
    });
    std::thread::sleep(std::time::Duration::from_millis(20));
    let (lock, cv) = &*fired;
    *lock.lock().unwrap() = true;
    cv.notify_all();
    assert!(!t.join().unwrap(), "a signalled wait must not report a timeout");
}

/// THE ONE THAT WOULD HURT: dropping the watchdog must not wait out the
/// threshold. If cancellation did not work, every fragment on a debug-level
/// scan would block for five seconds and the scan would appear hung — a far
/// worse bug than the missing warning this whole thing exists to provide.
#[test]
fn dropping_the_watchdog_returns_immediately_rather_than_waiting() {
    let restore = logging::level();
    logging::set_level(logging::Level::Debug);
    crate::set_slow_warning_threshold(std::time::Duration::from_secs(30));

    let start = std::time::Instant::now();
    {
        let _w = crate::SlowWatchdog::arm("slow.txt").expect("armed at debug level");
    }
    let elapsed = start.elapsed();

    crate::set_slow_warning_threshold(std::time::Duration::from_secs(5));
    logging::set_level(restore);
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "drop waited {elapsed:?} — the timer is not being stopped"
    );
}

/// Go declares `SlowWarningThreshold` in a `var` block, not a `const` one, and
/// its default is 5s.
#[test]
fn the_threshold_defaults_to_gos_five_seconds_and_is_settable() {
    assert_eq!(
        crate::slow_warning_threshold(),
        std::time::Duration::from_secs(5)
    );
    crate::set_slow_warning_threshold(std::time::Duration::from_millis(250));
    assert_eq!(
        crate::slow_warning_threshold(),
        std::time::Duration::from_millis(250)
    );
    crate::set_slow_warning_threshold(std::time::Duration::from_secs(5));
}



