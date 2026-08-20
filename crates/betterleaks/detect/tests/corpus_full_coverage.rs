//! Coverage against the SECOND synthetic corpus
//! (`tests/fixtures/leaks_formats_full.json` — a different generation run from
//! the one `corpus_coverage.rs` uses, same 20 detector names).
//!
//! # Re-baselined 2026-08-14, when M13 replaced the engine
//!
//! Same situation as `corpus_coverage.rs`, and the same verified explanation —
//! see that file's table for the per-detector reasons. In short: this fixture
//! was generated against the old hand-written 26-rule engine, and most of its
//! misses are samples that are **not format-valid** for the real catalogue's
//! stricter patterns (missing the `T3BlbkFJ` marker, a bare PEM header with no
//! body, non-base32 AWS ids, low-entropy hex, and so on).
//!
//! `tests/real_formats.rs` proves the engine DOES detect format-valid keys of
//! these same types, which is what makes re-baselining here honest rather than
//! bar-lowering.
//!
//! This test guards the baseline plus one aggregate the per-detector table
//! cannot express: the TOTAL number of synthetic samples detected across the
//! whole corpus. A rule change that quietly trades coverage between detectors
//! shows up there even when every individual floor still holds.

use detect::Detector;

/// Verified baseline as of the M13 engine; coverage may rise, never fall.
const BASELINE: &[(&str, usize)] = &[
    ("anthropic-api", 0),
    // 0, not 2 — the corpus emits AWS ids alone, and the rule requires a paired
    // `aws-secret-access-key` within 5 lines (Go agrees).
    ("aws-akia", 0),
    ("firebase-db-url", 0),
    ("gcp-service-account", 0),
    ("github-fine", 12),
    ("github-pat", 12),
    ("google-api", 12),
    ("google-oauth-client", 0),
    ("google-oauth-secret", 0),
    ("jwt", 4),
    ("mapbox-secret", 0),
    ("npm-token", 12),
    ("openai-legacy", 0),
    ("openai-proj", 0),
    ("openrouter", 12),
    ("private-key-pem", 0),
    ("sendgrid", 12),
    ("slack-token", 12),
    ("stripe-secret", 12),
    ("twilio-sk", 0),
];

/// Sum of the baseline — the aggregate floor.
const BASELINE_TOTAL: usize = 100;

/// The detector's examples, reconstructed from their encoded form.
///
/// The fixture stores `fake_examples_enc` rather than the raw strings: these are
/// provider-shaped tokens, and committing the literals to a public repository
/// both blocks the push (GitHub partner-pattern protection) and fires abuse
/// alerts at Slack/Stripe/AWS/etc. for fake keys. The decoded values are
/// byte-identical to the originals, so the measured baselines above still mean
/// exactly what they meant when they were recorded.
fn examples_of(det: &serde_json::Value) -> Vec<String> {
    det["fake_examples_enc"]
        .as_array()
        .expect("fixture entry must carry fake_examples_enc")
        .iter()
        .map(|e| testkeys::reveal(e.as_str().expect("encoded entry is a string")))
        .collect()
}

#[test]
fn corpus_full_coverage_does_not_regress() {
    let raw = include_str!("fixtures/leaks_formats_full.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("parse corpus fixture");
    let d = Detector::with_default_rules();

    let floor_for = |name: &str| -> usize {
        BASELINE.iter().find(|(n, _)| *n == name).map(|(_, v)| *v).unwrap_or(0)
    };

    let mut rows = Vec::new();
    let mut regressions = Vec::new();
    let mut total_hits = 0usize;

    for det in v.as_array().expect("array") {
        let name = det["name"].as_str().unwrap();
        let examples = examples_of(det);
        let hit = examples
            .iter()
            .filter(|ex| !d.detect_string(ex).is_empty())
            .count();
        total_hits += hit;
        rows.push((name.to_string(), hit, examples.len()));
        let floor = floor_for(name);
        if hit < floor {
            regressions.push(format!(
                "{name}: {hit}/{} REGRESSED below baseline {floor}",
                examples.len()
            ));
        }
    }

    eprintln!("\n=== full corpus coverage (detected / total, baseline) ===");
    for (n, h, t) in &rows {
        let floor = floor_for(n);
        let mark = if *h > floor { "UP " } else { "BASE" };
        eprintln!("  [{mark}] {n:<24} {h}/{t}  (baseline {floor})");
    }
    eprintln!("total detected: {total_hits} (baseline {BASELINE_TOTAL})");

    assert!(regressions.is_empty(), "coverage regressed:\n{}", regressions.join("\n"));
    assert!(
        total_hits >= BASELINE_TOTAL,
        "aggregate detection fell: {total_hits} < {BASELINE_TOTAL} — a rule change may have \
         traded coverage between detectors while every individual floor still held"
    );
    assert_eq!(rows.len(), 20, "corpus detector count");
}


