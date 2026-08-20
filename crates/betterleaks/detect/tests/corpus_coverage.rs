//! Coverage of the `detect` engine against an independent leak-format corpus
//! (`tests/fixtures/leaks_formats.json`: 20 detectors × 12 synthetic,
//! machine-generated, NON-FUNCTIONAL fake keys).
//!
//! # Re-baselined 2026-08-14, when M13 replaced the engine
//!
//! This corpus was generated against the **old hand-written 26-rule engine**,
//! whose patterns were laxer than the real gitleaks catalogue. M13 swapped in
//! the real 414-rule engine, and coverage of this fixture went DOWN for eight
//! detectors — because most of its "fake examples" are **not format-valid** for
//! the real detectors.
//!
//! That is a precision improvement, not a regression, and it was verified per
//! detector rather than assumed (`examples/diagnose_corpus.rs` reports, for each
//! miss, whether NO rule regex matches or a filter discarded it):
//!
//! | detector | why the real catalogue does not match |
//! |---|---|
//! | `anthropic-api` | real pattern needs `sk-ant-api03-` + **93** chars + literal `AA`; samples are ~72 chars with no `AA` |
//! | `openai-proj` / `openai-legacy` | real pattern requires the embedded marker **`T3BlbkFJ`** (base64 "OpenAI"); samples lack it |
//! | `private-key-pem` | real pattern needs the header **plus ≥64 chars of body** and a footer; samples are a bare header line |
//! | `mapbox-secret` | real pattern needs `mapbox` assignment context AND `pk.`+60+`.`+22; samples are a bare `sk.eyJ…` |
//! | `gcp-service-account` | sample is the fragment `"type": "service_account"` with no key material |
//! | `google-oauth-*`, `firebase-db-url` | no rule of that shape in the catalogue |
//! | `aws-akia` | generator emits `[0-9A-Z]{16}`; real AWS ids are base32 `[A-Z2-7]{16}`, so non-base32 samples are correctly rejected |
//! | `twilio-sk` | regex DOES match, then `entropy(secret) <= 3.0` discards the low-entropy hex fake |
//! | `jwt` | 4/12 — the rest are not structurally valid JWTs |
//!
//! **`tests/real_formats.rs` is the counter-evidence**: it constructs each of
//! these key types to the catalogue's ACTUAL pattern and asserts the engine
//! fires. Without that companion test, re-baselining here would just be lowering
//! the bar until it passed.
//!
//! So this test now guards against REGRESSION from the measured baseline rather
//! than asserting an aspirational one: coverage may rise, never fall.

use detect::Detector;

/// Verified baseline as of the M13 engine. A detector may exceed its entry;
/// falling below one is a regression and fails.
const BASELINE: &[(&str, usize)] = &[
    ("anthropic-api", 0),
    ("openai-proj", 0),
    ("openai-legacy", 0),
    ("openrouter", 12),
    ("google-api", 12),
    // 0, not 2: `aws-access-token` requires the `aws-secret-access-key`
    // component within 5 lines, and the corpus emits access-key ids ALONE. The
    // Go engine reports nothing for a lone id either — verified directly.
    ("aws-akia", 0),
    ("github-pat", 12),
    ("github-fine", 12),
    ("stripe-secret", 12),
    ("slack-token", 12),
    ("google-oauth-secret", 0),
    ("google-oauth-client", 0),
    ("gcp-service-account", 0),
    ("private-key-pem", 0),
    ("jwt", 4),
    ("twilio-sk", 0),
    ("sendgrid", 12),
    ("npm-token", 12),
    ("mapbox-secret", 0),
    ("firebase-db-url", 0),
];

/// The detector's examples, reconstructed from their encoded form.
///
/// The fixture stores `fake_examples_enc` rather than the raw strings: these are
/// provider-shaped tokens, and committing the literals to a public repository
/// both blocks the push (GitHub partner-pattern protection, which cannot be
/// disabled per-repo) and fires abuse alerts at Slack/Stripe/AWS/etc. for keys
/// that were never real.
///
/// Decoding yields the ORIGINAL bytes, which matters here more than anywhere
/// else in the tree: every number in `BASELINE` was *measured* against these
/// exact 240 strings — `jwt` is 4/12 because only four are structurally valid,
/// `twilio-sk` is 0/12 because the entropy filter discards those particular hex
/// digits. Regenerating the values instead of reconstructing them would move the
/// baseline silently, which is the "lowering the bar until it passed" failure
/// this module's header warns about.
fn examples_of(det: &serde_json::Value) -> Vec<String> {
    det["fake_examples_enc"]
        .as_array()
        .expect("fixture entry must carry fake_examples_enc")
        .iter()
        .map(|e| testkeys::reveal(e.as_str().expect("encoded entry is a string")))
        .collect()
}

#[test]
fn corpus_coverage_does_not_regress() {
    let raw = include_str!("fixtures/leaks_formats.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("parse corpus fixture");
    let detectors = v.as_array().expect("corpus is an array");
    let d = Detector::with_default_rules();

    let floor_for = |name: &str| -> usize {
        BASELINE
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    };

    let mut rows = Vec::new();
    let mut regressions = Vec::new();

    for det in detectors {
        let name = det["name"].as_str().unwrap();
        let examples = examples_of(det);
        let total = examples.len();
        let hit = examples
            .iter()
            .filter(|ex| !d.detect_string(ex).is_empty())
            .count();
        rows.push((name.to_string(), hit, total));
        let floor = floor_for(name);
        if hit < floor {
            regressions.push(format!("{name}: {hit}/{total} REGRESSED below baseline {floor}"));
        }
    }

    eprintln!("\n=== corpus coverage (detected / total, baseline) ===");
    for (n, h, t) in &rows {
        let floor = floor_for(n);
        let mark = if *h > floor { "UP " } else if *h == *t { "OK " } else { "BASE" };
        eprintln!("  [{mark}] {n:<24} {h}/{t}  (baseline {floor})");
    }
    let covered = rows.iter().filter(|(_, h, t)| h == t).count();
    eprintln!("fully covered: {covered}/{}", rows.len());

    assert!(regressions.is_empty(), "coverage regressed:\n{}", regressions.join("\n"));

    // The corpus itself must not silently shrink.
    assert_eq!(rows.len(), 20, "corpus detector count");
}

/// The eight fully-covered detectors are the ones whose synthetic format happens
/// to match the real catalogue. Pin them at 12/12 so a real engine regression
/// there is caught sharply rather than blending into the table above.
#[test]
fn well_formed_detectors_stay_fully_covered() {
    let raw = include_str!("fixtures/leaks_formats.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("parse");
    let d = Detector::with_default_rules();

    for name in [
        "openrouter",
        "google-api",
        "github-pat",
        "github-fine",
        "stripe-secret",
        "slack-token",
        "sendgrid",
        "npm-token",
    ] {
        let det = v
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("{name} missing from corpus"));
        let examples = examples_of(det);
        let hit = examples
            .iter()
            .filter(|ex| !d.detect_string(ex).is_empty())
            .count();
        assert_eq!(hit, examples.len(), "{name} must stay fully covered");
    }
}


