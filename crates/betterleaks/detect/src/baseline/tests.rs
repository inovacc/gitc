//! Tests for baseline suppression.
//!
//! Both directions are load-bearing and each fails differently: a baseline that
//! over-matches hides a NEW secret, and one that under-matches floods a repo
//! with findings it already accepted — which teaches people to ignore the tool.

use super::*;

/// AWS-shaped key, generated at runtime — no literal provider token is committed
/// anywhere in this repository (see the `testkeys` crate).
fn aws_key() -> String {
    // Reconstructed byte for byte, NOT generated: whether the engine fires
    // depends on this exact string's entropy, so a fresh value would silently
    // change what these tests prove.
    testkeys::reveal("232e3d353f4134345639277d3f2824225f264b37")
}

fn finding() -> Finding {
    Finding {
        rule_id: "aws-access-token".to_string(),
        description: "AWS key".to_string(),
        start_line: 7,
        end_line: 7,
        start_column: 11,
        end_column: 31,
        r#match: format!("aws_key = {}", aws_key()),
        secret: aws_key(),
        file: "creds.txt".to_string(),
        entropy: 4.121928,
        fingerprint: "creds.txt:aws-access-token:7".to_string(),
        ..Default::default()
    }
}

#[test]
fn a_finding_present_in_the_baseline_is_not_new() {
    let base = vec![finding()];
    assert!(!is_new(&finding(), 0, &base));
}

#[test]
fn a_finding_absent_from_the_baseline_is_new() {
    assert!(is_new(&finding(), 0, &[]), "an empty baseline suppresses nothing");
    let other = Finding {
        rule_id: "different-rule".to_string(),
        ..finding()
    };
    assert!(is_new(&finding(), 0, &[other]));
}

/// Any of the compared fields differing makes it a DIFFERENT finding. A secret
/// that moved to another line, or into another file, is new.
#[test]
fn each_compared_field_distinguishes_a_finding() {
    let base = vec![finding()];
    let cases: Vec<(&str, Finding)> = vec![
        ("rule", Finding { rule_id: "x".into(), ..finding() }),
        ("description", Finding { description: "x".into(), ..finding() }),
        ("start_line", Finding { start_line: 8, ..finding() }),
        ("end_line", Finding { end_line: 8, ..finding() }),
        ("start_column", Finding { start_column: 1, ..finding() }),
        ("end_column", Finding { end_column: 1, ..finding() }),
        ("match", Finding { r#match: "x".into(), ..finding() }),
        ("secret", Finding { secret: "x".into(), ..finding() }),
        ("file", Finding { file: "other.txt".into(), ..finding() }),
        ("commit", Finding { commit: "abc".into(), ..finding() }),
        ("author", Finding { author: "someone".into(), ..finding() }),
        ("email", Finding { email: "a@b.c".into(), ..finding() }),
        ("date", Finding { date: "2026-01-01".into(), ..finding() }),
        ("message", Finding { message: "msg".into(), ..finding() }),
        ("entropy", Finding { entropy: 1.0, ..finding() }),
    ];
    for (name, f) in cases {
        assert!(is_new(&f, 0, &base), "a differing {name} must read as NEW");
    }
}

/// **The fingerprint is deliberately NOT compared.** If its format ever
/// changed, every baseline would silently stop matching at once and every
/// repository using one would be flooded.
#[test]
fn a_changed_fingerprint_does_not_make_a_finding_new() {
    let base = vec![finding()];
    let refingerprinted = Finding {
        fingerprint: "some:entirely:new:format".to_string(),
        ..finding()
    };
    assert!(
        !is_new(&refingerprinted, 0, &base),
        "the fingerprint must not participate in the comparison"
    );
}

/// **With `--redact` on, the secret and match are skipped.** A redacted
/// baseline does not contain them, so comparing would make every finding look
/// new — exactly when the user asked for less output, not more.
#[test]
fn redaction_relaxes_the_secret_comparison() {
    let redacted_baseline = vec![Finding {
        r#match: "aws_key = REDACTED".to_string(),
        secret: "REDACTED".to_string(),
        ..finding()
    }];
    assert!(
        is_new(&finding(), 0, &redacted_baseline),
        "without redaction the differing secret makes it new"
    );
    assert!(
        !is_new(&finding(), 100, &redacted_baseline),
        "with redaction the secret is not compared, so it matches"
    );
}

// ── loading ─────────────────────────────────────────────────────────────────

#[test]
fn a_baseline_is_a_previous_json_report() {
    let path = std::env::temp_dir().join(format!("bl-baseline-{}.json", std::process::id()));
    let json = serde_json::to_string(&vec![finding()]).unwrap();
    std::fs::write(&path, json).unwrap();

    let loaded = load_baseline(&path.to_string_lossy()).expect("load");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].rule_id, "aws-access-token");
    assert!(!is_new(&finding(), 0, &loaded), "a round trip must still match");
}

/// The two failure modes need DIFFERENT fixes, so they get different messages:
/// a missing file is a wrong path, an unparseable one is the wrong format.
#[test]
fn the_two_load_failures_are_distinguished() {
    let missing = load_baseline("/definitely/not/here.json").unwrap_err();
    assert!(missing.contains("could not open"), "got {missing}");

    let path = std::env::temp_dir().join(format!("bl-bad-{}.json", std::process::id()));
    std::fs::write(&path, "id,rule\n1,aws").unwrap(); // a CSV report by mistake
    let bad = load_baseline(&path.to_string_lossy()).unwrap_err();
    let _ = std::fs::remove_file(&path);
    assert!(bad.contains("not supported"), "got {bad}");
}

#[test]
fn an_empty_baseline_file_loads_as_no_findings() {
    let path = std::env::temp_dir().join(format!("bl-empty-{}.json", std::process::id()));
    std::fs::write(&path, "[]").unwrap();
    let loaded = load_baseline(&path.to_string_lossy()).expect("load");
    let _ = std::fs::remove_file(&path);
    assert!(loaded.is_empty());
    assert!(is_new(&finding(), 0, &loaded));
}

// ── relative path ───────────────────────────────────────────────────────────

/// The baseline path is stored RELATIVE to the scan source, because the
/// detector skips scanning its own baseline — a report full of secrets sitting
/// inside the scanned tree would otherwise be reported as fresh findings.
#[test]
fn the_baseline_path_is_made_relative_to_the_source() {
    use std::path::Path;
    assert_eq!(
        relative_to(Path::new("/a/b"), Path::new("/a/b/baseline.json")),
        "baseline.json"
    );
    assert_eq!(
        relative_to(Path::new("/a/b/c"), Path::new("/a/b/baseline.json")),
        "../baseline.json"
    );
    assert_eq!(
        relative_to(Path::new("/a/b"), Path::new("/a/b")),
        ".",
        "the same path is the current directory"
    );
}

#[test]
fn add_baseline_wires_the_detector() {
    let dir = std::env::temp_dir().join(format!("bl-base-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("baseline.json");
    std::fs::write(&path, serde_json::to_string(&vec![finding()]).unwrap()).unwrap();

    let mut d = crate::Detector::with_default_config().expect("detector");
    d.add_baseline(&path.to_string_lossy(), &dir.to_string_lossy())
        .expect("add baseline");

    assert!(!d.is_new_finding(&finding(), 0), "the baselined finding is suppressed");
    let other = Finding { start_line: 99, ..finding() };
    assert!(d.is_new_finding(&other, 0), "a different finding still reports");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_detector_without_a_baseline_suppresses_nothing() {
    let d = crate::Detector::with_default_config().expect("detector");
    assert!(d.is_new_finding(&finding(), 0));
}

#[test]
fn a_missing_baseline_file_is_an_error_not_a_silent_empty_baseline() {
    let mut d = crate::Detector::with_default_config().expect("detector");
    assert!(
        d.add_baseline("/definitely/not/here.json", ".").is_err(),
        "a wrong --baseline-path must fail loudly, or the user believes it applied"
    );
}



