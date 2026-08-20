use super::*;
use crate::Detector;

fn aws_key() -> String {
    // Reconstructed byte for byte, NOT generated: whether the engine fires
    // depends on this exact string's entropy, so a fresh value would silently
    // change what these tests prove.
    testkeys::reveal("232e3d353f4134345639277d3f2824225f264b37")
}

/// `aws_key = <key>` — the payload these tests scan.
fn secret() -> String {
    format!("aws_key = {}\n", aws_key())
}

fn detector() -> Detector {
    Detector::with_default_config().expect("the shipped catalogue must load")
}

fn fragment(path: &str, raw: &str, sha: &str) -> Fragment {
    // `start_line: 1` mirrors what the file source actually produces — a
    // default-constructed 0 would put every finding on line 0 and make the
    // fingerprint assertions below test the fixture rather than the code.
    let mut f = Fragment {
        raw: raw.to_string(),
        start_line: 1,
        ..Default::default()
    };
    f.attributes
        .insert(sources::ATTR_PATH.to_string(), path.to_string());
    if !sha.is_empty() {
        f.attributes
            .insert(sources::ATTR_GIT_SHA.to_string(), sha.to_string());
    }
    f
}

/// A source that yields exactly what it is given, including errors — the shape
/// `DetectSource` has to survive.
struct Scripted(Vec<Result<Fragment, String>>);

impl Source for Scripted {
    type Error = String;
    fn fragments(
        &self,
        yield_fn: sources::FragmentsFunc<'_, String>,
    ) -> Result<(), String> {
        for item in &self.0 {
            yield_fn(item.clone())?;
        }
        Ok(())
    }
}

/// The accumulator half: findings go in through `add_finding` and come back out
/// of `findings`, which is the entire contract of the deprecated API.
#[test]
fn add_finding_accumulates_and_findings_returns_them() {
    let d = detector();
    let mut legacy = LegacyDetector::new(&d);
    assert!(legacy.findings().is_empty());

    for f in d.detect(&fragment("creds.txt", secret().as_str(), "")) {
        legacy.add_finding(f);
    }
    assert_eq!(legacy.findings().len(), 1);
    assert_eq!(legacy.findings()[0].secret, aws_key());
    // The fingerprint is SET by add_finding, not inherited — Go builds it there.
    assert_eq!(legacy.findings()[0].fingerprint, "creds.txt:generic-api-key:1");
}

/// A finding built by hand, so `add_finding` is the ONLY gate under test.
///
/// It has to be hand-built: `Detector::detect` already applies the ignore list
/// and the baseline itself, so feeding it a detected finding would test that
/// filter instead and pass no matter what `add_finding` does. An earlier draft
/// of these two tests did exactly that, and survived deleting the check they
/// were supposed to be pinning.
fn raw_finding(path: &str, sha: &str) -> Finding {
    let mut f = Finding {
        rule_id: "generic-api-key".to_string(),
        start_line: 1,
        secret: aws_key(),
        ..Default::default()
    };
    f.attributes
        .insert(sources::ATTR_PATH.to_string(), path.to_string());
    if !sha.is_empty() {
        f.attributes
            .insert(sources::ATTR_GIT_SHA.to_string(), sha.to_string());
    }
    f
}

/// The ignore list is consulted on the GLOBAL fingerprint shape.
#[test]
fn a_globally_ignored_fingerprint_is_dropped() {
    let mut d = detector();
    d.gitleaks_ignore
        .insert("creds.txt:generic-api-key:1".to_string());
    let mut legacy = LegacyDetector::new(&d);

    legacy.add_finding(raw_finding("creds.txt", ""));
    assert!(
        legacy.findings().is_empty(),
        "the ignore entry must suppress it: {:?}",
        legacy.findings()
    );

    // A commit-LESS entry suppresses the finding in every commit that carries
    // it, which is what makes an ignore file usable against history.
    legacy.add_finding(raw_finding("creds.txt", "abc123"));
    assert!(legacy.findings().is_empty(), "{:?}", legacy.findings());

    // But it must not suppress a different file.
    legacy.add_finding(raw_finding("other.txt", ""));
    assert_eq!(legacy.findings().len(), 1, "a different file still reports");
}

/// …and on the COMMIT-QUALIFIED shape, which is a different string. Checking
/// only one of the two would let half of every `.betterleaksignore` file be
/// silently ineffective.
#[test]
fn a_commit_qualified_ignored_fingerprint_is_dropped() {
    let mut d = detector();
    d.gitleaks_ignore
        .insert("abc123:creds.txt:generic-api-key:1".to_string());
    let mut legacy = LegacyDetector::new(&d);

    legacy.add_finding(raw_finding("creds.txt", "abc123"));
    assert!(legacy.findings().is_empty(), "{:?}", legacy.findings());

    // The same entry must NOT suppress the same finding in another commit —
    // that is the entire difference between the two fingerprint shapes.
    legacy.add_finding(raw_finding("creds.txt", "def456"));
    assert_eq!(legacy.findings().len(), 1, "a different commit still reports");

    // Nor the commit-less form of it.
    legacy.add_finding(raw_finding("creds.txt", ""));
    assert_eq!(legacy.findings().len(), 2, "no commit is not that commit");
}

/// `commitMap` is a SET. Counting fragments instead would report a number
/// larger than the number of commits, which is the one thing the
/// "N commits scanned." line exists to state.
#[test]
fn commits_are_counted_once_however_many_fragments_they_produce() {
    let d = detector();
    let mut legacy = LegacyDetector::new(&d);
    let src = Scripted(vec![
        Ok(fragment("a.txt", secret().as_str(), "sha-one")),
        Ok(fragment("b.txt", "nothing here\n", "sha-one")),
        Ok(fragment("c.txt", secret().as_str(), "sha-two")),
    ]);
    let found = legacy.detect_source(&src, true).expect("scan");
    assert_eq!(found.len(), 2, "two secrets across three fragments");
    assert_eq!(legacy.commits.len(), 2, "three fragments, TWO commits");
}

/// A per-fragment error is logged and the scan CONTINUES. Stopping would report
/// the findings gathered so far as though they were the whole answer.
#[test]
fn a_fragment_error_does_not_end_the_scan() {
    let d = detector();
    let mut legacy = LegacyDetector::new(&d);
    let src = Scripted(vec![
        Err("unreadable blob".to_string()),
        Ok(fragment("creds.txt", secret().as_str(), "")),
    ]);
    let found = legacy.detect_source(&src, false).expect("scan");
    assert_eq!(found.len(), 1, "the fragment after the error was still scanned");
}

/// The empty-fragment skip is `content AND path both empty`, not `either`.
///
/// Go: `if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == ""`.
/// Written as `||` it would skip every fragment that merely lacks a path — the
/// second one below — and a scan of piped stdin would report clean.
#[test]
fn the_empty_fragment_skip_requires_both_to_be_empty() {
    let d = detector();
    let mut legacy = LegacyDetector::new(&d);
    let before = d.total_bytes();
    let src = Scripted(vec![
        // Nothing at all: skipped, so the detector never sees its bytes.
        Ok(fragment("", "", "")),
        // No path, but real content — this is what stdin looks like, and it
        // MUST be scanned.
        Ok(fragment("", secret().as_str(), "")),
    ]);
    let found = legacy.detect_source(&src, false).expect("scan");

    assert_eq!(found.len(), 1, "the path-less fragment must still be scanned");
    assert_eq!(found[0].secret, aws_key());
    assert_eq!(
        d.total_bytes() - before,
        secret().as_str().len() as u64,
        "exactly one fragment's bytes were counted — the empty one was skipped \
         before the detector, as Go does"
    );
}

/// `shouldVerbosePrint` — and specifically that it is NOT the live path's rule.
#[test]
fn should_verbose_print_follows_the_status_filter() {
    let d = detector();
    let mut legacy = LegacyDetector::new(&d);
    let mut f = Finding::default();

    // Verbose off suppresses everything, filter or no filter.
    assert!(!legacy.should_verbose_print(&f));

    legacy.verbose = true;
    assert!(legacy.should_verbose_print(&f), "an empty filter prints all");

    // With a filter, an unvalidated finding needs the "none" pseudo-status.
    legacy
        .validation_status_filter
        .insert("valid".to_string());
    assert!(
        !legacy.should_verbose_print(&f),
        "no status, and the filter does not name none"
    );
    legacy.validation_status_filter.insert("none".to_string());
    assert!(legacy.should_verbose_print(&f));

    f.validation_status = report::ValidationStatus::VALID;
    assert!(legacy.should_verbose_print(&f));
    f.validation_status = report::ValidationStatus(std::borrow::Cow::Borrowed("invalid"));
    assert!(
        !legacy.should_verbose_print(&f),
        "a status the filter does not name is not printed"
    );
}

/// The validation counts this path accumulates, which Go reports at the end.
#[test]
fn validation_statuses_are_counted() {
    let d = detector();
    let mut legacy = LegacyDetector::new(&d);
    for (i, status) in ["valid", "valid", "invalid"].iter().enumerate() {
        let mut f = Finding {
            rule_id: "r".to_string(),
            file: format!("f{i}.txt"),
            start_line: 1,
            secret: "s".to_string(),
            ..Default::default()
        };
        f.validation_status = report::ValidationStatus(std::borrow::Cow::Borrowed(status));
        legacy.add_finding(f);
    }
    assert_eq!(legacy.validation_counts().get("valid"), Some(&2));
    assert_eq!(legacy.validation_counts().get("invalid"), Some(&1));
    assert_eq!(legacy.findings().len(), 3);
}

/// `Detect` and `DetectContext` are aliases of the live detector, and must not
/// have drifted into doing something else.
#[test]
fn the_deprecated_detect_aliases_agree_with_the_live_one() {
    let d = detector();
    let legacy = LegacyDetector::new(&d);
    let frag = fragment("creds.txt", secret().as_str(), "");
    let live = d.detect(&frag);
    assert_eq!(legacy.detect(&frag).len(), live.len());
    assert_eq!(legacy.detect_context(&frag).len(), live.len());
    assert_eq!(live.len(), 1, "the fixture must actually find something");
}




