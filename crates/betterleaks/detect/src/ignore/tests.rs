//! Tests for `.betterleaksignore` handling.
//!
//! Both directions matter and each has a distinct failure mode: an entry that
//! fails to suppress buries the real findings in noise, and an entry that
//! over-suppresses hides a live secret. The tests assert both.

use super::*;
use report::Finding;

fn finding(file: &str, rule: &str, line: i64, commit: &str) -> Finding {
    let mut f = Finding {
        file: file.to_string(),
        rule_id: rule.to_string(),
        start_line: line,
        commit: commit.to_string(),
        ..Default::default()
    };
    f.fingerprint = if commit.is_empty() {
        format!("{file}:{rule}:{line}")
    } else {
        format!("{commit}:{file}:{rule}:{line}")
    };
    f
}

#[test]
fn parses_both_fingerprint_shapes() {
    let (set, invalid) = parse_ignore_file(
        "cmd/rules/jwt.go:jwt:17\n\
         418edf165dbb63d6f46993ae8f8818ffd87ea582:cmd/rules/jwt.go:jwt:19\n",
    );
    assert!(set.contains("cmd/rules/jwt.go:jwt:17"), "global form");
    assert!(
        set.contains("418edf165dbb63d6f46993ae8f8818ffd87ea582:cmd/rules/jwt.go:jwt:19"),
        "commit form"
    );
    assert_eq!(set.len(), 2);
    assert!(invalid.is_empty());
}

#[test]
fn skips_blank_lines_and_comments() {
    let (set, _) = parse_ignore_file("# a comment\n\n   \nfile.go:rule:1\n   # indented comment\n");
    assert_eq!(set.len(), 1);
    assert!(set.contains("file.go:rule:1"));
}

/// Windows separators are normalised in the PATH component only. An ignore file
/// written on Windows must suppress the same finding on Linux.
#[test]
fn windows_paths_are_normalised_in_the_path_component() {
    let (set, _) = parse_ignore_file(
        "cmd\\rules\\jwt.go:jwt:17\n\
         abc123:cmd\\rules\\jwt.go:jwt:19\n",
    );
    assert!(set.contains("cmd/rules/jwt.go:jwt:17"));
    assert!(set.contains("abc123:cmd/rules/jwt.go:jwt:19"));
    assert!(!set.iter().any(|e| e.contains('\\')), "no backslash survives");
}

/// Go warns about a malformed entry but INSERTS it anyway. Dropping it would be
/// tidier and wrong — a user's entry would stop working with no error.
#[test]
fn malformed_entries_are_reported_but_still_inserted() {
    let (set, invalid) = parse_ignore_file("only-two:parts\nfile.go:rule:1\n");
    assert_eq!(invalid, vec!["only-two:parts"]);
    assert!(set.contains("only-two:parts"), "Go inserts it regardless");
    assert_eq!(set.len(), 2);
}

#[test]
fn a_listed_global_fingerprint_is_suppressed() {
    let (set, _) = parse_ignore_file("creds.txt:aws-access-token:1\n");
    assert!(is_ignored(&set, &finding("creds.txt", "aws-access-token", 1, "")));
}

/// Only an EXACT match suppresses. A different line, rule or file is a
/// different finding — otherwise one ignore entry would blanket a whole file.
#[test]
fn a_near_miss_is_not_suppressed() {
    let (set, _) = parse_ignore_file("creds.txt:aws-access-token:1\n");
    assert!(!is_ignored(&set, &finding("creds.txt", "aws-access-token", 2, "")), "line differs");
    assert!(!is_ignored(&set, &finding("creds.txt", "generic-api-key", 1, "")), "rule differs");
    assert!(!is_ignored(&set, &finding("other.txt", "aws-access-token", 1, "")), "file differs");
    assert!(!is_ignored(&HashSet::new(), &finding("creds.txt", "aws-access-token", 1, "")));
}

/// **The behaviour that makes an ignore file usable against history.** A
/// commit-less entry suppresses the finding in EVERY commit that carries it —
/// Go checks the global fingerprint first, before looking at the commit.
#[test]
fn a_global_entry_suppresses_a_finding_in_any_commit() {
    let (set, _) = parse_ignore_file("creds.txt:aws-access-token:1\n");
    assert!(is_ignored(&set, &finding("creds.txt", "aws-access-token", 1, "abc123")));
    assert!(is_ignored(&set, &finding("creds.txt", "aws-access-token", 1, "def456")));
}

#[test]
fn a_commit_entry_suppresses_only_that_commit() {
    let (set, _) = parse_ignore_file("abc123:creds.txt:aws-access-token:1\n");
    assert!(is_ignored(&set, &finding("creds.txt", "aws-access-token", 1, "abc123")));
    assert!(
        !is_ignored(&set, &finding("creds.txt", "aws-access-token", 1, "def456")),
        "a different commit is a different fingerprint"
    );
    assert!(
        !is_ignored(&set, &finding("creds.txt", "aws-access-token", 1, "")),
        "a commit-qualified entry must NOT suppress a commit-less (directory) finding"
    );
}

/// The real file betterleaks ships — the one that turns 561 findings into 1.
///
/// Counts measured from the file itself: 943 non-comment lines but only 941
/// DISTINCT ones — two entries are duplicated in the shipped file — of which 64
/// are the GLOBAL 3-part form and 877 the commit 4-part form. Both shapes
/// appearing in one real file is exactly why both branches of `is_ignored`
/// exist, and the duplicates are why this asserts set size rather than a line
/// count.
#[test]
fn the_real_betterleaks_ignore_file_parses() {
    let content = include_str!("../../testdata/betterleaksignore.txt");
    let (set, invalid) = parse_ignore_file(content);

    assert!(invalid.is_empty(), "unexpected malformed entries: {invalid:?}");

    let global = set.iter().filter(|e| e.split(':').count() == 3).count();
    let commit = set.iter().filter(|e| e.split(':').count() == 4).count();
    assert_eq!(global, 64, "global-form entries");
    assert_eq!(commit, 877, "commit-form entries (2 lines are duplicated)");
    assert_eq!(set.len(), 941, "941 distinct entries from 943 lines");

    // A spot-check of each shape, taken verbatim from the file.
    assert!(set.contains("README.md:aws-access-token:204"), "a global entry");
    assert!(
        set.contains("418edf165dbb63d6f46993ae8f8818ffd87ea582:cmd/generate/config/rules/jwt.go:jwt:17"),
        "a commit entry"
    );
}
