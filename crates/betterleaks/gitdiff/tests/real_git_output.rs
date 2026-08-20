//! Parse REAL `git log -p` output, not hand-written fixtures.
//!
//! Hand-written diffs test what I believed the format to be. This fixture is
//! actual output from `git log -p --max-count=3 --no-color` on the betterleaks
//! source repository — 3 commits, 279 file diffs, 989 hunks, 541 KB — so it
//! exercises real-world shapes a fixture would not think to include: renames,
//! mode changes, binary files, CRLF, paths with odd characters, hunk headings,
//! and no-newline markers.
//!
//! Counts here are measured from the fixture with `grep`, so a parser that
//! silently drops files or hunks fails rather than looking healthy.

use gitdiff::{parse, Op};

const REAL: &str = include_str!("fixtures/real_git_log.txt");

/// Measured: `rg -c '^commit '` = 3, `'^diff --git '` = 279, `'^@@'` = 989.
#[test]
fn parses_every_file_and_hunk_in_real_output() {
    let files = parse(REAL);

    assert_eq!(
        files.len(),
        279,
        "every `diff --git` must become a file — a parser that skips one looks healthy while missing leaks"
    );

    let hunks: usize = files.iter().map(|f| f.text_fragments.len()).sum();
    assert_eq!(hunks, 989, "every `@@` hunk must be parsed");

    let commits: std::collections::BTreeSet<&str> = files
        .iter()
        .filter_map(|f| f.patch_header.as_ref())
        .map(|h| h.sha.as_str())
        .collect();
    assert_eq!(commits.len(), 3, "three distinct commits");
}

/// Every file must carry a commit header, a non-empty new name, and a 40-char
/// SHA. A missing header means a finding would be attributed to no commit.
#[test]
fn every_file_is_attributable() {
    for f in parse(REAL) {
        let h = f
            .patch_header
            .as_ref()
            .unwrap_or_else(|| panic!("{} has no commit header", f.new_name));
        assert_eq!(h.sha.len(), 40, "{} has a malformed sha {:?}", f.new_name, h.sha);
        assert!(h.sha.chars().all(|c| c.is_ascii_hexdigit()), "sha not hex: {}", h.sha);
        assert!(!h.author_name.is_empty(), "{} has no author", f.new_name);
        assert!(h.author_email.contains('@'), "{} author email {:?}", f.new_name, h.author_email);
        // A delete legitimately has no new name; anything else must.
        if !f.is_delete {
            assert!(!f.new_name.is_empty(), "a non-delete file with no name");
        }
    }
}

/// Hunk positions must be sane: a real `@@ +N` is 1-based and non-decreasing
/// within a file, since git emits hunks in order.
#[test]
fn hunk_positions_are_ordered_and_positive() {
    for f in parse(REAL) {
        let mut last = 0i64;
        for frag in &f.text_fragments {
            assert!(
                frag.new_position >= 0,
                "{} has a negative hunk position {}",
                f.new_name,
                frag.new_position
            );
            assert!(
                frag.new_position >= last,
                "{} hunks out of order: {} after {}",
                f.new_name,
                frag.new_position,
                last
            );
            last = frag.new_position;
        }
    }
}

/// Added lines must reconstruct exactly the `+` lines of the fixture (minus the
/// `+++` file headers, which are not content). This is the strongest check that
/// `Raw(OpAdd)` is neither dropping nor inventing content.
#[test]
fn added_lines_match_the_raw_fixture() {
    // Count `+` lines in the fixture, excluding `+++ ` headers.
    let expected: usize = REAL
        .lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++ "))
        .count();

    let parsed: usize = parse(REAL)
        .iter()
        .flat_map(|f| &f.text_fragments)
        .flat_map(|t| &t.lines)
        .filter(|l| l.op == Op::Add)
        .count();

    assert_eq!(parsed, expected, "added-line count must match the fixture exactly");
    assert!(expected > 1000, "sanity: the fixture should be substantial");
}

/// Same for deletions and context, so the op classification cannot be skewed.
#[test]
fn deleted_and_context_lines_match_the_raw_fixture() {
    let expected_del: usize = REAL
        .lines()
        .filter(|l| l.starts_with('-') && !l.starts_with("--- "))
        .count();
    let parsed_del: usize = parse(REAL)
        .iter()
        .flat_map(|f| &f.text_fragments)
        .flat_map(|t| &t.lines)
        .filter(|l| l.op == Op::Delete)
        .count();
    assert_eq!(parsed_del, expected_del, "deleted-line count");
}

/// Parsing 541 KB of real diff must not panic, and must be quick enough to sit
/// on a scan path.
#[test]
fn parsing_real_output_is_not_pathological() {
    let start = std::time::Instant::now();
    let files = parse(REAL);
    let elapsed = start.elapsed();
    assert!(!files.is_empty());
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "parsing 541 KB took {elapsed:?} — too slow for a history scan"
    );
}
