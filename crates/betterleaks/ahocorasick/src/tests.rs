//! Faithful port of Go `internal/ahocorasick/matcher_test.go`, plus the
//! `SimpleFold` differential golden captured from the Go source.

use super::*;

/// Collect every `(id, start, end)` triple `visit` reports.
fn collect(m: &Matcher, text: &str) -> Vec<(usize, usize, usize)> {
    let mut got = Vec::new();
    m.visit(text, |id, start, end| {
        got.push((id, start, end));
        true
    });
    got
}

/// Port of Go `TestVisit`. Overlapping matches, ASCII folding, and — critically —
/// the ORDER outputs are reported in (own outputs before failure-inherited ones).
#[test]
fn visit() {
    let m = Matcher::compile(&["he", "she", "hers", "his"], true);
    assert_eq!(
        collect(&m, "aHiS uSHers"),
        vec![(3, 1, 4), (1, 6, 9), (0, 7, 9), (2, 7, 11)]
    );
}

/// Port of Go `TestVisitUnicodeSimpleFoldOffsets`. `ſ` (U+017F) is 2 source bytes
/// but ONE matcher byte, so the reported offsets must be SOURCE offsets.
#[test]
fn visit_unicode_simple_fold_offsets() {
    let m = Matcher::compile(&["key", "secret"], true);
    assert_eq!(
        collect(&m, "KEY ſecret"),
        vec![(0, 0, "KEY".len()), (1, "KEY ".len(), "KEY ſecret".len())]
    );
}

/// Port of Go `TestVisitStableIDsAndStop`. Duplicate patterns keep distinct,
/// input-index IDs, and returning false aborts traversal.
#[test]
fn visit_stable_ids_and_stop() {
    let m = Matcher::compile(&["x", "x"], false);
    let mut ids = Vec::new();
    m.visit("xx", |id, _, _| {
        ids.push(id);
        ids.len() < 2
    });
    assert_eq!(ids, vec![0, 1]);
}

/// Port of Go `TestVisitConcurrent`. A compiled Matcher is read-only and safe to
/// share across threads; Go asserts this with `t.Parallel()`, Rust with
/// `thread::scope` over a shared `&Matcher`.
#[test]
fn visit_concurrent() {
    let m = Matcher::compile(&["needle"], true);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                for _ in 0..100 {
                    let mut matches = 0;
                    m.visit("NEEDLE needle", |_, _, _| {
                        matches += 1;
                        true
                    });
                    assert_eq!(matches, 2);
                }
            });
        }
    });
}

/// DIFFERENTIAL GOLDEN, captured by running the Go source's own `foldRuneASCII`
/// over every valid rune (`.scripts/05-B_gen_fold_golden.ps1`):
///
/// ```text
/// U+017F  'ſ'  's'
/// U+212A  'K'  'k'
/// TOTAL   2
/// ```
///
/// Exactly TWO non-ASCII runes have an ASCII member in their `unicode.SimpleFold`
/// orbit. Rust std has no `SimpleFold`, so the port encodes this set directly
/// rather than approximating it with `to_lowercase`/`to_uppercase`.
#[test]
fn fold_rune_ascii_matches_go_golden() {
    assert_eq!(fold_rune_ascii('\u{017F}'), Some(b's'));
    assert_eq!(fold_rune_ascii('\u{212A}'), Some(b'k'));

    // Everything else non-ASCII has NO ASCII fold — spot-check the near misses
    // that a to_lowercase/to_uppercase approximation would get wrong.
    for c in [
        '\u{00E9}', // é
        '\u{00C9}', // É
        '\u{0130}', // İ  (dotted capital I — NOT in the golden)
        '\u{0131}', // ı  (dotless small i — NOT in the golden)
        '\u{1E9E}', // ẞ
        '\u{212B}', // Å (angstrom sign)
        '\u{0410}', // А (Cyrillic)
    ] {
        assert_eq!(fold_rune_ascii(c), None, "U+{:04X} should have no ASCII fold", c as u32);
    }
}

/// A non-ASCII rune with no ASCII fold RESETS the DFA to the root, so a pattern
/// cannot match across it.
#[test]
fn non_foldable_rune_resets_state() {
    let m = Matcher::compile(&["ab"], true);
    // "a" then é then "b" — the é resets state, so "ab" must NOT match.
    assert_eq!(collect(&m, "aéb"), vec![]);
    // Sanity: contiguous "ab" does match.
    assert_eq!(collect(&m, "ab"), vec![(0, 0, 2)]);
}

/// With folding DISABLED, ASCII case is significant and non-ASCII bytes are fed
/// through as raw bytes (Go takes the `else` branch, `fold(b, false)`).
#[test]
fn no_fold_is_case_sensitive() {
    let m = Matcher::compile(&["he"], false);
    assert_eq!(collect(&m, "HE he"), vec![(0, 3, 5)]);
}

/// Characterization: an empty pattern completes at the ROOT state, so Go's
/// `if length := m.lengths[id]; length > 0` guard leaves `start == end`.
#[test]
fn empty_pattern_reports_zero_width() {
    let m = Matcher::compile(&["", "a"], false);
    let got = collect(&m, "a");
    // The empty pattern is an output of the root state, which `visit` only
    // consults AFTER consuming a byte — so it fires once, zero-width, at the
    // position reached after 'a', alongside the "a" match.
    assert!(
        got.contains(&(1, 0, 1)),
        "expected the \"a\" match, got {got:?}"
    );
}

/// Characterization: no patterns at all is a valid, inert matcher.
#[test]
fn empty_pattern_set() {
    let m = Matcher::compile(&[], true);
    assert_eq!(collect(&m, "anything"), vec![]);
}

/// Characterization: a pattern longer than the 128-entry stack ring forces the
/// heap fallback (`if m.maxLength > len(starts)`), and offsets stay correct.
#[test]
fn pattern_longer_than_stack_ring() {
    let long: String = "ab".repeat(100); // 200 bytes > 128
    let m = Matcher::compile(&[&long], false);
    let text = format!("xx{long}yy");
    assert_eq!(collect(&m, &text), vec![(0, 2, 2 + long.len())]);
}
