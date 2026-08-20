//! Faithful port of Go `internal/confidence/confidence_test.go` (`TestMeets`),
//! plus characterization tests for the exports that test leaves uncovered
//! (`valid`, `ATTRIBUTE`, and the error text `Parse` produces).

use super::*;

/// Port of Go `TestMeets` — the same 5-case table, same order.
#[test]
fn meets_table() {
    let cases: &[(&str, &str, bool)] = &[
        ("low", "medium", false),
        ("medium", "medium", true),
        ("high", "medium", true),
        ("", "high", true),
        ("custom", "high", true),
    ];
    for &(value, minimum, want) in cases {
        assert_eq!(
            meets(value, minimum),
            want,
            "meets({value:?}, {minimum:?})"
        );
    }
}

/// Second half of Go `TestMeets`: `Parse(" HIGH ")` trims + lowercases, and
/// `Parse("certain")` is an error.
#[test]
fn parse_trims_and_lowercases() {
    assert_eq!(parse(" HIGH "), Ok("high".to_string()));
    assert!(parse("certain").is_err());
}

/// Characterization (no Go test): `Parse("")` returns the empty string with no
/// error — the branch Go spells `if value == "" || Valid(value)`.
#[test]
fn parse_empty_is_ok() {
    assert_eq!(parse(""), Ok(String::new()));
    assert_eq!(parse("   "), Ok(String::new()));
}

/// Characterization (no Go test): `Valid` accepts exactly the three levels, and
/// is NOT case-insensitive (Go compares the raw string; `Parse` is what folds).
#[test]
fn valid_exact_three_levels() {
    for v in ["low", "medium", "high"] {
        assert!(valid(v), "valid({v:?}) should be true");
    }
    for v in ["", "LOW", "High", "custom", " low"] {
        assert!(!valid(v), "valid({v:?}) should be false");
    }
}

/// Characterization (no Go test): the error text reproduces Go's
/// `fmt.Errorf("invalid confidence %q (expected low, medium, or high)", value)`.
/// Go's `%q` quotes the value, so `certain` renders as `"certain"`.
#[test]
fn error_text_matches_go() {
    let err = parse("certain").unwrap_err();
    assert_eq!(
        err.to_string(),
        r#"invalid confidence "certain" (expected low, medium, or high)"#
    );
    // Parse lowercases + trims BEFORE validating, so the error carries the
    // NORMALIZED value, not the caller's raw input.
    let err = parse("  CERTAIN  ").unwrap_err();
    assert_eq!(
        err.to_string(),
        r#"invalid confidence "certain" (expected low, medium, or high)"#
    );
}

/// Characterization (no Go test): the rank ordering `meets` is built on, probed
/// across the full 4x4 matrix of {low, medium, high, custom} x minimums.
#[test]
fn meets_full_matrix() {
    // (value, minimum) -> want. Anything with an invalid `value` is true
    // (back-compat), and an empty `minimum` is always true.
    let cases: &[(&str, &str, bool)] = &[
        ("low", "", true),
        ("low", "low", true),
        ("low", "medium", false),
        ("low", "high", false),
        ("medium", "", true),
        ("medium", "low", true),
        ("medium", "medium", true),
        ("medium", "high", false),
        ("high", "", true),
        ("high", "low", true),
        ("high", "medium", true),
        ("high", "high", true),
        // invalid `value` short-circuits to true regardless of minimum
        ("custom", "", true),
        ("custom", "low", true),
        ("custom", "high", true),
        ("", "low", true),
        // an invalid MINIMUM ranks 0, so any valid value clears it
        ("low", "bogus", true),
    ];
    for &(value, minimum, want) in cases {
        assert_eq!(
            meets(value, minimum),
            want,
            "meets({value:?}, {minimum:?})"
        );
    }
}

#[test]
fn attribute_const() {
    assert_eq!(ATTRIBUTE, "confidence");
}
