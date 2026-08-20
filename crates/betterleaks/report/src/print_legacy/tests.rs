//! Tests for the legacy finding printer.
//!
//! Go prints straight to stdout with `fmt.Printf`, which makes the format
//! untestable. Writing to a `Write` is the one reshape here, and it is what
//! lets these assertions exist at all.

use super::*;

/// AWS-shaped key, generated at runtime — no literal provider token is committed
/// anywhere in this repository (see the `testkeys` crate). Any valid key works
/// here; these tests only require that the same value goes in and comes out.
fn aws_key() -> String {
    testkeys::aws(1)
}
use std::collections::HashMap;

fn finding() -> Finding {
    Finding {
        rule_id: "aws-access-token".to_string(),
        secret: aws_key(),
        r#match: format!("aws_key = {}", aws_key()),
        line: format!("  aws_key = {}  ", aws_key()),
        start_line: 7,
        start_column: 3,
        entropy: 4.121928,
        fingerprint: "creds.txt:aws-access-token:7".to_string(),
        ..Default::default()
    }
}

fn render(f: &Finding, no_color: bool, redact: u32) -> String {
    let mut buf = Vec::new();
    print_legacy(&mut buf, f, no_color, redact).expect("print");
    String::from_utf8(buf).expect("utf8")
}

#[test]
fn the_key_value_layout_matches_go() {
    let out = render(&finding(), true, 0);
    assert!(out.contains(&format!("Finding:     aws_key = {}", aws_key())));
    assert!(out.contains(&format!("Secret:      {}", aws_key())));
    assert!(out.contains("RuleID:      aws-access-token"));
    assert!(out.contains("Line:        7"));
    assert!(out.contains("Fingerprint: creds.txt:aws-access-token:7"));
    // Go formats entropy with `%f` — six decimal places.
    assert!(out.contains("Entropy:     4.121928"), "got {out}");
}

/// Absent fields are OMITTED, not printed blank — an empty `Link:` line is
/// noise in a report a human has to read.
#[test]
fn absent_fields_are_omitted() {
    let out = render(&finding(), true, 0);
    assert!(!out.contains("Link:"));
    assert!(!out.contains("Tags:"));
    assert!(!out.contains("Context:"));
    assert!(!out.contains("Validation:"));
    assert!(!out.contains("Attributes:"));
}

#[test]
fn present_optional_fields_are_shown() {
    let mut f = finding();
    f.link = "https://github.com/o/r/blob/abc/creds.txt#L7".to_string();
    f.tags = vec!["aws".to_string(), "key".to_string()];
    let out = render(&f, true, 0);
    assert!(out.contains("Link:        https://github.com/o/r/blob/abc/creds.txt#L7"));
    assert!(out.contains("Tags:        aws, key"));
}

/// **Attributes are SORTED.** Go sorts the keys explicitly, because a map's
/// iteration order would make the output differ between runs of the same scan.
#[test]
fn attributes_are_printed_in_sorted_order() {
    let mut f = finding();
    f.attributes = HashMap::from([
        ("zeta".to_string(), "3".to_string()),
        ("alpha".to_string(), "1".to_string()),
        ("mid".to_string(), "2".to_string()),
    ]);
    let out = render(&f, true, 0);
    let a = out.find("alpha").unwrap();
    let m = out.find("mid").unwrap();
    let z = out.find("zeta").unwrap();
    assert!(a < m && m < z, "attributes must be sorted:\n{out}");
}

// ── redaction ───────────────────────────────────────────────────────────────

/// **A printed secret is a leak the scanner caused.** `--redact` must reach
/// every field the secret appears in, not just the `Secret:` line.
#[test]
fn full_redaction_replaces_the_secret_everywhere() {
    let mut f = finding();
    f.match_context = format!("  aws_key = {}", aws_key());
    let out = render(&f, true, 100);
    assert!(
        !out.contains(&aws_key()),
        "the secret survived redaction:\n{out}"
    );
    assert!(out.contains("REDACTED"));
    assert!(out.contains("Finding:     aws_key = REDACTED"), "the match too:\n{out}");
}

/// A partial mask KEEPS a prefix and appends `...` — Go's `MaskSecret` shows
/// enough to recognise the value while not printing it whole.
#[test]
fn partial_redaction_keeps_a_prefix_and_elides_the_rest() {
    let out = render(&finding(), true, 50);
    assert!(!out.contains(&aws_key()), "the whole secret must not appear");
    assert!(!out.contains("REDACTED"), "only 100 uses the word");
    // 20 chars at 50% keeps 10.
    assert!(out.contains(&format!("Secret:      {}...", &aws_key()[..10])), "got:\n{out}");
}

#[test]
fn no_redaction_shows_the_secret() {
    assert!(render(&finding(), true, 0).contains(&aws_key()));
}

// ── colour ──────────────────────────────────────────────────────────────────

/// `--no-color` must emit NO escape sequences — the output is frequently piped
/// into a file or a CI log where they are noise.
#[test]
fn no_color_emits_no_escape_sequences() {
    let out = render(&finding(), true, 0);
    assert!(!out.contains('\u{1b}'), "found an escape sequence:\n{out:?}");
}

/// With colour ENABLED the `Finding:` line is RECONSTRUCTED from the source
/// line (lead-in + match + trailing context) rather than printed as the bare
/// match. That difference is observable without a terminal, which matters:
/// `color::render` is a no-op off a TTY — faithful to Go, whose `isTTY` is a
/// package var — so escape sequences cannot be asserted here at all.
#[test]
fn the_colour_branch_reconstructs_the_line_around_the_match() {
    let mut f = finding();
    f.line = format!("  aws_key = {}  # trailing comment here", aws_key());

    let plain = render(&f, true, 0);
    let coloured = render(&f, false, 0);

    assert!(
        plain.contains(&format!("Finding:     aws_key = {}\n", aws_key())),
        "the no-colour branch prints the bare match:\n{plain}"
    );
    assert!(
        coloured.contains("# trailing comment"),
        "the colour branch carries the surrounding line:\n{coloured}"
    );
    assert!(coloured.contains(&aws_key()));
}

/// A long trailing context is truncated, so one minified line cannot fill the
/// screen.
#[test]
fn a_long_trailing_context_is_elided() {
    let mut f = finding();
    f.line = format!("aws_key = {}{}", aws_key(), "x".repeat(200));
    f.start_column = 1;
    let out = render(&f, false, 0);
    assert!(out.contains("..."), "the tail should be elided:\n{out}");
    assert!(!out.contains(&"x".repeat(30)), "and not printed whole");
}

/// A path-only rule reports `file detected: …` and has no line to highlight, so
/// it takes the plain branch.
#[test]
fn a_file_match_is_printed_plainly() {
    let mut f = finding();
    f.r#match = "file detected: id_rsa".to_string();
    f.secret = "id_rsa".to_string();
    f.line = String::new();
    let out = render(&f, false, 0);
    assert!(out.contains("Finding:     file detected: id_rsa"));
    assert!(out.contains("Secret:      id_rsa"));
}

// ── locate_match ────────────────────────────────────────────────────────────

/// **The column is trusted first**, because a line can contain the match text
/// more than once and the column says WHICH one.
#[test]
fn the_start_column_disambiguates_a_repeated_match() {
    let line = "key = A; key = A";
    // 1-based column 15 is the SECOND `key = A`... the match here is just `A`.
    assert_eq!(locate_match(line, "A", 7), Some(6), "the first A");
    assert_eq!(locate_match(line, "A", 16), Some(15), "the second A");
}

#[test]
fn a_wrong_column_falls_back_to_searching_forward() {
    let line = "aaa SECRET bbb";
    // Column points past the match; the forward search from there fails, so it
    // falls back to a full search.
    assert_eq!(locate_match(line, "SECRET", 99), Some(4));
}

#[test]
fn locate_match_handles_absent_and_empty_input() {
    assert_eq!(locate_match("", "x", 1), None);
    assert_eq!(locate_match("line", "", 1), None);
    assert_eq!(locate_match("line", "nope", 1), None);
}

/// A multi-byte line must not panic when the column lands mid-character.
#[test]
fn locate_match_is_utf8_safe() {
    let line = "héllo SECRET wörld";
    assert!(locate_match(line, "SECRET", 2).is_some());
    // A column inside the two-byte `é` must not slice mid-character.
    assert!(locate_match(line, "SECRET", 3).is_some());
}

// ── validation ──────────────────────────────────────────────────────────────

#[test]
fn a_validation_status_is_printed_with_its_reason_and_meta() {
    let mut f = finding();
    f.validation_status = crate::ValidationStatus("valid".into());
    f.validation_reason = "200 from the provider".to_string();
    f.validation_meta = HashMap::from([
        ("status".to_string(), serde_json::json!(200)),
        ("account".to_string(), serde_json::json!("acme")),
    ]);
    let out = render(&f, true, 0);
    assert!(out.contains("Validation:  VALID"), "got {out}");
    assert!(out.contains("(200 from the provider)"));
    // Sorted, for the same reproducibility reason as attributes.
    let a = out.find("account").unwrap();
    let s = out.find("status").unwrap();
    assert!(a < s, "validation meta must be sorted:\n{out}");
}

// ── context ─────────────────────────────────────────────────────────────────

#[test]
fn the_match_context_is_indented() {
    let ctx = format_match_context("line one\nline two", "m", "s", true);
    assert_eq!(ctx, "    line one\n    line two");
}

/// The context keeps its text either way. Colour cannot be asserted here:
/// `color::render` is a no-op off a TTY, faithfully to Go.
#[test]
fn the_context_text_survives_both_colour_modes() {
    for no_color in [true, false] {
        let ctx = format_match_context("prefix SECRET suffix", "m = SECRET", "SECRET", no_color);
        assert!(ctx.contains("SECRET"), "no_color={no_color}");
        assert!(ctx.starts_with("    "), "always indented");
    }
    let plain = format_match_context("prefix SECRET suffix", "m", "SECRET", true);
    assert!(!plain.contains('\u{1b}'), "no colour when asked for none");
}

