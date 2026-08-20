//! Tests for the pretty (default `--verbose`) printer.
//!
//! Weighted almost entirely toward CARET POSITIONING, because that is the part
//! that can be confidently wrong: the caret must land under the secret after
//! the line has been control-stripped, tab-expanded and windowed to the
//! terminal width, and each of those steps moves byte offsets relative to
//! display columns. A caret under the wrong text is worse than no caret.

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
        line: format!("aws_key = {}", aws_key()),
        start_line: 7,
        start_column: 1,
        ..Default::default()
    }
}

fn render(f: &Finding) -> String {
    let mut buf = Vec::new();
    print_pretty(&mut buf, f, true, 0).expect("print");
    String::from_utf8(buf).expect("utf8")
}

/// Where the carets begin, in columns after the `│ N │ ` gutter.
fn caret_offset(out: &str) -> Option<usize> {
    let line = out.lines().find(|l| l.contains('^'))?;
    let body = line.split('│').nth(2)?;
    Some(body.len() - body.trim_start().len() - 1)
}

fn body_of(out: &str, needle: &str) -> String {
    out.lines()
        .find(|l| l.contains(needle))
        .and_then(|l| l.split('│').nth(2).map(|s| s.to_string()))
        .unwrap_or_default()
}

// ── the box ─────────────────────────────────────────────────────────────────

#[test]
fn the_box_is_drawn_around_the_finding() {
    let out = render(&finding());
    assert!(out.starts_with("┌─aws-access-token──○\n│\n"), "header:\n{out}");
    assert!(out.contains("└○"), "footer:\n{out}");
    assert!(out.contains(&format!("│ 7 │ aws_key = {}", aws_key())), "body:\n{out}");
}

/// **The caret must land under the secret**, not under the whole match.
#[test]
fn the_caret_row_underlines_exactly_the_secret() {
    let out = render(&finding());
    let carets = out.lines().find(|l| l.contains('^')).expect("a caret row");
    let count = carets.chars().filter(|c| *c == '^').count();
    assert_eq!(count, 20, "one caret per secret character:\n{out}");
    // `aws_key = ` is 10 characters, so the carets start at column 10.
    assert_eq!(caret_offset(&out), Some(10), "caret column:\n{out}");
}

/// **A TAB is 8 columns wide on screen but one byte in the string.** Without
/// expansion the caret lands eight columns early for every tab before it.
#[test]
fn tabs_are_expanded_before_the_caret_is_placed() {
    let mut f = finding();
    f.line = format!("\t{}", aws_key());
    f.r#match = format!("\t{}", aws_key());
    f.start_column = 0;
    let out = render(&f);

    let body = body_of(&out, &aws_key());
    assert!(!body.contains('\t'), "the tab must be expanded:\n{out}");
    let offset = caret_offset(&out).expect("a caret row");
    assert!(
        offset >= 2,
        "the caret must sit past the expanded tab, got {offset}:\n{out}"
    );
    // The rendered body and the caret row must agree on where the secret is.
    let leading_spaces = body.len() - body.trim_start().len();
    assert_eq!(
        offset,
        leading_spaces - 1,
        "caret and text disagree:\n{out}"
    );
}

/// ANSI escapes occupy bytes but zero columns. Left in, every position after
/// them shifts.
#[test]
fn terminal_control_sequences_are_stripped() {
    assert_eq!(strip_terminal_controls("a\u{1b}[31mb\u{1b}[0mc"), "abc");
    assert_eq!(strip_terminal_controls("a\u{7}b"), "ab", "BEL");
    assert_eq!(strip_terminal_controls("a\u{8}b"), "ab", "backspace");
    // Tab and newline are KEPT — tabs get expanded, newlines split lines.
    assert_eq!(strip_terminal_controls("a\tb\nc"), "a\tb\nc");
    // CR is kept too. Gos comment on the regex says CR is stripped, but its
    // character class is [\x00-\x08\x0b-\x0c\x0e-\x1f\x7f] and 0x0d is not in
    // it. The port follows the CODE, not the comment — and CR is handled
    // anyway, by the trims in normalize_snippet and split_lines.
    assert_eq!(strip_terminal_controls("a\rb"), "a\rb", "CR is NOT in Gos class");
}

#[test]
fn a_line_with_escapes_still_places_the_caret_correctly() {
    let mut f = finding();
    f.line = format!("\u{1b}[31maws_key\u{1b}[0m = {}", aws_key());
    let out = render(&f);
    assert!(!out.contains('\u{1b}'), "escapes must not reach the output:\n{out}");
    assert_eq!(caret_offset(&out), Some(10), "caret column after stripping:\n{out}");
}

// ── windowing ───────────────────────────────────────────────────────────────

#[test]
fn a_short_line_is_not_windowed() {
    let w = window_line("aws_key = SECRET", 10, 6, 80);
    assert_eq!(w.display, "aws_key = SECRET");
    assert_eq!(w.secret_start_col, 10);
    assert_eq!(w.secret_len_col, 6);
    assert!(!w.truncated);
}

/// A long line is windowed AROUND the secret — a minified bundle would
/// otherwise show 100 columns of noise and no finding.
#[test]
fn a_long_line_is_windowed_around_the_secret() {
    let line = format!("{}SECRET{}", "a".repeat(200), "b".repeat(200));
    let w = window_line(&line, 200, 6, 40);
    assert!(w.display.contains("SECRET"), "the secret must stay visible: {}", w.display);
    assert!(w.display.starts_with(WINDOW_ELLIPSIS), "elided on the left");
    assert!(w.display.ends_with(WINDOW_ELLIPSIS), "and on the right");
    assert!(display_width(&w.display) <= 40, "within budget: {}", w.display);
    // The reported column must point at the secret WITHIN the windowed text.
    let chars: Vec<char> = w.display.chars().collect();
    let at: String = chars[w.secret_start_col..w.secret_start_col + 6].iter().collect();
    assert_eq!(at, "SECRET", "the caret column must land on the secret");
}

/// A secret longer than the whole budget is clipped, and says so.
#[test]
fn a_secret_wider_than_the_budget_is_marked_truncated() {
    let line = "x".repeat(300);
    let w = window_line(&line, 0, 300, 40);
    assert!(w.truncated, "clipping must be reported");
    assert!(w.secret_len_col < 300);
}

#[test]
fn fit_to_budget_elides_rather_than_wrapping() {
    assert_eq!(fit_to_budget("short", 40), "short");
    let long = "a".repeat(100);
    let fitted = fit_to_budget(&long, 40);
    assert_eq!(display_width(&fitted), 40);
    assert!(fitted.ends_with(WINDOW_ELLIPSIS));
}

/// A clipped caret run ends in `.` rather than `^`, so the reader can see the
/// highlight is incomplete.
#[test]
fn a_truncated_caret_run_ends_in_a_dot() {
    let mut f = finding();
    f.secret = "S".repeat(400);
    f.line = format!("key = {}", f.secret);
    f.r#match = f.line.clone();
    f.start_column = 7;
    let out = render(&f);
    let carets = out.lines().find(|l| l.contains('^')).expect("caret row");
    assert!(carets.contains('.'), "truncation marker missing:\n{out}");
    assert!(carets.contains("(400 bytes)"), "the true length is stated:\n{out}");
}

// ── multi-line ──────────────────────────────────────────────────────────────

/// **The secret's own line is always shown**, even when it falls in the elided
/// middle — otherwise the finding's own text is what gets hidden.
#[test]
fn the_secrets_line_is_shown_even_when_the_middle_is_elided() {
    let mut lines: Vec<String> = (0..20).map(|i| format!("line {i}")).collect();
    lines[10] = format!("hidden = {}", aws_key());
    let mut f = finding();
    f.line = lines.join("\n");
    f.r#match = format!("hidden = {}", aws_key());
    f.start_column = 0;

    let out = render(&f);
    assert!(out.contains("more lines"), "the middle should be elided:\n{out}");
    assert!(
        out.contains(&aws_key()),
        "the secret's line must survive elision:\n{out}"
    );
    assert!(out.contains('^'), "and still carry a caret:\n{out}");
    assert!(
        out.contains("│ 17 │ hidden"),
        "line numbers stay absolute — start_line 7 + index 10:\n{out}"
    );
}

#[test]
fn the_head_and_tail_lines_are_kept() {
    let mut f = finding();
    f.line = (0..20).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
    f.r#match = "nowhere".to_string();
    f.secret = "nowhere".to_string();
    let out = render(&f);
    assert!(out.contains("line 0") && out.contains("line 1") && out.contains("line 2"));
    assert!(out.contains("line 19"), "the last line is kept");
    assert!(out.contains("more lines"));
}

/// Line numbers are padded to the widest, so the gutter stays aligned.
#[test]
fn line_numbers_are_padded_to_the_widest() {
    assert_eq!(line_num_width(1, 1), 1);
    assert_eq!(line_num_width(1, 10), 2);
    assert_eq!(line_num_width(995, 10), 4);
    assert_eq!(line_num_width(0, 0), 1, "never zero-width");
}

// ── unlocatable secrets ─────────────────────────────────────────────────────

/// **When the secret cannot be found in the line, NO caret is drawn.** Pointing
/// at an arbitrary column would be a confident lie.
#[test]
fn an_unlocatable_secret_renders_without_a_caret() {
    let mut f = finding();
    f.line = "a completely different line".to_string();
    f.r#match = "not here".to_string();
    f.secret = "nor here".to_string();
    let out = render(&f);
    assert!(out.contains("a completely different line"));
    assert!(!out.contains('^'), "no caret when the position is unknown:\n{out}");
}

#[test]
fn secret_bounds_prefer_the_match_and_column_over_a_bare_search() {
    let line = "a = SEC; b = SEC";
    // The column disambiguates which `SEC` the finding is about.
    assert_eq!(secret_byte_bounds(line, "b = SEC", "SEC", 10), Some((13, 3)));
    assert_eq!(secret_byte_bounds(line, "a = SEC", "SEC", 1), Some((4, 3)));
    assert_eq!(secret_byte_bounds(line, "nope", "nope", 0), None);
}

// ── file-only findings ──────────────────────────────────────────────────────

#[test]
fn a_file_only_finding_shows_no_snippet() {
    let mut f = finding();
    f.r#match = "file detected: id_rsa".to_string();
    f.secret = "id_rsa".to_string();
    f.line = String::new();
    f.attributes = HashMap::from([("path".to_string(), "keys/id_rsa".to_string())]);
    let out = render(&f);
    assert!(out.contains("┌─aws-access-token──○"));
    assert!(out.contains("attributes:"));
    assert!(out.contains("path"));
    assert!(!out.contains('^'), "nothing to point at:\n{out}");
}

// ── metadata ────────────────────────────────────────────────────────────────

#[test]
fn attributes_are_sorted_and_dot_leadered() {
    let mut f = finding();
    f.attributes = HashMap::from([
        ("zeta".to_string(), "3".to_string()),
        ("alpha".to_string(), "1".to_string()),
    ]);
    let out = render(&f);
    let a = out.find("alpha").unwrap();
    let z = out.find("zeta").unwrap();
    assert!(a < z, "sorted:\n{out}");
    assert!(out.contains("alpha ......"), "dot leader:\n{out}");
}

#[test]
fn validation_status_and_meta_are_shown() {
    let mut f = finding();
    f.validation_status = crate::ValidationStatus("valid".into());
    f.validation_reason = "200 OK".to_string();
    f.validation_meta = HashMap::from([("account".to_string(), serde_json::json!("acme"))]);
    let out = render(&f);
    assert!(out.contains("│ validation:"));
    assert!(out.contains("status"));
    assert!(out.contains("VALID"));
    assert!(out.contains("reason"));
    assert!(out.contains("200 OK"));
    assert!(out.contains("account"));
}

// ── component sets ──────────────────────────────────────────────────────────

fn set(status: &str, comps: &[(&str, i64, &str)]) -> ComponentSet {
    ComponentSet {
        validation_status: crate::ValidationStatus(status.to_string().into()),
        components: comps
            .iter()
            .map(|(rule, line, secret)| crate::ComponentFinding {
                rule_id: rule.to_string(),
                start_line: *line,
                secret: secret.to_string(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

/// **When any set validated, the invalid ones collapse to a count.** A rule with
/// several candidate pairs would otherwise bury the one that actually worked.
#[test]
fn invalid_component_sets_collapse_when_one_is_valid() {
    let mut f = finding();
    f.component_sets = vec![
        set("invalid", &[("aws-secret", 3, "aaa")]),
        set("valid", &[("aws-secret", 5, "bbb")]),
        set("invalid", &[("aws-secret", 9, "ccc")]),
    ];
    let out = render(&f);
    assert!(out.contains("│ components:"));
    assert!(out.contains("bbb"), "the valid set is shown:\n{out}");
    assert!(!out.contains("aaa"), "invalid sets are collapsed:\n{out}");
    assert!(out.contains("+ 2 invalid sets"), "with a count:\n{out}");
}

#[test]
fn all_sets_are_shown_when_none_validated() {
    let mut f = finding();
    f.component_sets = vec![
        set("", &[("aws-secret", 3, "aaa")]),
        set("", &[("aws-secret", 5, "bbb")]),
    ];
    let out = render(&f);
    assert!(out.contains("aaa") && out.contains("bbb"), "both shown:\n{out}");
    assert!(!out.contains("invalid set"), "nothing to collapse:\n{out}");
}

/// The icon appears only on a set's FIRST row — its presence is what separates
/// one set from the next.
#[test]
fn the_status_icon_delimits_a_multi_component_set() {
    let mut f = finding();
    f.component_sets = vec![set(
        "valid",
        &[("aws-key", 1, "AKIA..."), ("aws-secret", 2, "wJal...")],
    )];
    let out = render(&f);
    // Only the component ROWS, not the box header which also names the rule.
    let rows: Vec<&str> = out.lines().filter(|l| l.contains("aws-key:") || l.contains("aws-secret:")).collect();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].contains('✓'), "first row carries the icon: {}", rows[0]);
    assert!(!rows[1].contains('✓'), "continuation row does not: {}", rows[1]);
}

#[test]
fn set_icons_reflect_the_validation_status() {
    assert_eq!(pretty_set_icon("valid", true), "✓");
    assert_eq!(pretty_set_icon("invalid", true), "✗");
    assert_eq!(pretty_set_icon("error", true), "✗");
    assert_eq!(pretty_set_icon("needs_validation", true), "?");
    assert_eq!(pretty_set_icon("revoked", true), "!");
    assert_eq!(pretty_set_icon("", true), "-");
    assert_eq!(pretty_set_icon("something-new", true), "?");
}

// ── redaction ───────────────────────────────────────────────────────────────

#[test]
fn redaction_removes_the_secret_from_the_snippet_too() {
    let mut buf = Vec::new();
    print_pretty(&mut buf, &finding(), true, 100).expect("print");
    let out = String::from_utf8(buf).unwrap();
    assert!(
        !out.contains(&aws_key()),
        "the secret survived into the rendered line:\n{out}"
    );
    assert!(out.contains("REDACTED"));
}

#[test]
fn a_displayed_component_secret_is_capped_at_forty_runes() {
    let long = "x".repeat(100);
    let shown = redact_for_display(&long, 0);
    assert_eq!(shown.chars().count(), 43, "40 runes plus the ellipsis");
    assert!(shown.ends_with("..."));
    assert_eq!(redact_for_display("short", 0), "short");
    assert_eq!(redact_for_display("anything", 100), "REDACTED");
}

// ── terminal width ──────────────────────────────────────────────────────────

#[test]
fn the_terminal_width_comes_from_columns_with_a_floor() {
    // A too-small or unparseable value falls back to the default rather than
    // collapsing the layout.
    std::env::set_var("COLUMNS", "10");
    assert_eq!(terminal_cols(), DEFAULT_TERM_COLS);
    std::env::set_var("COLUMNS", "junk");
    assert_eq!(terminal_cols(), DEFAULT_TERM_COLS);
    std::env::set_var("COLUMNS", "120");
    assert_eq!(terminal_cols(), 120);
    std::env::remove_var("COLUMNS");
    assert_eq!(terminal_cols(), DEFAULT_TERM_COLS);
}

// ── tab expansion ───────────────────────────────────────────────────────────

#[test]
fn tab_expansion_respects_the_gutter_offset() {
    // Starting at column 0, a tab fills to the next multiple of 8.
    let (out, _) = expand_tabs_for_body("\tx", 0);
    assert_eq!(out, "        x");
    // Starting at column 5, the same tab only needs 3 spaces.
    let (out, _) = expand_tabs_for_body("\tx", 5);
    assert_eq!(out, "   x");
}

/// The mapping is what keeps the caret aligned — it translates a position in
/// the ORIGINAL line into one in the expanded line.
#[test]
fn the_expansion_mapping_tracks_every_offset() {
    let (out, mapping) = expand_tabs_for_body("a\tb", 0);
    assert_eq!(out, "a       b");
    assert_eq!(mapping[0], 0, "'a' stays at 0");
    assert_eq!(mapping[1], 1, "the tab starts at 1");
    assert_eq!(mapping[2], 8, "'b' moves to 8");
    assert_eq!(mapping[3], 9, "and the end to 9");
}

