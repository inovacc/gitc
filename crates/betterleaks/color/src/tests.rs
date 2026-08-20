//! Characterization tests for the `color` port. Go `internal/color` has NO test
//! file, so these pin the observable behavior read off `color.go` — and they
//! exercise the colorizing branch that Go's own package-level `isTTY` makes
//! unreachable under `go test`.

use super::*;

/// `hexToANSI`: strips a leading `#`, requires exactly 6 chars, and renders
/// `38;2;R;G;B` in DECIMAL.
#[test]
fn hex_to_ansi_basic() {
    assert_eq!(hex_to_ansi("#f05c07"), "38;2;240;92;7");
    // The `#` is optional — Go uses TrimPrefix, not a requirement.
    assert_eq!(hex_to_ansi("f05c07"), "38;2;240;92;7");
    assert_eq!(hex_to_ansi("#000000"), "38;2;0;0;0");
    assert_eq!(hex_to_ansi("#ffffff"), "38;2;255;255;255");
    // Uppercase hex parses the same (Go's ParseUint is case-insensitive).
    assert_eq!(hex_to_ansi("#F05C07"), "38;2;240;92;7");
}

/// Wrong length (after trimming `#`) yields an EMPTY string, which `Render`
/// then treats as "no color".
#[test]
fn hex_to_ansi_wrong_length_is_empty() {
    for bad in ["", "#", "#fff", "fff", "#f05c0", "#f05c077", "#f05c07f"] {
        assert_eq!(hex_to_ansi(bad), "", "hex_to_ansi({bad:?})");
    }
}

/// Go discards ParseUint's error (`r, _ := ...`), so a non-hex digit yields 0
/// for that channel rather than failing.
#[test]
fn hex_to_ansi_invalid_digits_become_zero() {
    // "zz" fails to parse -> 0; "5c" parses -> 92.
    assert_eq!(hex_to_ansi("#zz5c07"), "38;2;0;92;7");
    assert_eq!(hex_to_ansi("#f0zz07"), "38;2;240;0;7");
    assert_eq!(hex_to_ansi("#f05czz"), "38;2;240;92;0");
    assert_eq!(hex_to_ansi("#zzzzzz"), "38;2;0;0;0");
}

/// A 6-BYTE input that is not 6 chars: Go slices `hex[0:2]` by BYTES and lets
/// ParseUint fail, so a multibyte char degrades to 0 rather than panicking.
/// This is the case a naive Rust `&hex[0..2]` would panic on.
#[test]
fn hex_to_ansi_multibyte_does_not_panic() {
    // "é" is 2 bytes in UTF-8, so this is 6 BYTES but only 5 chars.
    let s = "é05c0";
    assert_eq!(s.len(), 6, "precondition: 6 BYTES");
    // Go slices bytes: [0..2] is the two bytes of "é" (ParseUint fails -> 0),
    // [2..4] is "05" -> 5, [4..6] is "c0" -> 192.
    assert_eq!(hex_to_ansi(s), "38;2;0;5;192");
}

/// Not a TTY -> the text is returned untouched, whatever the style.
#[test]
fn render_without_tty_is_passthrough() {
    let s = Style::new().foreground("#f05c07").bold().italic();
    assert_eq!(s.render_with_tty("hello", false), "hello");
    assert_eq!(Style::new().render_with_tty("hello", false), "hello");
}

/// A TTY with NO attributes set also returns the text untouched — Go's
/// `if len(codes) == 0 { return text }` branch.
#[test]
fn render_with_tty_no_codes_is_passthrough() {
    assert_eq!(Style::new().render_with_tty("hello", true), "hello");
}

/// Code ORDER is part of the wire output: bold (`1`), then italic (`3`), then
/// the foreground — joined by `;`.
#[test]
fn render_with_tty_code_order() {
    let bold = Style::new().bold();
    assert_eq!(bold.render_with_tty("x", true), "\x1b[1mx\x1b[0m");

    let italic = Style::new().italic();
    assert_eq!(italic.render_with_tty("x", true), "\x1b[3mx\x1b[0m");

    let fg = Style::new().foreground("#f05c07");
    assert_eq!(fg.render_with_tty("x", true), "\x1b[38;2;240;92;7mx\x1b[0m");

    let all = Style::new().bold().italic().foreground("#f05c07");
    assert_eq!(
        all.render_with_tty("x", true),
        "\x1b[1;3;38;2;240;92;7mx\x1b[0m"
    );

    // Builder order must NOT change the emitted order.
    let reordered = Style::new().foreground("#f05c07").italic().bold();
    assert_eq!(
        reordered.render_with_tty("x", true),
        "\x1b[1;3;38;2;240;92;7mx\x1b[0m"
    );
}

/// An invalid-length hex leaves `fg` empty, so a bold+bad-color style emits
/// ONLY the bold code — the `if s.fg != ""` guard.
#[test]
fn render_with_tty_skips_empty_fg() {
    let s = Style::new().bold().foreground("#fff");
    assert_eq!(s.render_with_tty("x", true), "\x1b[1mx\x1b[0m");
}

/// Empty text still gets wrapped when codes are present (Go does not special-case it).
#[test]
fn render_with_tty_empty_text() {
    let s = Style::new().bold();
    assert_eq!(s.render_with_tty("", true), "\x1b[1m\x1b[0m");
}

/// Calling a setter twice is idempotent (Go sets a bool / overwrites `fg`).
#[test]
fn setters_are_idempotent_and_overwrite() {
    let s = Style::new().bold().bold();
    assert_eq!(s.render_with_tty("x", true), "\x1b[1mx\x1b[0m");

    let s = Style::new().foreground("#f05c07").foreground("#000000");
    assert_eq!(s.render_with_tty("x", true), "\x1b[38;2;0;0;0mx\x1b[0m");
}

/// `New()` is the zero value, matching Go's `Style{}`.
#[test]
fn new_is_default() {
    assert_eq!(Style::new(), Style::default());
}
