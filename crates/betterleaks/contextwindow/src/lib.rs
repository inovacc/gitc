//! Port of Go `internal/contextwindow` (`contextwindow.go`) — parses the
//! directional line/character window grammar shared by `--match-context` and a
//! component's `within` field, and extracts that window around a match.
//!
//! **std-first:** the Go source imports stdlib `regexp` for ONE anchored token
//! pattern, `(?i)^([+-]?)(\d+)([CL]?)$`. That is a fixed three-field shape, so
//! [`parse_token`] hand-rolls it rather than pulling a regex engine into a leaf
//! crate. Zero dependencies.
//!
//! **Byte semantics (important):** Go slices strings by BYTES and never panics
//! on a mid-rune boundary; `&str` slicing in Rust does. Column clipping is
//! defined in bytes, so a multibyte character CAN land inside a clip window.
//! The core therefore works on `&[u8]` ([`extract_bytes`]) and [`extract`] is a
//! `&str` convenience that converts with `from_utf8_lossy`.
//!
//! **Flagged deviation:** where Go would return a `string` holding invalid UTF-8
//! (a clip that split a character), [`extract`] substitutes U+FFFD. Go's string
//! type permits arbitrary bytes and Rust's `String` does not, so this cannot be
//! reproduced 1:1 through a `String` return. Use [`extract_bytes`] for the
//! faithful bytes.

use std::error::Error;
use std::fmt;

/// Go `contextwindow.Mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    None,
    Cols,
    Box,
}

/// Go `contextwindow.Spec` — directional context boundaries around a match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Spec {
    pub mode: Mode,
    pub cols_before: usize,
    pub cols_after: usize,
    pub lines_before: usize,
    pub lines_after: usize,
}

impl Spec {
    /// Go `Spec.IsZero` — reports whether no window is configured.
    pub fn is_zero(&self) -> bool {
        self.mode == Mode::None
    }
}

/// Go's `fmt.Errorf` cases from `Parse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextWindowError {
    /// `empty token in context window %q`
    EmptyToken(String),
    /// `invalid context window token %q`
    InvalidToken(String),
    /// `invalid context window amount %q: …`
    InvalidAmount(String),
    /// `invalid context window %q`
    Invalid(String),
}

impl fmt::Display for ContextWindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContextWindowError::EmptyToken(v) => {
                write!(f, "empty token in context window {}", go_quote(v))
            }
            ContextWindowError::InvalidToken(t) => {
                write!(f, "invalid context window token {}", go_quote(t))
            }
            ContextWindowError::InvalidAmount(a) => write!(
                f,
                "invalid context window amount {}: value out of range",
                go_quote(a)
            ),
            ContextWindowError::Invalid(v) => {
                write!(f, "invalid context window {}", go_quote(v))
            }
        }
    }
}

impl Error for ContextWindowError {}

/// Go's unexported `direction` accumulator.
#[derive(Default)]
struct Direction {
    before: usize,
    after: usize,
    bidirected: usize,
}

/// Go `applyDirection`. Each direction keeps its MAX, so a later token widens
/// the window rather than replacing it.
fn apply_direction(target: &mut Direction, marker: Option<u8>, amount: usize) {
    match marker {
        Some(b'-') => target.before = target.before.max(amount),
        Some(b'+') => target.after = target.after.max(amount),
        _ => target.bidirected = target.bidirected.max(amount),
    }
}

/// Hand-rolled equivalent of Go's `(?i)^([+-]?)(\d+)([CL]?)$`.
///
/// Returns `(marker, digits, unit)`. `unit` is upper-cased here so the caller
/// matches Go's `strings.ToUpper(matches[3])`.
fn parse_token(tok: &str) -> Option<(Option<u8>, &str, Option<u8>)> {
    let b = tok.as_bytes();
    let mut i = 0;

    let marker = match b.first() {
        Some(&c @ (b'+' | b'-')) => {
            i = 1;
            Some(c)
        }
        _ => None,
    };

    // `\d+` — at least one ASCII digit.
    let digits_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == digits_start {
        return None;
    }
    let digits = &tok[digits_start..i];

    // `([CL]?)` then `$`.
    let unit = match b.get(i) {
        None => None,
        Some(&c) if c.eq_ignore_ascii_case(&b'C') || c.eq_ignore_ascii_case(&b'L') => {
            i += 1;
            Some(c.to_ascii_uppercase())
        }
        Some(_) => return None,
    };
    if i != b.len() {
        return None; // trailing junk, e.g. "10L-"
    }

    Some((marker, digits, unit))
}

/// Go `Parse` — parses the grammar shared by `--match-context` and component
/// `within` fields.
pub fn parse(value: &str) -> Result<Spec, ContextWindowError> {
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return Ok(Spec::default());
    }

    let mut cols = Direction::default();
    let mut lines = Direction::default();
    let mut has_lines = false;
    let mut has_cols = false;

    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(ContextWindowError::EmptyToken(value.to_string()));
        }

        let Some((marker, digits, unit)) = parse_token(token) else {
            return Err(ContextWindowError::InvalidToken(token.to_string()));
        };

        // Go's `strconv.Atoi` fails on overflow; so does this parse.
        let Ok(amount) = digits.parse::<usize>() else {
            return Err(ContextWindowError::InvalidAmount(digits.to_string()));
        };

        // An absent unit defaults to "C".
        match unit.unwrap_or(b'C') {
            b'L' => {
                has_lines = true;
                // "10L" means 10 lines TOTAL, so 9 either side.
                apply_direction(&mut lines, marker, amount.saturating_sub(1));
            }
            _ => {
                has_cols = true;
                apply_direction(&mut cols, marker, amount);
            }
        }
    }

    let mut spec = Spec {
        cols_before: cols.before.max(cols.bidirected),
        cols_after: cols.after.max(cols.bidirected),
        ..Default::default()
    };

    if has_lines {
        spec.mode = Mode::Box;
        spec.lines_before = lines.before.max(lines.bidirected);
        spec.lines_after = lines.after.max(lines.bidirected);
    } else if has_cols {
        spec.mode = Mode::Cols;
    } else {
        // Unreachable in practice: every token sets one of the two flags.
        // Ported anyway so the shape stays 1:1 with the source.
        return Err(ContextWindowError::Invalid(value.to_string()));
    }

    Ok(spec)
}

/// Go `Extract` — the context selected by `spec` around `match_index` in `raw`.
///
/// See the module note: this converts with `from_utf8_lossy`; use
/// [`extract_bytes`] when the exact bytes matter.
pub fn extract(raw: &str, match_index: [usize; 2], spec: &Spec) -> String {
    String::from_utf8_lossy(&extract_bytes(raw.as_bytes(), match_index, spec)).into_owned()
}

/// The faithful, byte-exact core of [`extract`].
pub fn extract_bytes(raw: &[u8], match_index: [usize; 2], spec: &Spec) -> Vec<u8> {
    if spec.is_zero() || raw.is_empty() {
        return Vec::new();
    }
    match spec.mode {
        Mode::Cols => {
            let start = match_index[0].saturating_sub(spec.cols_before);
            let end = (match_index[1] + spec.cols_after).min(raw.len());
            raw[start..end].to_vec()
        }
        Mode::Box => extract_box(raw, match_index, spec),
        Mode::None => Vec::new(),
    }
}

fn extract_box(raw: &[u8], match_index: [usize; 2], spec: &Spec) -> Vec<u8> {
    let (match_start, match_end) = (match_index[0], match_index[1]);

    // Go: strings.LastIndexByte(raw[:matchStart], '\n') + 1 — a miss gives -1+1 = 0.
    let line_start = raw[..match_start]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(0, |i| i + 1);

    // Go: IndexByte(raw[matchEnd:], '\n'); -1 means "to the end".
    let line_end = raw[match_end..]
        .iter()
        .position(|&c| c == b'\n')
        .map_or(raw.len(), |i| i + match_end);

    let mut context_start = line_start;
    for _ in 0..spec.lines_before {
        if context_start == 0 {
            break;
        }
        context_start = raw[..context_start - 1]
            .iter()
            .rposition(|&c| c == b'\n')
            .map_or(0, |i| i + 1);
    }

    let mut context_end = line_end;
    for _ in 0..spec.lines_after {
        if context_end >= raw.len() {
            break;
        }
        match raw[context_end + 1..].iter().position(|&c| c == b'\n') {
            None => {
                context_end = raw.len();
                break;
            }
            Some(next) => context_end += next + 1,
        }
    }

    let extracted = &raw[context_start..context_end];

    // Column clipping only makes sense for single-line matches. For a multiline
    // match the first line's column offset does not apply to later lines.
    let match_spans_lines = raw[match_start..match_end].contains(&b'\n');
    if match_spans_lines || (spec.cols_before == 0 && spec.cols_after == 0) {
        return extracted.to_vec();
    }

    let match_column = match_start - line_start;
    let match_length = match_end - match_start;
    let clip_start = match_column.saturating_sub(spec.cols_before);
    let clip_end = match_column + match_length + spec.cols_after;

    let clipped: Vec<&[u8]> = extracted
        .split(|&c| c == b'\n')
        .map(|line| {
            // A short line is shown in FULL rather than clipped to nothing.
            let start = if line.len() <= clip_start { 0 } else { clip_start };
            &line[start..clip_end.min(line.len())]
        })
        .collect();

    clipped.join(&b'\n')
}

/// Reproduce Go's `%q` verb for the error texts.
///
/// **Known duplication:** `confidence` carries the same helper. Neither crate
/// depends on the other, and two copies of twenty lines beat a dependency edge
/// between leaves — but if a THIRD crate needs it, extract a shared helper
/// rather than copying again.
///
/// **Scope:** ASCII printables, the seven single-letter escapes, `\"`/`\\`, and
/// `\xHH`. Go additionally renders non-printable NON-ASCII as `\uXXXX`; these
/// inputs are config tokens, so that path is unreachable here.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;
