//! Port of Go `internal/confidence` (`confidence.go`).
//!
//! Faithful 1:1: the same three valid levels, the same rank ordering, and the
//! same "unset or custom values are retained" back-compat rule in [`meets`].

use std::error::Error;
use std::fmt;

/// Go `confidence.Attribute`.
pub const ATTRIBUTE: &str = "confidence";

/// Go `Parse`'s error. Go returns `fmt.Errorf("invalid confidence %q (expected
/// low, medium, or high)", value)`; the payload carries the offending value so
/// `Display` can reproduce that text exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidenceError {
    Invalid(String),
}

impl fmt::Display for ConfidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfidenceError::Invalid(value) => write!(
                f,
                "invalid confidence {} (expected low, medium, or high)",
                go_quote(value)
            ),
        }
    }
}

impl Error for ConfidenceError {}

/// Go `Valid`.
pub fn valid(value: &str) -> bool {
    value == "low" || value == "medium" || value == "high"
}

/// Go `Parse`.
pub fn parse(value: &str) -> Result<String, ConfidenceError> {
    // Go: `value = strings.ToLower(strings.TrimSpace(value))` — trim FIRST, then
    // lowercase. Both are applied before validation, so the error text below
    // carries the NORMALIZED value, exactly as Go's does.
    let value = value.trim().to_lowercase();
    if value.is_empty() || valid(&value) {
        return Ok(value);
    }
    Err(ConfidenceError::Invalid(value))
}

/// Go `Meets` — reports whether a finding confidence meets `minimum`. Unset or
/// custom values are retained for backward compatibility with arbitrary
/// attributes.
pub fn meets(value: &str, minimum: &str) -> bool {
    if minimum.is_empty() || !valid(value) {
        return true;
    }
    rank(value) >= rank(minimum)
}

fn rank(value: &str) -> i32 {
    match value {
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        _ => 0,
    }
}

/// Reproduce Go's `%q` verb (`strconv.Quote`) for the error text.
///
/// **Scope (flagged):** covers the cases this port can actually produce — ASCII
/// printables, the seven single-letter escapes, `\"`/`\\`, `\xHH` for other
/// non-printable ASCII, and non-ASCII passed through. Go additionally renders
/// non-printable NON-ASCII as `\uXXXX`/`\UXXXXXXXX`; that path is unreachable
/// here because `parse` only quotes a trimmed, lowercased value, but it is a
/// known gap rather than a claim of full `strconv.Quote` parity.
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
