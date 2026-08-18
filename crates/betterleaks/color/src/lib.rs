//! Port of Go `internal/color` (`color.go`) — ANSI styling for terminal output.
//!
//! **std-first:** Go uses `github.com/mattn/go-isatty`; Rust std has
//! [`std::io::IsTerminal`] (stable since 1.70), so NO crate is added.
//!
//! **Deviation (flagged):** Go's cache is
//! `isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)`. Rust std has no
//! `IsCygwinTerminal` equivalent — under a Cygwin/MSYS pty Go would colorize and
//! this port will not. Everything else is 1:1.

use std::io::IsTerminal;
use std::sync::OnceLock;

/// Go's package-level `isTTY`, "evaluated once at init and caches whether stdout
/// is a terminal". Go evaluates it at package init; Rust evaluates it on first
/// use and then caches — observationally identical for a process that never
/// reopens stdout.
fn is_tty() -> bool {
    static IS_TTY: OnceLock<bool> = OnceLock::new();
    *IS_TTY.get_or_init(|| std::io::stdout().is_terminal())
}

/// Go `color.Style` — ANSI formatting attributes. Go's methods take a VALUE
/// receiver and return a new `Style`, so the port is a consuming builder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Style {
    /// ANSI color escape (empty = no color). Go field `fg`.
    fg: String,
    bold: bool,
    italic: bool,
}

impl Style {
    /// Go `color.New()` — a new empty Style.
    pub fn new() -> Style {
        Style::default()
    }

    /// Go `Style.Foreground(hex)` — set the foreground from a hex string like
    /// `"#f05c07"`.
    pub fn foreground(mut self, hex: &str) -> Style {
        self.fg = hex_to_ansi(hex);
        self
    }

    /// Go `Style.Bold()`.
    pub fn bold(mut self) -> Style {
        self.bold = true;
        self
    }

    /// Go `Style.Italic()`.
    pub fn italic(mut self) -> Style {
        self.italic = true;
        self
    }

    /// Go `Style.Render(text)` — wrap `text` in the configured escapes. When
    /// stdout is not a TTY the codes are suppressed and `text` is returned as-is.
    pub fn render(&self, text: &str) -> String {
        self.render_with_tty(text, is_tty())
    }

    /// The TTY-independent half of [`Self::render`], split out so both branches
    /// are testable (Go's `isTTY` is a package var and is always false under
    /// `go test`, leaving the colorizing branch uncovered upstream).
    fn render_with_tty(&self, text: &str, tty: bool) -> String {
        if !tty {
            return text.to_string();
        }
        // Code order is part of the observable output: bold, italic, foreground.
        let mut codes: Vec<&str> = Vec::new();
        if self.bold {
            codes.push("1");
        }
        if self.italic {
            codes.push("3");
        }
        if !self.fg.is_empty() {
            codes.push(&self.fg);
        }
        if codes.is_empty() {
            return text.to_string();
        }
        format!("\x1b[{}m{}\x1b[0m", codes.join(";"), text)
    }
}

/// Go `hexToANSI` — convert `"#f05c07"` to a 24-bit ANSI escape code.
/// Unexported in Go, so private here.
///
/// Go slices the string by BYTES (`hex[0:2]`) and discards ParseUint's error, so
/// a multibyte char yields 0 for that channel rather than panicking. The port
/// works on `as_bytes()` for the same reason — a naive `&hex[0..2]` would panic
/// on a mid-rune boundary (see `hex_to_ansi_multibyte_does_not_panic`).
fn hex_to_ansi(hex: &str) -> String {
    let hex = hex.strip_prefix('#').unwrap_or(hex);
    let b = hex.as_bytes();
    if b.len() != 6 {
        return String::new();
    }
    let channel = |range: std::ops::Range<usize>| -> u8 {
        std::str::from_utf8(&b[range])
            .ok()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .unwrap_or(0)
    };
    format!(
        "38;2;{};{};{}",
        channel(0..2),
        channel(2..4),
        channel(4..6)
    )
}

#[cfg(test)]
mod tests;
