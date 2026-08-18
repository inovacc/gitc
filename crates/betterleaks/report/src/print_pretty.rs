//! Port of Go `report/print_pretty.go` — the DEFAULT `--verbose` finding
//! format: a boxed snippet with the offending line and a caret row under the
//! secret.
//!
//! ## Why this is more than layout code
//!
//! The caret has to land under the secret, in a terminal, after the line has
//! been tab-expanded, control-stripped and possibly windowed to fit the
//! width. Every one of those steps moves byte offsets relative to display
//! columns, and getting the correspondence wrong points the reader at the wrong
//! part of the line — which is worse than no caret at all.
//!
//! Go's approach, ported here: normalise the line, EXPAND TABS first (recording
//! a byte-offset mapping), then do all caret arithmetic in display columns and
//! never convert back.
//!
//! ## The reshape
//!
//! Go prints with `fmt.Printf` straight to stdout. This writes to a `Write`, so
//! the layout is testable — the whole reason this module has tests where Go's
//! has none.

use crate::finding::mask_secret;
use crate::{ComponentSet, Finding};
use std::io::{self, Write};

/// Go's terminal constants.
pub const DEFAULT_TERM_COLS: usize = 100;
pub const MIN_TERM_COLS: usize = 60;
pub const TAB_STOP: usize = 8;
/// One rune, one display column.
pub const WINDOW_ELLIPSIS: &str = "…";
pub const MAX_HEAD_LINES: usize = 3;
pub const MAX_TAIL_LINES: usize = 1;
pub const MIN_LINE_NUM_WIDTH: usize = 1;

/// Go `terminalCols` — `$COLUMNS`, else the default.
///
/// Re-read per finding so a resize is picked up without restarting, and floored
/// at `MIN_TERM_COLS` so an absurd value cannot collapse the layout.
pub fn terminal_cols() -> usize {
    if let Ok(v) = std::env::var("COLUMNS") {
        if let Ok(n) = v.parse::<usize>() {
            if n >= MIN_TERM_COLS {
                return n;
            }
        }
    }
    DEFAULT_TERM_COLS
}

/// Go `displayWidth` — one column per RUNE.
///
/// Deliberately not grapheme- or east-asian-width aware, and Go says why: a
/// secret is in practice ASCII (base64, hex, a token), so double-counting CJK
/// would add a dependency and a class of bugs for no gain on the data that
/// actually appears.
pub fn display_width(s: &str) -> usize {
    s.chars().count()
}

/// Display columns occupied by `s[..byte_end]`.
pub fn rune_prefix_width(s: &str, byte_end: usize) -> usize {
    let mut end = byte_end.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    display_width(&s[..end])
}

/// Go `byteAtCol` — the byte index of the `target_col`-th rune.
pub fn byte_at_col(s: &str, target_col: usize) -> usize {
    let mut col = 0;
    for (i, _) in s.char_indices() {
        if col == target_col {
            return i;
        }
        col += 1;
    }
    s.len()
}

/// Go `expandTabsForBody` — replace tabs with the spaces a terminal would
/// render, given that the body starts at `gutter_cols`.
///
/// Returns the expanded text AND a byte-offset mapping, because every later
/// step needs to translate a position in the ORIGINAL line into one in the
/// rendered line. Expanding without the mapping is what makes carets drift.
pub fn expand_tabs_for_body(s: &str, gutter_cols: usize) -> (String, Vec<usize>) {
    let mut mapping = vec![0usize; s.len() + 1];
    let mut out = String::with_capacity(s.len());
    let mut col = gutter_cols;
    for (i, ch) in s.char_indices() {
        mapping[i] = out.len();
        if ch == '\t' {
            let w = TAB_STOP - (col % TAB_STOP);
            for _ in 0..w {
                out.push(' ');
            }
            col += w;
            continue;
        }
        out.push(ch);
        col += 1;
    }
    mapping[s.len()] = out.len();
    (out, mapping)
}

/// Go `truncateRunes` — `(text, was_truncated)`.
pub fn truncate_runes(s: &str, max_runes: usize) -> (String, bool) {
    if max_runes == 0 {
        return (String::new(), true);
    }
    let mut n = 0;
    for (i, _) in s.char_indices() {
        if n == max_runes {
            return (s[..i].to_string(), true);
        }
        n += 1;
    }
    (s.to_string(), false)
}

/// Go `lineNumWidth` — digits needed for the largest line number shown.
pub fn line_num_width(start_line: i64, line_count: usize) -> usize {
    let mut max_line = (start_line + line_count as i64 - 1).max(1);
    let mut w = 0;
    while max_line > 0 {
        w += 1;
        max_line /= 10;
    }
    w.max(MIN_LINE_NUM_WIDTH)
}

/// Go `terminalControlRe` — ANSI escapes plus zero-width/destructive controls.
///
/// **These must go before ANY caret arithmetic.** They occupy bytes but zero (or
/// negative) display columns, so leaving them in shifts every subsequent
/// position. Tab and newline are deliberately KEPT — tabs are expanded properly
/// a step later, and newlines separate the lines.
pub fn strip_terminal_controls(s: &str) -> String {
    let bytes: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == '\u{1b}' {
            // CSI: ESC [ params intermediates final
            if i + 1 < bytes.len() && bytes[i + 1] == '[' {
                let mut j = i + 2;
                while j < bytes.len() && matches!(bytes[j], '0'..='9' | ';' | '?') {
                    j += 1;
                }
                while j < bytes.len() && (' '..='/').contains(&bytes[j]) {
                    j += 1;
                }
                if j < bytes.len() && ('@'..='~').contains(&bytes[j]) {
                    i = j + 1;
                    continue;
                }
            }
            // OSC: ESC ] … BEL or ESC \
            if i + 1 < bytes.len() && bytes[i + 1] == ']' {
                let mut j = i + 2;
                while j < bytes.len() && bytes[j] != '\u{07}' && bytes[j] != '\u{1b}' {
                    j += 1;
                }
                if j < bytes.len() {
                    if bytes[j] == '\u{07}' {
                        i = j + 1;
                        continue;
                    }
                    if j + 1 < bytes.len() && bytes[j + 1] == '\\' {
                        i = j + 2;
                        continue;
                    }
                }
            }
            // Two-character escape: ESC @..Z \..._
            if i + 1 < bytes.len()
                && (('@'..='Z').contains(&bytes[i + 1]) || ('\\'..='_').contains(&bytes[i + 1]))
            {
                i += 2;
                continue;
            }
        }
        // Bare control characters, EXCEPT tab and newline.
        let cp = c as u32;
        if (cp <= 0x08) || (0x0b..=0x0c).contains(&cp) || (0x0e..=0x1f).contains(&cp) || cp == 0x7f {
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

pub fn has_terminal_controls(s: &str) -> bool {
    strip_terminal_controls(s) != s
}

/// Go `normalizeSnippet`.
///
/// Note `start_column` is RESET when controls are stripped: the offsets it
/// referred to no longer exist, and `secret_byte_bounds` will relocate the
/// secret by searching. Keeping a stale column would aim the caret confidently
/// at the wrong place.
pub fn normalize_snippet(f: &Finding) -> Finding {
    let mut out = f.clone();
    out.line = f.line.trim_end_matches(['\r', '\n']).to_string();
    out.r#match = f.r#match.trim_end_matches(['\r', '\n']).to_string();
    out.secret = f.secret.trim_end_matches(['\r', '\n']).to_string();

    let n = out
        .line
        .bytes()
        .take_while(|b| *b == b'\n' || *b == b'\r')
        .count();
    if n > 0 {
        out.line = out.line[n..].to_string();
        out.start_column = if out.start_column > n as i64 {
            out.start_column - n as i64
        } else {
            0
        };
    }
    if has_terminal_controls(&out.line) {
        out.line = strip_terminal_controls(&out.line);
        out.r#match = strip_terminal_controls(&out.r#match);
        out.secret = strip_terminal_controls(&out.secret);
        out.start_column = 0;
    }
    out
}

pub fn split_lines(s: &str) -> Vec<String> {
    s.split('\n')
        .map(|l| l.trim_end_matches('\r').to_string())
        .collect()
}

/// Go `segmentForSecret` — `(line index, byte offset within that line)`.
pub fn segment_for_secret(text: &str, secret_start_byte: usize) -> (usize, usize) {
    let secret_start_byte = secret_start_byte.min(text.len());
    let mut seg_idx = 0;
    let mut line_start = 0;
    for (i, b) in text.bytes().enumerate().take(secret_start_byte) {
        if b == b'\n' {
            seg_idx += 1;
            line_start = i + 1;
        }
    }
    (seg_idx, secret_start_byte - line_start)
}

/// Go `secretByteBounds` — where the secret actually is in the line.
///
/// Four strategies in Go's order, and the ORDER is the point: the match plus the
/// column hint first (which disambiguates a line containing the secret twice),
/// then a plain search, then the raw column. Returning `None` is honest — the
/// caller then renders the line with no caret rather than pointing somewhere
/// arbitrary.
pub fn secret_byte_bounds(
    line: &str,
    m: &str,
    secret: &str,
    start_col1: i64,
) -> Option<(usize, usize)> {
    if secret.is_empty() {
        let mi = crate::locate_match(line, m, start_col1).or_else(|| line.find(m))?;
        return Some((mi, m.len()));
    }
    if let Some(mi) = crate::locate_match(line, m, start_col1) {
        if let Some(rel) = m.find(secret) {
            let s = mi + rel;
            if s + secret.len() <= line.len()
                && line.is_char_boundary(s)
                && line.is_char_boundary(s + secret.len())
                && &line[s..s + secret.len()] == secret
            {
                return Some((s, secret.len()));
            }
        }
    }
    if let Some(si) = line.find(secret) {
        return Some((si, secret.len()));
    }
    if start_col1 > 0 {
        let b = (start_col1 - 1) as usize;
        if b + secret.len() <= line.len()
            && line.is_char_boundary(b)
            && line.is_char_boundary(b + secret.len())
            && &line[b..b + secret.len()] == secret
        {
            return Some((b, secret.len()));
        }
    }
    None
}

/// The result of fitting one line to the terminal width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub display: String,
    /// Columns from the body start to the visible secret.
    pub secret_start_col: usize,
    /// Display width of the VISIBLE part of the secret.
    pub secret_len_col: usize,
    /// Whether windowing clipped any of the secret.
    pub truncated: bool,
}

/// Go `windowLine` — fit one line to `budget_cols`, centred on the secret.
///
/// All later caret arithmetic reads these DISPLAY-COLUMN values directly; no
/// byte-to-column conversion happens outside this function. Input must already
/// be tab-free.
pub fn window_line(
    line: &str,
    secret_start_byte: usize,
    secret_len_byte: usize,
    budget_cols: usize,
) -> Window {
    let budget_cols = budget_cols.max(10);
    let secret_start_byte = secret_start_byte.min(line.len());
    let secret_end_byte = (secret_start_byte + secret_len_byte)
        .min(line.len())
        .max(secret_start_byte);

    let full_cols = display_width(line);
    let secret_start_col_abs = rune_prefix_width(line, secret_start_byte);

    if full_cols <= budget_cols {
        return Window {
            display: line.to_string(),
            secret_start_col: secret_start_col_abs,
            secret_len_col: display_width(&line[secret_start_byte..secret_end_byte]),
            truncated: false,
        };
    }

    // Give the secret roughly a quarter of the budget as leading context, then
    // take the rest. Two columns are reserved for the ellipsis markers.
    let context_before = (budget_cols / 4).max(6);
    let mut win_start_col = secret_start_col_abs.saturating_sub(context_before);
    let inner_budget = if budget_cols >= 6 {
        budget_cols - 2
    } else {
        budget_cols - 1
    };
    let mut win_end_col = win_start_col + inner_budget;
    if win_end_col > full_cols {
        win_end_col = full_cols;
        win_start_col = win_end_col.saturating_sub(inner_budget);
    }

    let win_start_byte = byte_at_col(line, win_start_col);
    let win_end_byte = byte_at_col(line, win_end_col).max(win_start_byte);

    let lead = if win_start_byte > 0 { WINDOW_ELLIPSIS } else { "" };
    let trail = if win_end_byte < line.len() { WINDOW_ELLIPSIS } else { "" };
    let display = format!("{lead}{}{trail}", &line[win_start_byte..win_end_byte]);
    let lead_cols = display_width(lead);

    let win_start_col_actual = rune_prefix_width(line, win_start_byte);
    let secret_start_col = if secret_start_byte >= win_start_byte {
        lead_cols + (secret_start_col_abs - win_start_col_actual)
    } else {
        // The secret began before the window — anchor the carets at the lead
        // ellipsis rather than at a negative column.
        lead_cols
    };

    let vis_start = secret_start_byte.max(win_start_byte);
    let vis_end = secret_end_byte.min(win_end_byte).max(vis_start);
    Window {
        display,
        secret_start_col,
        secret_len_col: display_width(&line[vis_start..vis_end]),
        truncated: vis_start != secret_start_byte || vis_end != secret_end_byte,
    }
}

/// Go `fitToBudget` — trim to `budget_cols`, appending an ellipsis if cut.
pub fn fit_to_budget(s: &str, budget_cols: usize) -> String {
    let s = s.trim_end_matches([' ', '\r']);
    if display_width(s) <= budget_cols {
        return s.to_string();
    }
    let cut = byte_at_col(s, budget_cols.saturating_sub(1));
    format!("{}{WINDOW_ELLIPSIS}", &s[..cut])
}

/// Go `redactForDisplay` — mask, then cap at 40 runes.
pub fn redact_for_display(secret: &str, redact: u32) -> String {
    let mut secret = secret.to_string();
    if redact > 0 {
        if redact >= 100 {
            return "REDACTED".to_string();
        }
        secret = mask_secret(&secret, redact);
    }
    let secret = secret.trim().to_string();
    match truncate_runes(&secret, 40) {
        (t, true) => format!("{t}..."),
        (t, false) => t,
    }
}

/// Go `prettySetIcon` — the per-component-set validation glyph.
pub fn pretty_set_icon(status: &str, no_color: bool) -> String {
    let lower = status.trim().to_lowercase();
    let icon = match lower.as_str() {
        "valid" => "✓",
        "invalid" | "error" => "✗",
        "needs_validation" => "?",
        "revoked" => "!",
        "" => "-",
        _ => "?",
    };
    if no_color {
        return icon.to_string();
    }
    let style = match lower.as_str() {
        "valid" => color::Style::new().foreground("#00d26a"),
        "invalid" | "error" => color::Style::new().foreground("#888888"),
        "needs_validation" => color::Style::new().foreground("#60a5fa"),
        "revoked" => color::Style::new().foreground("#f5d445"),
        _ => color::Style::new().foreground("#c0c0c0"),
    };
    style.render(icon)
}

// ── the box ─────────────────────────────────────────────────────────────────

fn write_header<W: Write>(w: &mut W, f: &Finding) -> io::Result<()> {
    writeln!(w, "┌─{}──○", f.rule_id)?;
    writeln!(w, "│")
}

fn write_row<W: Write>(w: &mut W, line_num: i64, pad: usize, body: &str) -> io::Result<()> {
    writeln!(w, "│ {line_num:<pad$} │ {body}")
}

fn write_caret_row<W: Write>(
    w: &mut W,
    pad: usize,
    pad_cols: usize,
    ptr_cols: usize,
    ptr_truncated: bool,
    label: &str,
    no_color: bool,
) -> io::Result<()> {
    let mut carets = "^".repeat(ptr_cols);
    if ptr_truncated && ptr_cols >= 1 {
        // The last caret becomes a dot — the reader can see the highlight is
        // clipped rather than believing the secret ends there.
        carets = format!("{}.", &carets[..ptr_cols - 1]);
    }
    let gutter = format!("│ {} │ ", " ".repeat(pad));
    let mut body = format!("{}{carets}{label}", " ".repeat(pad_cols));
    if !no_color {
        body = color::Style::new().bold().foreground("#ef4444").render(&body);
    }
    writeln!(w, "{gutter}{body}")
}

fn write_more_lines_row<W: Write>(w: &mut W, pad: usize, hidden: usize) -> io::Result<()> {
    writeln!(w, "│ {} │ {WINDOW_ELLIPSIS} ({hidden} more lines)", " ".repeat(pad))
}

fn write_footer<W: Write>(w: &mut W) -> io::Result<()> {
    write!(w, "└○\n\n\n")
}

/// Go `dotLeader` — `key ...... value`, aligned to the longest key.
fn dot_leader<W: Write>(w: &mut W, key: &str, value: &str, max_key: usize) -> io::Result<()> {
    let dots = ".".repeat((max_key + 6).saturating_sub(key.len()));
    writeln!(w, "│   {key} {dots} {value}")
}

/// Go `(Finding).printPretty` — the whole box.
pub fn print_pretty<W: Write>(
    w: &mut W,
    f: &Finding,
    no_color: bool,
    redact: u32,
) -> io::Result<()> {
    let mut f = f.clone();
    if redact > 0 {
        let secret = if redact >= 100 {
            "REDACTED".to_string()
        } else {
            mask_secret(&f.secret, redact)
        };
        f.line = f.line.replace(&f.secret, &secret);
        f.r#match = f.r#match.replace(&f.secret, &secret);
        f.match_context = f.match_context.replace(&f.secret, &secret);
        f.secret = secret;
    }

    if f.r#match.trim().starts_with("file detected:") {
        return print_pretty_file_only(w, &f, no_color, redact);
    }

    let work = normalize_snippet(&f);
    write_header(w, &work)?;

    let mut raw_lines = split_lines(&work.line);
    if raw_lines.is_empty() {
        raw_lines = vec![String::new()];
    }
    let pad = line_num_width(work.start_line, raw_lines.len());
    // The gutter is `│ %*d │ ` — five single-column runes plus the digits.
    let gutter_cols = pad + 5;
    let budget = terminal_cols()
        .saturating_sub(gutter_cols)
        .max(MIN_TERM_COLS - 10);

    // Tabs are expanded FIRST, so every position below is a display column.
    let mut lines = Vec::with_capacity(raw_lines.len());
    let mut mappings = Vec::with_capacity(raw_lines.len());
    for l in &raw_lines {
        let (expanded, mapping) = expand_tabs_for_body(l, gutter_cols);
        lines.push(expanded);
        mappings.push(mapping);
    }

    let bounds = secret_byte_bounds(&work.line, &work.r#match, &work.secret, work.start_column);
    let Some((start_byte, len_byte)) = bounds else {
        // The secret could not be located. Render the lines with NO caret
        // rather than aiming one at an arbitrary column.
        render_lines_only(w, &lines, work.start_line, pad, budget)?;
        print_pretty_meta(w, &work, no_color, redact)?;
        return write_footer(w);
    };

    let (seg_idx, secret_byte_in_seg_raw) = segment_for_secret(&work.line, start_byte);
    let seg_idx = seg_idx.min(lines.len() - 1);
    let mapping = &mappings[seg_idx];
    let secret_byte_in_seg = mapping[secret_byte_in_seg_raw.min(mapping.len() - 1)];
    let raw_bytes_in_seg = len_byte
        .min(raw_lines[seg_idx].len().saturating_sub(secret_byte_in_seg_raw));
    let bytes_in_seg = mapping[(secret_byte_in_seg_raw + raw_bytes_in_seg).min(mapping.len() - 1)]
        .saturating_sub(secret_byte_in_seg);

    if lines.len() == 1 {
        render_line_with_caret(
            w, &lines[seg_idx], work.start_line, secret_byte_in_seg, bytes_in_seg, len_byte,
            budget, pad, no_color,
        )?;
    } else {
        render_multi_line(
            w, &lines, work.start_line, seg_idx, secret_byte_in_seg, bytes_in_seg, len_byte,
            budget, pad, no_color,
        )?;
    }

    print_pretty_meta(w, &work, no_color, redact)?;
    write_footer(w)
}

#[allow(clippy::too_many_arguments)]
fn render_line_with_caret<W: Write>(
    w: &mut W,
    secret_line: &str,
    line_num: i64,
    secret_byte_in_seg: usize,
    bytes_in_seg: usize,
    full_secret_len: usize,
    budget: usize,
    pad: usize,
    no_color: bool,
) -> io::Result<()> {
    let win = window_line(secret_line, secret_byte_in_seg, bytes_in_seg, budget);
    write_row(w, line_num, pad, &win.display)?;

    // Truncated either because the window clipped it, or because the secret
    // spans past the end of this line.
    let ptr_trunc = win.truncated || bytes_in_seg < full_secret_len;
    let label = if ptr_trunc {
        format!(" ({full_secret_len} bytes)")
    } else {
        String::new()
    };
    write_caret_row(
        w,
        pad,
        win.secret_start_col,
        win.secret_len_col,
        ptr_trunc,
        &label,
        no_color,
    )
}

/// Which lines to show: the first few, the last one, and (elsewhere) a
/// "(N more lines)" marker. A 500-line fragment must not fill the screen.
fn marked_lines(n: usize, always: Option<usize>) -> Vec<bool> {
    let mut mark = vec![false; n];
    for m in mark.iter_mut().take(MAX_HEAD_LINES.min(n)) {
        *m = true;
    }
    for i in n.saturating_sub(MAX_TAIL_LINES)..n {
        mark[i] = true;
    }
    if let Some(i) = always {
        if i < n {
            mark[i] = true;
        }
    }
    mark
}

fn render_lines_only<W: Write>(
    w: &mut W,
    lines: &[String],
    start_line: i64,
    pad: usize,
    budget: usize,
) -> io::Result<()> {
    let mark = marked_lines(lines.len(), None);
    let mut i = 0;
    while i < lines.len() {
        if mark[i] {
            write_row(w, start_line + i as i64, pad, &fit_to_budget(&lines[i], budget))?;
            i += 1;
            continue;
        }
        let mut j = i;
        while j < lines.len() && !mark[j] {
            j += 1;
        }
        write_more_lines_row(w, pad, j - i)?;
        i = j;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_multi_line<W: Write>(
    w: &mut W,
    lines: &[String],
    start_line: i64,
    seg_idx: usize,
    secret_byte_in_seg: usize,
    bytes_in_seg: usize,
    full_secret_len: usize,
    budget: usize,
    pad: usize,
    no_color: bool,
) -> io::Result<()> {
    // The secret's own line is ALWAYS shown, even if it falls in the elided
    // middle — otherwise the finding's own text is the part that gets hidden.
    let mark = marked_lines(lines.len(), Some(seg_idx));
    let mut i = 0;
    while i < lines.len() {
        if mark[i] {
            if i == seg_idx {
                render_line_with_caret(
                    w, &lines[i], start_line + i as i64, secret_byte_in_seg, bytes_in_seg,
                    full_secret_len, budget, pad, no_color,
                )?;
            } else {
                write_row(w, start_line + i as i64, pad, &fit_to_budget(&lines[i], budget))?;
            }
            i += 1;
            continue;
        }
        let mut j = i;
        while j < lines.len() && !mark[j] {
            j += 1;
        }
        write_more_lines_row(w, pad, j - i)?;
        i = j;
    }
    Ok(())
}

fn print_pretty_file_only<W: Write>(
    w: &mut W,
    f: &Finding,
    no_color: bool,
    redact: u32,
) -> io::Result<()> {
    let mut f = f.clone();
    f.r#match = f.r#match.trim_end_matches(['\r', '\n']).to_string();
    f.secret = f.secret.trim_end_matches(['\r', '\n']).to_string();
    write_header(w, &f)?;
    print_pretty_meta(w, &f, no_color, redact)?;
    write_footer(w)
}

/// Go `printPrettyMeta` — attributes, validation, component sets.
fn print_pretty_meta<W: Write>(
    w: &mut W,
    f: &Finding,
    no_color: bool,
    redact: u32,
) -> io::Result<()> {
    if !f.attributes.is_empty() {
        writeln!(w, "│")?;
        writeln!(w, "│ attributes:")?;
        let mut keys: Vec<&String> = f.attributes.keys().collect();
        keys.sort();
        let max_k = keys.iter().map(|k| k.len()).max().unwrap_or(0);
        for k in keys {
            dot_leader(w, k, &f.attributes[k], max_k)?;
        }
    }
    let status = f.validation_status.0.as_ref();
    if !status.is_empty() {
        writeln!(w, "│ validation:")?;
        let mut vk: Vec<&String> = f.validation_meta.keys().collect();
        vk.sort();
        // 6 is the width of "status"/"reason", the two always-present keys.
        let max_vk = vk.iter().map(|k| k.len()).max().unwrap_or(0).max(6);
        let mut vs = status.to_uppercase();
        if !no_color {
            vs = crate::print_legacy::validation_style_pub(status, no_color).render(&vs);
        }
        dot_leader(w, "status", &vs, max_vk)?;
        if !f.validation_reason.is_empty() {
            dot_leader(w, "reason", &f.validation_reason, max_vk)?;
        }
        for k in vk {
            dot_leader(w, k, &f.validation_meta[k].to_string(), max_vk)?;
        }
    }
    print_component_findings(w, f, no_color, redact)
}

/// Go `PrintComponentFindings`.
///
/// When ANY set validated, the invalid ones are collapsed to a count rather
/// than listed: a rule with several component candidates can otherwise bury the
/// one that actually worked.
pub fn print_component_findings<W: Write>(
    w: &mut W,
    f: &Finding,
    no_color: bool,
    redact: u32,
) -> io::Result<()> {
    if f.component_sets.is_empty() {
        return Ok(());
    }
    let mut sets: Vec<ComponentSet> = f.component_sets.clone();
    // A STABLE sort putting valid sets first — stability keeps the original
    // order within each group, which is what makes the output reproducible.
    sets.sort_by_key(|s| s.validation_status.0.as_ref() != "valid");

    let has_valid = sets.iter().any(|s| s.validation_status.0.as_ref() == "valid");

    let mut to_render: Vec<&ComponentSet> = Vec::new();
    let mut max_key = 0usize;
    let mut invalid_count = 0usize;
    for set in &sets {
        if has_valid && set.validation_status.0.as_ref() != "valid" {
            invalid_count += 1;
            continue;
        }
        to_render.push(set);
        for comp in &set.components {
            let k = format!("{}:{}", comp.rule_id, comp.start_line);
            max_key = max_key.max(k.len());
        }
    }

    writeln!(w, "│ components:")?;
    for set in to_render {
        let icon = pretty_set_icon(set.validation_status.0.as_ref(), no_color);
        for (j, comp) in set.components.iter().enumerate() {
            let key = format!("{}:{}", comp.rule_id, comp.start_line);
            let dots = ".".repeat((max_key + 6).saturating_sub(key.len()));
            let val = redact_for_display(&comp.secret, redact);
            if j == 0 {
                // The icon appears only on a set's FIRST row — its presence is
                // what delimits one set from the next.
                writeln!(w, "│   {icon}  {key} {dots} {val}")?;
            } else {
                writeln!(w, "│      {key} {dots} {val}")?;
            }
        }
    }

    if invalid_count > 0 {
        let mut summary = format!(
            "+ {invalid_count} invalid set{}",
            if invalid_count > 1 { "s" } else { "" }
        );
        if !no_color {
            summary = color::Style::new().foreground("#888888").render(&summary);
        }
        writeln!(w, "│   {summary}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
