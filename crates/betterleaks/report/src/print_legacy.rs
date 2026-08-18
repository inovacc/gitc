//! Port of Go `report/print_legacy.go` — the `--legacy-print` finding format.
//!
//! This is the key/value layout: `Finding:`, `Secret:`, `RuleID:` and so on, one
//! per line. It writes to a `Write` rather than to stdout directly, which is the
//! one reshape — Go prints with `fmt.Printf`, and that makes the output
//! untestable. Everything else is a faithful port, colours included.
//!
//! The colouring is not decoration: the SECRET is highlighted inside the wider
//! MATCH inside the source LINE, so a human can see at a glance which part of a
//! long line the finding actually is.

use crate::finding::mask_secret;
use crate::Finding;
use std::io::{self, Write};

/// The style for the match around the secret.
fn match_style() -> color::Style {
    color::Style::new().foreground("#f5d445")
}

/// The style for the secret itself.
fn secret_style() -> color::Style {
    color::Style::new().bold().italic().foreground("#f05c07")
}

/// Go `locateMatch` — where the match starts within the line.
///
/// `start_column` is a 1-based BYTE offset and is trusted first, because a line
/// can contain the match text more than once and the column says which one.
/// Only when that fails does it search — and it searches FORWARD from the
/// expected position rather than from the start, for the same reason.
pub fn locate_match(raw_line: &str, raw_match: &str, start_col: i64) -> Option<usize> {
    if raw_line.is_empty() || raw_match.is_empty() {
        return None;
    }
    if start_col > 0 {
        let idx = (start_col - 1) as usize;
        if idx + raw_match.len() <= raw_line.len()
            && raw_line.is_char_boundary(idx)
            && raw_line.is_char_boundary(idx + raw_match.len())
            && &raw_line[idx..idx + raw_match.len()] == raw_match
        {
            return Some(idx);
        }
        let idx = idx.min(raw_line.len());
        // Walk back to a character boundary so slicing cannot panic on UTF-8.
        let mut from = idx;
        while from > 0 && !raw_line.is_char_boundary(from) {
            from -= 1;
        }
        if let Some(rel) = raw_line[from..].find(raw_match) {
            return Some(from + rel);
        }
    }
    raw_line.find(raw_match)
}

/// Go `(Finding).PrintLegacy`.
pub fn print_legacy<W: Write>(w: &mut W, f: &Finding, no_color: bool, redact: u32) -> io::Result<()> {
    // Redaction happens on a COPY: the caller may still need the real secret,
    // and Go takes the finding by value here for the same reason.
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
    f.line = f.line.trim().to_string();
    f.secret = f.secret.trim().to_string();
    f.r#match = f.r#match.trim().to_string();

    // A path-only rule reports `file detected: …` and has no line to highlight.
    let is_file_match = f.r#match.starts_with("file detected:");
    let mut skip_color = no_color;
    let mut finding_line = String::new();
    let mut secret_display = String::new();

    if !is_file_match {
        let match_idx = locate_match(&f.line, &f.r#match, f.start_column);
        skip_color = false;
        let match_in_line = match match_idx {
            Some(i) if !no_color => i,
            _ => {
                skip_color = true;
                0
            }
        };
        let secret_in_match = f.r#match.find(&f.secret).unwrap_or(0);

        // Show at most 20 bytes of lead-in, with an ellipsis — a minified line
        // would otherwise push the finding off the screen.
        let mut start = f.line[..match_in_line].to_string();
        if match_in_line > 20 {
            start = format!("...{}", &f.line[match_in_line - 20..match_in_line]);
        }

        let match_beginning = match_style().render(&f.r#match[..secret_in_match]);
        secret_display = f.secret.clone();
        if secret_display.len() > 100 {
            secret_display = format!("{}...", &secret_display[..100]);
        }
        let styled_secret = secret_style().render(&secret_display);
        let after = (secret_in_match + f.secret.len()).min(f.r#match.len());
        let match_end = match_style().render(&f.r#match[after..]);

        let line_end_idx = (match_in_line + f.r#match.len()).min(f.line.len());
        let mut line_end = f.line[line_end_idx..].to_string();
        if line_end.len() > 20 {
            line_end = format!("{}...", &line_end[..20]);
        }

        finding_line = format!(
            "{}{}{}{}{}\n",
            start.trim_start_matches(' ').trim_start_matches('\n'),
            match_beginning,
            styled_secret,
            match_end,
            line_end
        );
        secret_display = styled_secret;
    }

    if skip_color || is_file_match {
        writeln!(w, "{:<12} {}", "Finding:", f.r#match)?;
        writeln!(w, "{:<12} {}", "Secret:", f.secret)?;
    } else {
        write!(w, "{:<12} {}", "Finding:", finding_line)?;
        writeln!(w, "{:<12} {}", "Secret:", secret_display)?;
    }

    writeln!(w, "{:<12} {}", "RuleID:", f.rule_id)?;
    // Go uses `%f`, which is six decimal places.
    writeln!(w, "{:<12} {:.6}", "Entropy:", f.entropy)?;

    if !f.tags.is_empty() {
        writeln!(w, "{:<12} {}", "Tags:", f.tags.join(", "))?;
    }

    if !f.attributes.is_empty() {
        writeln!(w, "{:<12}", "Attributes:")?;
        // SORTED — Go sorts the keys explicitly, because a map's iteration
        // order would make the output differ between runs.
        let mut keys: Vec<&String> = f.attributes.keys().collect();
        keys.sort();
        for k in keys {
            writeln!(w, "  {}: {}", k, f.attributes[k])?;
        }
    }

    writeln!(w, "{:<12} {}", "Line:", f.start_line)?;
    writeln!(w, "{:<12} {}", "Fingerprint:", f.fingerprint)?;

    if !f.link.is_empty() {
        writeln!(w, "{:<12} {}", "Link:", f.link)?;
    }
    if !f.match_context.is_empty() {
        writeln!(w, "{:<12}", "Context:")?;
        writeln!(
            w,
            "{}",
            format_match_context(&f.match_context, &f.r#match, &f.secret, no_color)
        )?;
    }

    print_validation(w, &f, no_color)?;
    writeln!(w)?;
    Ok(())
}

/// Go `validationStyle`, re-exported for the pretty printer.
pub(crate) fn validation_style_pub(status: &str, no_color: bool) -> color::Style {
    validation_style(status, no_color)
}

/// Go `validationStyle`.
fn validation_style(status: &str, no_color: bool) -> color::Style {
    if no_color {
        return color::Style::new();
    }
    match status {
        "valid" => color::Style::new().bold().foreground("#00d26a"),
        "needs_validation" => color::Style::new().bold().foreground("#60a5fa"),
        "invalid" => color::Style::new().foreground("#888888"),
        "revoked" => color::Style::new().foreground("#f5d445"),
        "unknown" => color::Style::new().foreground("#c0c0c0"),
        "error" => color::Style::new().foreground("#f05c07"),
        _ => color::Style::new(),
    }
}

/// Go `printValidationLegacy`.
fn print_validation<W: Write>(w: &mut W, f: &Finding, no_color: bool) -> io::Result<()> {
    let status = f.validation_status.0.as_ref();
    if status.is_empty() {
        return Ok(());
    }
    let styled = validation_style(status, no_color);
    write!(
        w,
        "{:<12} {}",
        "Validation:",
        styled.render(&status.to_uppercase())
    )?;
    if !f.validation_reason.is_empty() {
        write!(w, "  ({})", f.validation_reason)?;
    }
    writeln!(w)?;

    let meta_style = if no_color {
        color::Style::new()
    } else {
        color::Style::new().foreground("#9ca3af")
    };
    let mut keys: Vec<&String> = f.validation_meta.keys().collect();
    keys.sort();
    for k in keys {
        let line = format!("{:<10} {}", format!("{k} ="), f.validation_meta[k]);
        writeln!(w, "  {}", meta_style.render(&line))?;
    }
    Ok(())
}

/// Go `formatMatchContextLegacy` — indent each context line and highlight the
/// match/secret within it.
pub fn format_match_context(context: &str, m: &str, secret: &str, no_color: bool) -> String {
    let indent = "    ";
    let mut out: Vec<String> = Vec::new();
    for line in context.split('\n') {
        let mut rendered = line.to_string();
        if !no_color && !secret.is_empty() && line.contains(secret) {
            rendered = line.replace(secret, &secret_style().render(secret));
        } else if !no_color && !m.is_empty() && line.contains(m) {
            rendered = line.replace(m, &match_style().render(m));
        }
        out.push(format!("{indent}{rendered}"));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests;
