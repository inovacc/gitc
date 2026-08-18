//! Port of Go `detect.processComponents` and its proximity helpers —
//! multi-part ("composite") rules.
//!
//! **Why this is not optional.** 25 catalogue rules declare components, and for
//! a REQUIRED one the primary finding is DROPPED unless a matching component
//! sits nearby. `aws-access-token` is the headline case:
//!
//! ```toml
//! components = [ { id = "aws-secret-access-key", within = "5L" } ]
//! ```
//!
//! so a lone AWS access-key id is NOT reported by the source engine. Deferring
//! this made the port strictly MORE permissive than Go — false positives in a
//! commit gate, on the single most common secret type. Verified against the Go
//! engine directly, which reports nothing for a bare `AKIA…`.

use config::Component;
use contextwindow::{Mode, Spec};
use report::{ComponentFinding, Finding};

/// Go `maxComponentSets`.
pub const MAX_COMPONENT_SETS: usize = 100;

/// Go `hasAllRequiredComponents` — every non-optional component needs a match.
pub fn has_all_required_components(
    component_findings: &[ComponentFinding],
    components: &[Component],
) -> bool {
    components.iter().all(|c| {
        c.optional || component_findings.iter().any(|f| f.rule_id == c.rule_id)
    })
}

/// Go `rawLineStarts` — byte offset of each line start, index 0 included.
fn raw_line_starts(raw: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, &c) in raw.as_bytes().iter().enumerate() {
        if c == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Go `findingStartOffset`.
fn finding_start_offset(line_starts: &[usize], fragment_start_line: i64, f: &Finding) -> Option<usize> {
    let line = f.start_line - fragment_start_line;
    if line < 0 || line as usize >= line_starts.len() || f.start_column < 1 {
        return None;
    }
    Some(line_starts[line as usize] + f.start_column as usize - 1)
}

/// Go `findingEndOffset`.
fn finding_end_offset(line_starts: &[usize], fragment_start_line: i64, f: &Finding) -> Option<usize> {
    let line = f.end_line - fragment_start_line;
    if line < 0 || line as usize >= line_starts.len() || f.end_column < 0 {
        return None;
    }
    Some(line_starts[line as usize] + f.end_column as usize)
}

/// Go `withinProximity`.
///
/// A ZERO window means "anywhere in the fragment" — not "nowhere". Getting that
/// backwards would silently drop every composite finding.
pub fn within_proximity(
    raw: &str,
    fragment_start_line: i64,
    primary: &Finding,
    component: &Finding,
    window: &Spec,
) -> bool {
    if window.is_zero() {
        return true;
    }

    match window.mode {
        Mode::Cols => {
            let starts = raw_line_starts(raw);
            let (Some(p_start), Some(p_end), Some(c_start)) = (
                finding_start_offset(&starts, fragment_start_line, primary),
                finding_end_offset(&starts, fragment_start_line, primary),
                finding_start_offset(&starts, fragment_start_line, component),
            ) else {
                return false;
            };
            let lo = p_start.saturating_sub(window.cols_before);
            let hi = (p_end + window.cols_after).min(raw.len());
            c_start >= lo && c_start < hi
        }
        Mode::Box => {
            if component.start_line < primary.start_line - window.lines_before as i64
                || component.start_line > primary.end_line + window.lines_after as i64
            {
                return false;
            }
            // Column bounds only apply to a single-line primary.
            if primary.start_line == primary.end_line
                && (window.cols_before > 0 || window.cols_after > 0)
            {
                let component_column = component.start_column - 1;
                let window_start =
                    (primary.start_column - 1 - window.cols_before as i64).max(0);
                let window_end = primary.end_column + window.cols_after as i64;
                return component_column >= window_start && component_column < window_end;
            }
            true
        }
        Mode::None => false,
    }
}

/// Build a [`ComponentFinding`] from a component rule's own finding.
pub fn to_component_finding(found: &Finding, optional: bool) -> ComponentFinding {
    ComponentFinding {
        rule_id: found.rule_id.clone(),
        optional,
        start_line: found.start_line,
        end_line: found.end_line,
        start_column: found.start_column,
        end_column: found.end_column,
        line: found.line.clone(),
        r#match: found.r#match.clone(),
        secret: found.secret.clone(),
        capture_groups: found.capture_groups.clone(),
        rule_specificity: found.rule_specificity,
    }
}
