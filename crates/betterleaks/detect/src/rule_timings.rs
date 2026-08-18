//! Port of Go `detect/rule_timings.go` — per-rule cost accounting behind
//! `--diagnostics=rules` / `--diagnostics=rules-csv`.
//!
//! A catalogue of 414 rules is not uniformly cheap: one pathological regex can
//! dominate a scan. This is the instrument that says which one, so the answer
//! is measured rather than guessed.
//!
//! Durations are Go nanoseconds and rendered with
//! [`logging::duration::duration_string`], because the human and CSV reports
//! both print `Duration.String()` and a Rust `{:?}` would not match it.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;

/// Go `RuleTiming`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleTiming {
    pub rule_id: String,
    /// Go `time.Duration` — nanoseconds.
    pub total: i64,
    pub hits: u64,
}

impl RuleTiming {
    /// Go `RuleTiming.Average` — integer division, and 0 for no hits rather
    /// than a division by zero.
    pub fn average(&self) -> i64 {
        if self.hits == 0 {
            return 0;
        }
        self.total / self.hits as i64
    }
}

/// Go `RuleTimingCollector`.
///
/// Go guards a map with a `sync.Mutex`; the same shape here, because
/// `Detector::detect` takes `&self` and the collector is written during
/// detection.
#[derive(Debug, Default)]
pub struct RuleTimingCollector {
    timings: Mutex<HashMap<String, RuleTiming>>,
}

impl RuleTimingCollector {
    pub fn new() -> RuleTimingCollector {
        RuleTimingCollector::default()
    }

    /// Go `Record`. An empty rule id is ignored, as in Go.
    pub fn record(&self, rule_id: &str, duration: i64) {
        if rule_id.is_empty() {
            return;
        }
        let mut map = self.timings.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(rule_id.to_string()).or_default();
        entry.rule_id = rule_id.to_string();
        entry.total += duration;
        entry.hits += 1;
    }

    /// Go `Snapshot` — a sorted copy, so the caller can write it without
    /// holding the lock.
    pub fn snapshot(&self) -> Vec<RuleTiming> {
        let map = self.timings.lock().unwrap_or_else(|e| e.into_inner());
        let mut timings: Vec<RuleTiming> = map.values().cloned().collect();
        sort_rule_timings(&mut timings);
        timings
    }
}

/// Go `SortRuleTimings` — slowest first, then most hits, then rule id.
///
/// Go uses `sort.SliceStable`; `sort_by` on a `Vec` is stable in Rust too. The
/// final rule-id tiebreak makes the order total, so the report is reproducible
/// across runs even though the source is a hash map.
pub fn sort_rule_timings(timings: &mut [RuleTiming]) {
    timings.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then_with(|| b.hits.cmp(&a.hits))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
}

/// Go `WriteRuleTimingsCSV`.
///
/// The CSV is hand-written rather than pulled from a crate: the only field that
/// can contain a comma or a quote is the rule id, and Go's `encoding/csv`
/// quoting rules for it are three lines. [`csv_field`] carries them.
pub fn write_rule_timings_csv<W: Write>(w: &mut W, timings: &[RuleTiming]) -> std::io::Result<()> {
    let mut sorted = timings.to_vec();
    sort_rule_timings(&mut sorted);

    // Go's csv.Writer terminates records with a bare \n unless UseCRLF is set,
    // and betterleaks does not set it. Verified against the Go binary's output
    // rather than assumed — the first draft of this used \r\n.
    writeln!(
        w,
        "rule_id,total_duration_ns,total_duration,hits,avg_duration_ns,avg_duration"
    )?;
    for t in &sorted {
        let avg = t.average();
        writeln!(
            w,
            "{},{},{},{},{},{}",
            csv_field(&t.rule_id),
            t.total,
            logging::duration::duration_string(t.total),
            t.hits,
            avg,
            logging::duration::duration_string(avg),
        )?;
    }
    Ok(())
}

/// Go `csv.Writer.fieldNeedsQuotes`, in order: empty never quotes; the literal
/// `\.` always does (it would otherwise read as a Postgres end-of-data marker);
/// then comma / quote / CR / LF; then a leading whitespace rune, which would be
/// eaten on the way back in.
///
/// A rule id triggers none of these in practice. It is ported anyway because
/// "in practice" is exactly the assumption that breaks when someone adds a rule
/// id with a comma in it and the CSV silently gains a column.
fn csv_field(s: &str) -> String {
    let needs_quotes = if s.is_empty() {
        false
    } else if s == r"\." {
        true
    } else {
        s.contains([',', '"', '\r', '\n'])
            || s.chars().next().is_some_and(|c| c.is_whitespace())
    };
    if !needs_quotes {
        return s.to_string();
    }
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Go `WriteRuleTimingsHuman`.
///
/// The rule-id column is as wide as the widest id, minimum the width of the
/// header — Go's `%-*s`. Getting this wrong is invisible in a unit test that
/// checks a single row and glaring in a real 414-rule report.
pub fn write_rule_timings_human<W: Write>(w: &mut W, timings: &[RuleTiming]) -> std::io::Result<()> {
    let mut sorted = timings.to_vec();
    sort_rule_timings(&mut sorted);

    let mut rule_id_width = "Rule ID".len();
    for t in &sorted {
        // Go measures len() in BYTES, not characters.
        if t.rule_id.len() > rule_id_width {
            rule_id_width = t.rule_id.len();
        }
    }

    write!(w, "Rule Timings\n\nRules timed: {}\n\n", sorted.len())?;
    writeln!(
        w,
        "{:<width$}  {:>14}  {:>8}  {:>14}",
        "Rule ID",
        "Total",
        "Hits",
        "Average",
        width = rule_id_width
    )?;
    for t in &sorted {
        writeln!(
            w,
            "{:<width$}  {:>14}  {:>8}  {:>14}",
            t.rule_id,
            logging::duration::duration_string(t.total),
            t.hits,
            logging::duration::duration_string(t.average()),
            width = rule_id_width
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
