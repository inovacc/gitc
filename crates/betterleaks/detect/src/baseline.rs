//! Port of Go `detect/baseline.go` — suppressing findings that a previous scan
//! already recorded.
//!
//! A baseline is how a repository with existing findings adopts a scanner
//! without having to fix everything first: run once, save the JSON report, pass
//! it as `--baseline-path`, and from then on only NEW findings fail the build.
//!
//! ## Why the comparison is field-by-field
//!
//! Go compares fourteen fields explicitly rather than deriving equality, and
//! says why in a comment: it is significantly faster than a reflective compare,
//! at the cost of needing maintenance when `Finding` changes.
//!
//! Two exclusions are deliberate and load-bearing:
//!
//! * **The fingerprint is NOT compared.** If its format ever changes, every
//!   baseline would silently stop matching and a repository would be flooded
//!   with findings it had already accepted.
//! * **The secret and match are skipped when `--redact` is on**, because a
//!   redacted baseline does not contain them to compare against. Comparing
//!   anyway would make every finding look new.

use report::Finding;

/// Go `IsNew` — whether this finding is absent from the baseline.
pub fn is_new(finding: &Finding, redact: u32, baseline: &[Finding]) -> bool {
    !baseline.iter().any(|b| {
        finding.rule_id == b.rule_id
            && finding.description == b.description
            && finding.start_line == b.start_line
            && finding.end_line == b.end_line
            && finding.start_column == b.start_column
            && finding.end_column == b.end_column
            // With redaction on, the baseline holds a masked secret — comparing
            // it would never match, and every finding would read as new.
            && (redact > 0 || (finding.r#match == b.r#match && finding.secret == b.secret))
            && finding.file == b.file
            && finding.commit == b.commit
            && finding.author == b.author
            && finding.email == b.email
            && finding.date == b.date
            && finding.message == b.message
            // The FINGERPRINT is deliberately absent: a change to its format
            // would otherwise invalidate every baseline at once.
            && finding.entropy == b.entropy
    })
}

/// Go `LoadBaseline` — a baseline is a previous JSON report.
///
/// Both failure modes are distinguished, because they need different fixes: a
/// missing file is a wrong path, an unparseable one is the wrong format (a
/// SARIF or CSV report passed by mistake).
pub fn load_baseline(path: &str) -> Result<Vec<Finding>, String> {
    let bytes = std::fs::read(path).map_err(|_| format!("could not open {path}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| format!("the format of the file {path} is not supported"))
}

impl crate::Detector {
    /// Go `(*Detector).AddBaseline`.
    ///
    /// The path is also stored RELATIVE to the scan source, because the
    /// detector skips scanning its own baseline file — a report full of
    /// secrets sitting inside the tree being scanned would otherwise be
    /// reported as a fresh set of findings.
    pub fn add_baseline(&mut self, baseline_path: &str, source: &str) -> Result<(), String> {
        if baseline_path.is_empty() {
            self.baseline_path = String::new();
            return Ok(());
        }
        let absolute_source = std::fs::canonicalize(source)
            .unwrap_or_else(|_| std::path::PathBuf::from(source));
        let absolute_baseline = std::fs::canonicalize(baseline_path)
            .unwrap_or_else(|_| std::path::PathBuf::from(baseline_path));

        self.baseline = load_baseline(baseline_path)?;
        self.baseline_path = relative_to(&absolute_source, &absolute_baseline);
        Ok(())
    }

    /// Whether a finding survives the baseline.
    pub fn is_new_finding(&self, finding: &Finding, redact: u32) -> bool {
        if self.baseline.is_empty() {
            return true;
        }
        is_new(finding, redact, &self.baseline)
    }
}

/// Go `filepath.Rel` for the shapes this needs.
///
/// Falls back to the absolute target when no relative path exists (a different
/// drive on Windows), which is what `filepath.Rel` errors on — and an absolute
/// path still identifies the file correctly for the self-scan check.
fn relative_to(base: &std::path::Path, target: &std::path::Path) -> String {
    use std::path::Component;
    let mut b = base.components().peekable();
    let mut t = target.components().peekable();

    // Drop the shared prefix.
    while let (Some(x), Some(y)) = (b.peek(), t.peek()) {
        if x == y {
            b.next();
            t.next();
        } else {
            break;
        }
    }
    // A differing PREFIX (drive letter / UNC root) means there is no relative
    // path at all.
    if base
        .components()
        .next()
        .zip(target.components().next())
        .is_some_and(|(x, y)| matches!(x, Component::Prefix(_)) && x != y)
    {
        return target.to_string_lossy().to_string();
    }

    let ups = b.filter(|c| matches!(c, Component::Normal(_))).count();
    let rest: Vec<String> = t
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();

    let mut parts: Vec<String> = std::iter::repeat("..".to_string()).take(ups).collect();
    parts.extend(rest);
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

#[cfg(test)]
mod tests;
