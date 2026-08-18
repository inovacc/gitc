//! Port of Go `(*Detector).AddGitleaksIgnore` and the ignore check in
//! `AddFinding` (`detect/deprecated.go:139-161`).
//!
//! `.betterleaksignore` / `.gitleaksignore` is how a repository suppresses
//! findings it has already triaged, keyed by FINGERPRINT. It is not a nicety:
//! betterleaks' own repository ships a 943-line ignore file covering the sample
//! secrets in its rule generator, and without it a scan of that tree reports
//! **561 findings instead of 1**. A scanner that cries wolf 560 times is one
//! nobody reads.
//!
//! Two fingerprint shapes, both `:`-joined:
//!
//! ```text
//! file:rule-id:start-line              — global   (3 parts)
//! commit:file:rule-id:start-line       — a commit (4 parts)
//! ```

use report::Finding;
use std::collections::HashSet;

/// Go's `AddGitleaksIgnore` line handling.
///
/// Returns the normalised entries plus the lines Go would warn about. Malformed
/// lines are still INSERTED (Go warns and inserts anyway) — reproduced because
/// an entry silently dropped is a finding that silently comes back.
pub fn parse_ignore_file(content: &str) -> (HashSet<String>, Vec<String>) {
    let mut set = HashSet::new();
    let mut invalid = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Normalise Windows separators in the PATH component only — a `\` in a
        // rule id or a commit sha is not a path separator.
        let mut parts: Vec<String> = line.split(':').map(|s| s.to_string()).collect();
        match parts.len() {
            // `file:rule-id:start-line`
            3 => parts[0] = parts[0].replace('\\', "/"),
            // `commit:file:rule-id:start-line`
            4 => parts[1] = parts[1].replace('\\', "/"),
            _ => invalid.push(line.to_string()),
        }
        set.insert(parts.join(":"));
    }
    (set, invalid)
}

/// Go's global fingerprint — `file:rule-id:start-line`, ALWAYS without a commit.
///
/// Go builds this from `finding.File` (after `SyncDeprecatedSourceFields`),
/// not from the attribute map, so this does the same.
pub fn global_fingerprint(f: &Finding) -> String {
    format!("{}:{}:{}", f.file, f.rule_id, f.start_line)
}

/// Should this finding be suppressed?
///
/// Order is Go's and it matters: the GLOBAL fingerprint is checked first, so a
/// commit-less entry suppresses a finding in every commit that carries it —
/// which is what makes an ignore file usable against history. The
/// commit-qualified entry is only consulted for a finding that HAS a commit.
pub fn is_ignored(ignore: &HashSet<String>, f: &Finding) -> bool {
    if ignore.contains(&global_fingerprint(f)) {
        return true;
    }
    !f.commit.is_empty() && ignore.contains(&f.fingerprint)
}

#[cfg(test)]
mod tests;
