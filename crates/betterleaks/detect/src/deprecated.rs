//! Port of Go `detect/deprecated.go` — the accumulator API Go itself marks
//! `Deprecated`.
//!
//! ## Why this is a separate type rather than methods on [`Detector`]
//!
//! Go hangs `DetectSource`, `AddFinding`, `Findings` and friends off `*Detector`
//! and keeps their state — `findings`, `commitMap`, `commitMutex`, `findingsCh`
//! — in the same struct the live scan uses. Its own comment on `commitMap` says
//! those fields are "used only by this code path".
//!
//! This port's [`Detector`] is deliberately `&self` and shareable: `detect` is
//! called from several threads at once (S3 `--workers`, parallel git), and the
//! CLI owns accumulation. Moving six accumulator fields onto it to serve an API
//! nothing reaches would tax every live scan for a path with no caller, and
//! would put interior mutability in the middle of the hot struct.
//!
//! So the STATE lives here, in [`LegacyDetector`], which borrows a `Detector`
//! and reproduces every observable behaviour of `deprecated.go`: the routing
//! order in `AddFinding`, the fingerprint shapes, the ignore/baseline/confidence
//! gates, the commit set, `shouldVerbosePrint`, and the `"%d commits scanned."`
//! line only this path emits. Same behaviour, same order, without the tax.
//!
//! ## What it does NOT reproduce, and why
//!
//! Go's `DetectSource` fans findings through a buffered channel and a consumer
//! goroutine, so that validation results and plain findings arrive on one queue.
//! Here the routing is direct and synchronous. The channel is a *mechanism* for
//! joining two producers, not a behaviour a caller can observe — the findings,
//! their order relative to the source's fragments, and the counts are the same.
//! Flagged rather than silently reshaped.

use crate::Detector;
use report::Finding;
use sources::{Fragment, Source};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Go's deprecated accumulator half of `*Detector`.
///
/// Deprecated in Go, and deprecated here: new code calls
/// [`Detector::detect`] and owns its own findings. This exists so the port is
/// complete, and so a consumer migrating from the Go library has the same shape
/// available while it migrates.
pub struct LegacyDetector<'a> {
    detector: &'a Detector,
    findings: Vec<Finding>,
    /// Go `commitMap` — a SET, so the "N commits scanned" count does not
    /// double-count a commit that produced several fragments.
    commits: HashSet<String>,
    /// Go `ValidationCounts`.
    validation_counts: BTreeMap<String, i64>,
    /// Go `Verbose`.
    pub verbose: bool,
    /// Go `ValidationStatusFilter`, consulted only by `shouldVerbosePrint`.
    pub validation_status_filter: BTreeSet<String>,
}

impl<'a> LegacyDetector<'a> {
    pub fn new(detector: &'a Detector) -> LegacyDetector<'a> {
        LegacyDetector {
            detector,
            findings: Vec::new(),
            commits: HashSet::new(),
            validation_counts: BTreeMap::new(),
            verbose: false,
            validation_status_filter: BTreeSet::new(),
        }
    }

    /// Go `(*Detector).Detect` — Deprecated: use [`Detector::detect`].
    pub fn detect(&self, fragment: &Fragment) -> Vec<Finding> {
        self.detector.detect(fragment)
    }

    /// Go `(*Detector).DetectContext` — Deprecated. Go's only difference from
    /// `Detect` is the `context.Context` it threads for cancellation, which this
    /// port expresses through the caller's own control flow.
    pub fn detect_context(&self, fragment: &Fragment) -> Vec<Finding> {
        self.detector.detect(fragment)
    }

    /// Go `(*Detector).Findings` — Deprecated.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Go `ValidationCounts`, as accumulated by this path.
    pub fn validation_counts(&self) -> &BTreeMap<String, i64> {
        &self.validation_counts
    }

    /// Go `addCommit`. A set, not a counter — see the field comment.
    fn add_commit(&mut self, commit: &str) {
        self.commits.insert(commit.to_string());
    }

    /// Go `(*Detector).shouldVerbosePrint` — Deprecated.
    ///
    /// Note this is NOT how the live path decides: `cmd/directory.go:80` prints
    /// every finding when `--verbose`, and applies the status filter later, to
    /// the report. Only this deprecated path filters at print time. Reproducing
    /// the difference matters — collapsing the two would change what a
    /// `--verbose --validation-status` run prints.
    pub fn should_verbose_print(&self, f: &Finding) -> bool {
        if !self.verbose {
            return false;
        }
        if self.validation_status_filter.is_empty() {
            return true;
        }
        if f.validation_status.as_str().is_empty() {
            return self.validation_status_filter.contains("none");
        }
        self.validation_status_filter
            .contains(f.validation_status.as_str())
    }

    /// Go `(*Detector).AddFinding` — Deprecated.
    ///
    /// The ORDER of the gates is the behaviour: fingerprint first (both shapes),
    /// then the ignore list, then the baseline, then confidence. A finding
    /// rejected by an earlier gate must never reach a later one, because the
    /// later ones have side effects on the counts.
    pub fn add_finding(&mut self, mut finding: Finding) {
        finding.sync_deprecated_source_fields();

        // Go builds the global fingerprint FIRST and keeps it, then overwrites
        // `finding.Fingerprint` with the commit-qualified form when there is a
        // commit. Both are then checked against the ignore list — a
        // `.betterleaksignore` entry may name either shape.
        let global = crate::global_fingerprint(&finding);
        finding.set_fingerprint();

        if self.detector.gitleaks_ignore.contains(&global) {
            logging::debug()
                .str("finding", &finding.secret)
                .str("fingerprint", &global)
                .msg("skipping finding: global fingerprint");
            return;
        }
        if !finding.commit.is_empty() && self.detector.gitleaks_ignore.contains(&finding.fingerprint)
        {
            logging::debug()
                .str("finding", &finding.secret)
                .str("fingerprint", &finding.fingerprint)
                .msg("skipping finding: fingerprint");
            return;
        }

        if !self
            .detector
            .is_new_finding(&finding, self.detector.redact)
        {
            logging::debug()
                .str("finding", &finding.secret)
                .str("fingerprint", &finding.fingerprint)
                .msg("skipping finding: baseline");
            return;
        }

        if !confidence::meets(
            &finding.attr(confidence::ATTRIBUTE),
            &self.detector.min_confidence,
        ) {
            return;
        }

        let status = finding.validation_status.as_str().to_string();
        if !status.is_empty() {
            *self.validation_counts.entry(status).or_insert(0) += 1;
        }
        self.findings.push(finding);
    }

    /// Go `(*Detector).DetectSource` — Deprecated: drive the source yourself and
    /// call [`Detector::detect`].
    ///
    /// Returns the accumulated findings. A per-fragment error is LOGGED and the
    /// scan continues, exactly as Go does — one unreadable fragment must not end
    /// a scan and report what it managed as the whole answer.
    pub fn detect_source<S>(&mut self, source: &S, is_git: bool) -> Result<Vec<Finding>, S::Error>
    where
        S: Source + ?Sized,
        S::Error: std::fmt::Display,
    {
        let detector = self.detector;
        // Collected first, then routed: `add_finding` needs `&mut self` while
        // the closure below already borrows it.
        let mut pending: Vec<(Option<String>, Vec<Finding>)> = Vec::new();
        let mut yield_fn = |r: Result<Fragment, S::Error>| -> Result<(), S::Error> {
            let fragment = match r {
                Ok(f) => f,
                Err(e) => {
                    logging::error().msg(&e.to_string());
                    return Ok(());
                }
            };
            let sha = fragment.attr(sources::ATTR_GIT_SHA);
            let commit = if sha.is_empty() {
                None
            } else {
                Some(sha.to_string())
            };
            // Go checks BOTH: content and path must be empty. A path-only rule
            // can fire on a fragment with no content at all, so testing content
            // alone would drop those findings.
            if fragment.raw.is_empty() && fragment.attr(sources::ATTR_PATH).is_empty() {
                logging::trace().msg("skipping empty fragment");
                if commit.is_some() {
                    pending.push((commit, Vec::new()));
                }
                return Ok(());
            }
            pending.push((commit, detector.detect(&fragment)));
            Ok(())
        };

        let result = source.fragments(&mut yield_fn);

        for (commit, findings) in pending {
            if let Some(c) = commit {
                self.add_commit(&c);
            }
            for f in findings {
                self.add_finding(f);
            }
        }

        // Go emits this only for a `*sources.Git`, and only from this path.
        if is_git {
            logging::info().msg(&format!("{} commits scanned.", self.commits.len()));
            logging::debug().msg(
                "Note: this number might be smaller than expected due to commits with no additions",
            );
        }

        result?;
        Ok(self.findings.clone())
    }
}

#[cfg(test)]
mod tests;
