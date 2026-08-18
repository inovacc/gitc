//! Port of Go `detect` — the detection engine core (M13 in `PORT-PLAN.md`).
//!
//! **This REPLACES the hand-written 26-rule engine.** The previous crate was a
//! lensr-local approximation carrying 26 rules against the source's 414. This
//! is the real algorithm, driven by [`config`]'s full catalogue and
//! [`exprruntime`]'s filter evaluator.
//!
//! ## The detection path
//!
//! 1. **Keyword prefilter.** One Aho-Corasick pass over the fragment marks
//!    every rule whose keyword appears; rules with no keywords are always
//!    candidates. This is what keeps 414 rules affordable — without it each
//!    fragment would run 413 regexes.
//! 2. **Per rule, in specificity order.** Path-only rules short-circuit; the
//!    rest run their regex, extract the secret (honouring `secretGroup` and
//!    named captures), and compute location.
//! 3. **Filters.** `betterleaks:allow`/`gitleaks:allow`, specificity
//!    suppression, then the global and per-rule filter expressions.
//! 4. **Decode loop.** The whole pass repeats over `codec`-decoded content up to
//!    `max_decode_depth`, so a base64-wrapped secret is still found.
//! 5. **Dedupe.**
//!
//! ## Landed since this module was first written
//!
//! The list below used to say these were deferred. They are not, and a stale
//! "deferred" note is worse than none — it invites someone to build the same
//! thing twice, or to assume a gap that has closed:
//!
//! * **Components / proximity** (`processComponents`, `withinProximity`) — the
//!   25 rules that declare components build real component sets, which is what
//!   the composite validation path consumes;
//! * **Baseline**, **`.betterleaksignore`**, **rule timings**, and
//!   **validation** (behind `--validation`, off by default as upstream).
//!
//! * **The BPE tokenizer**, so `filter.tokenRatio` decides something in the
//!   121 expressions that call it. The vocabulary is Go's own
//!   `cl100k_base.tiktoken.gz`, embedded byte for byte — a different rank table
//!   would give different token counts and therefore different findings.
//!
//! ## Still deferred — named, not silently dropped
//!
//! * **`Run`/`iter.Seq` over a `Source`** — the streaming scan. `detect_string`
//!   and `detect_fragment` are the paths the CLI and the gate use.

mod baseline;
mod deprecated;
mod rule_timings;
mod tiktokenloader;
mod components;
mod ignore;
mod location;
mod utils;

pub use baseline::{is_new, load_baseline};
pub use deprecated::LegacyDetector;
pub use tiktokenloader::{load_tiktoken_bpe, Cl100kTokenizer};
pub use rule_timings::{
    sort_rule_timings, write_rule_timings_csv, write_rule_timings_human, RuleTiming,
    RuleTimingCollector,
};
pub use components::MAX_COMPONENT_SETS;
pub use ignore::{global_fingerprint, is_ignored, parse_ignore_file};
pub use location::Location;
pub use utils::{mask_secret, masked, shannon_entropy};

use config::Config;
use report::Finding;
use sources::Fragment;
use std::collections::HashMap;

/// Go `SlowWarningThreshold` (detect/detect.go:62-64) — how long a single
/// fragment may take before the scan says so.
///
/// A settable global rather than a `const` because Go declares it in a `var`
/// block, not a `const` one: it is reassignable, which is how its own tests
/// shorten it. [`set_slow_warning_threshold`] is that same lever.
static SLOW_WARNING_NANOS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(5_000_000_000);

/// The current value of Go's `SlowWarningThreshold`.
pub fn slow_warning_threshold() -> std::time::Duration {
    std::time::Duration::from_nanos(SLOW_WARNING_NANOS.load(std::sync::atomic::Ordering::Relaxed))
}

/// Reassign Go's `SlowWarningThreshold`.
pub fn set_slow_warning_threshold(d: std::time::Duration) {
    SLOW_WARNING_NANOS.store(d.as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
}

/// Wait for the inspection to finish, or for `threshold` to elapse.
///
/// Returns `true` only when the WAIT TIMED OUT — that is, the fragment is still
/// being inspected and deserves the warning. Returning true on an ordinary
/// wake-up would make every fragment warn, which is the failure mode that turns
/// a diagnostic into noise nobody reads.
///
/// Split out from the thread so the decision is testable without a five-second
/// test or a stderr capture.
fn wait_for_inspection(
    fired: &(std::sync::Mutex<bool>, std::sync::Condvar),
    threshold: std::time::Duration,
) -> bool {
    let (lock, cv) = fired;
    let guard = lock.lock().unwrap_or_else(|p| p.into_inner());
    let (done, timeout) = cv
        .wait_timeout_while(guard, threshold, |done| !*done)
        .unwrap_or_else(|p| p.into_inner());
    timeout.timed_out() && !*done
}

/// Go's `time.AfterFunc(SlowWarningThreshold, …)` around one fragment
/// inspection, and its `logger.GetLevel() <= zerolog.DebugLevel` guard.
///
/// The point of the Go behaviour is that the warning lands WHILE the fragment
/// is still being inspected — that is what tells an operator staring at a
/// motionless scan which file is responsible. Measuring the elapsed time after
/// the fact would report the stall only once it was over.
///
/// ⚠ COST, stated rather than hidden: Go arms a timer on a shared runtime heap;
/// this arms a THREAD, which is far more expensive. It is why the debug-level
/// guard is not an optimisation here but a requirement — at info level, the
/// default, nothing is spawned at all and `arm` returns `None`.
struct SlowWatchdog {
    fired: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl SlowWatchdog {
    /// `None` — and no thread — unless a debug record would actually be printed.
    fn arm(path: &str) -> Option<SlowWatchdog> {
        if !logging::Level::Debug.enabled_at(logging::level()) {
            return None;
        }
        let fired = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let waiter = std::sync::Arc::clone(&fired);
        let path = path.to_string();
        let threshold = slow_warning_threshold();
        let handle = std::thread::spawn(move || {
            if wait_for_inspection(&waiter, threshold) {
                // Go calls `SlowWarningThreshold.String()` — `time.Duration`'s
                // own formatting, NOT the project's `FormatDuration`. They
                // agree on 5s, but the message must track the Go call it ports.
                logging::debug().str("path", &path).msg(&format!(
                    "Taking longer than {} to inspect fragment",
                    logging::duration::duration_string(logging::duration::from_std(threshold))
                ));
            }
        });
        Some(SlowWatchdog {
            fired,
            handle: Some(handle),
        })
    }
}

impl Drop for SlowWatchdog {
    /// Go's `timer.Stop()`. Joining rather than detaching is deliberate: a
    /// detached thread could log "taking longer" about a fragment that had
    /// already finished, which is a lie that only appears under load.
    fn drop(&mut self) {
        let (lock, cv) = &*self.fired;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        cv.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Go `detect.Detector`.
pub struct Detector {
    pub config: Config,

    /// Go `MaxDecodeDepth`.
    pub max_decode_depth: usize,
    /// Go `MinConfidence`.
    pub min_confidence: String,
    /// Go `IgnoreGitleaksAllow`.
    pub ignore_gitleaks_allow: bool,
    /// Go `MatchContext`.
    pub match_context: contextwindow::Spec,
    /// Go `Redact` — needed HERE because the baseline comparison skips the
    /// secret when redaction is on (a redacted baseline has none to compare).
    pub redact: u32,

    /// Go `TotalBytes atomic.Uint64` — the "scanned ~N bytes" figure.
    ///
    /// Counted HERE rather than by the caller, and specifically AFTER the
    /// self-scan skip, because that is where Go counts it. Counting in the
    /// caller instead includes the scanner's own config file, which Go excludes
    /// — a 469-byte discrepancy that showed up in the corpus differential.
    total_bytes: std::sync::atomic::AtomicU64,

    /// Go `RuleTimings *RuleTimingCollector` - None when --diagnostics does
    /// not ask for rule timings, which is the default and the fast path.
    pub rule_timings: Option<std::sync::Arc<RuleTimingCollector>>,

    /// Go `tokenizer *tiktoken.Tiktoken`, behind its `sync.Once`.
    ///
    /// A `'static` reference rather than an owned value: the rank table is
    /// ~100k entries and every `Detector` would otherwise rebuild it. `None`
    /// when the asset failed to load, which is exactly Go's nil tokenizer —
    /// `tokenRatio` then returns 0 and nothing else changes.
    tokenizer: Option<&'static Cl100kTokenizer>,

    /// Go `prefilter *ahocorasick.Matcher` over the keyword set.
    prefilter: ahocorasick::Matcher,
    /// Keyword pattern id → rule indexes (Go `keywordRuleIndexes`).
    keyword_rule_indexes: Vec<Vec<usize>>,
    /// Rules with no keywords, always candidates (Go `noKeywordIndexes`).
    no_keyword_indexes: Vec<usize>,
    /// Go `rulesBySpecificity`.
    rules_by_specificity: Vec<String>,

    /// Compiled filter programs, keyed by rule id. Go compiles these lazily
    /// under a mutex; here they are built once at construction, which removes
    /// the lock from the hot path.
    rule_filters: HashMap<String, exprruntime::Program>,
    global_filter: Option<exprruntime::Program>,
    /// The compiled GLOBAL PREFILTER (`config.prefilter`). Compiled here rather
    /// than read from `Config`'s opaque program slot, because that slot is
    /// deliberately type-erased so `config` need not depend on `exprruntime` —
    /// the same reason the filters are compiled here.
    prefilter_program: Option<exprruntime::Program>,

    /// Go `baseline` — findings a previous scan already recorded.
    pub(crate) baseline: Vec<Finding>,
    /// Go `baselinePath`, relative to the scan source. The detector skips
    /// scanning its own baseline file, which would otherwise be a report full
    /// of secrets sitting inside the scanned tree.
    pub(crate) baseline_path: String,

    /// Go `gitleaksIgnore` — fingerprints suppressed by a
    /// `.betterleaksignore` / `.gitleaksignore` file. Empty until
    /// [`Detector::add_ignore_file`] is called, which is what the CLI does.
    pub gitleaks_ignore: std::collections::HashSet<String>,
}

impl Detector {
    /// Go `NewDetectorDefaultConfig` — the embedded 414-rule catalogue.
    pub fn with_default_config() -> Result<Detector, String> {
        let cfg = config::default_config().map_err(|e| e.to_string())?;
        Ok(Detector::new(cfg))
    }

    /// Compatibility alias for the pre-M13 API the lensr gate calls.
    ///
    /// It now returns the REAL engine with all 414 rules rather than the
    /// hand-written 26, which is the whole point of M13.
    pub fn with_default_rules() -> Detector {
        Detector::with_default_config().expect("the embedded catalogue must parse")
    }

    /// Go `NewDetectorContext` (minus validation and source wiring).
    pub fn new(config: Config) -> Detector {
        // Build the keyword prefilter. Pattern ids are positions in this vector,
        // which is how a match maps back to candidate rules.
        let keywords: Vec<String> = config.keywords.iter().cloned().collect();
        let keyword_refs: Vec<&str> = keywords.iter().map(|s| s.as_str()).collect();
        // fold_ascii = true: keywords are lower-cased at config load, and the
        // haystack is arbitrary case.
        let prefilter = ahocorasick::Matcher::compile(&keyword_refs, true);

        // Rules ordered by DESCENDING specificity, so a specific provider rule
        // is seen before the generic catch-all and can suppress it.
        let mut rules_by_specificity: Vec<String> = config.ordered_rules.clone();
        rules_by_specificity.sort_by(|a, b| {
            let sa = config.rules.get(a).map_or(0, |r| r.specificity);
            let sb = config.rules.get(b).map_or(0, |r| r.specificity);
            // Descending by specificity, then catalogue order for stability.
            sb.cmp(&sa)
        });

        let index_of: HashMap<&str, usize> = rules_by_specificity
            .iter()
            .enumerate()
            .map(|(i, id)| (id.as_str(), i))
            .collect();

        let mut keyword_rule_indexes: Vec<Vec<usize>> = vec![Vec::new(); keywords.len()];
        for (kw_id, kw) in keywords.iter().enumerate() {
            if let Some(ids) = config.keyword_to_rules.get(kw) {
                for id in ids {
                    if let Some(&ri) = index_of.get(id.as_str()) {
                        keyword_rule_indexes[kw_id].push(ri);
                    }
                }
            }
        }
        let no_keyword_indexes: Vec<usize> = config
            .no_keyword_rules
            .iter()
            .filter_map(|id| index_of.get(id.as_str()).copied())
            .collect();

        // Compile filters up front. A filter that fails to compile is DROPPED
        // with the rule still active — Go logs a warning and proceeds, so a bad
        // expression must not silently disable detection.
        let mut rule_filters = HashMap::new();
        for (id, rule) in &config.rules {
            if rule.filter.trim().is_empty() {
                continue;
            }
            if let Ok(Some(p)) = exprruntime::compile(&rule.filter) {
                rule_filters.insert(id.clone(), p);
            }
        }
        let global_filter = exprruntime::compile(&config.filter).ok().flatten();
        let prefilter_program = exprruntime::compile(&config.prefilter).ok().flatten();

        Detector {
            config,
            // Go's `NewDetectorDefaultConfig` leaves this at the zero value, so
            // the default engine performs NO decode passes. Verified by running
            // the Go engine: `MaxDecodeDepth=0`. Raising it here would make the
            // port scan strictly more than the source.
            max_decode_depth: 0,
            min_confidence: String::new(),
            ignore_gitleaks_allow: false,
            match_context: contextwindow::Spec::default(),
            redact: 0,
            total_bytes: std::sync::atomic::AtomicU64::new(0),
            rule_timings: None,
            // Built on first use and shared. Go defers this behind a sync.Once
            // for the same reason: most scans never evaluate a tokenRatio.
            tokenizer: Cl100kTokenizer::shared(),
            prefilter,
            keyword_rule_indexes,
            no_keyword_indexes,
            rules_by_specificity,
            rule_filters,
            global_filter,
            prefilter_program,
            // Empty until the CLI loads a `.betterleaksignore`, matching Go's
            // `make(map[string]struct{})` — the library never suppresses on its
            // own initiative.
            baseline: Vec::new(),
            baseline_path: String::new(),
            gitleaks_ignore: std::collections::HashSet::new(),
        }
    }

    /// Go `TotalBytes.Load()` — the bytes actually scanned.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many rules are loaded — 414 with the embedded catalogue.
    pub fn rule_count(&self) -> usize {
        self.config.rules.len()
    }

    /// Go `DetectString`.
    pub fn detect_string(&self, content: &str) -> Vec<Finding> {
        self.detect(&Fragment {
            raw: content.to_string(),
            ..Default::default()
        })
    }

    /// Compatibility entry point for the lensr gate, which reads blobs as bytes.
    ///
    /// Non-UTF-8 input is converted lossily rather than skipped: the gate scans
    /// arbitrary git blobs, and refusing to look at one because of an invalid
    /// byte would be a silent detection hole.
    pub fn detect_bytes(&self, data: &[u8]) -> Vec<Finding> {
        match std::str::from_utf8(data) {
            Ok(s) => self.detect_string(s),
            Err(_) => self.detect_string(&String::from_utf8_lossy(data)),
        }
    }

    /// Go `(*Detector).Detect` / `detectFragment` — the scan + decode loop.
    pub fn detect(&self, fragment: &Fragment) -> Vec<Finding> {
        // Go arms a `time.AfterFunc` around every fragment inspection
        // (detect/detect.go:548-558) so a fragment that is TAKING TOO LONG says
        // so WHILE it is still running. Logging the duration afterwards would
        // report the stall only once it ended, which is no use to somebody
        // watching a scan that appears hung.
        let _watchdog = SlowWatchdog::arm(fragment.attr(sources::ATTR_PATH));

        // Never scan our own config or baseline — a report or a rule file full
        // of secret-shaped strings, sitting inside the tree being scanned.
        let path = fragment.attr(sources::ATTR_PATH);
        if !path.is_empty()
            && (utils::same_path(path, &self.config.path)
                || (!self.baseline_path.is_empty()
                    && utils::same_path(path, &self.baseline_path)))
        {
            return Vec::new();
        }

        // Counted AFTER the skip, as Go does, so the summary never claims to
        // have scanned bytes it deliberately passed over.
        use std::sync::atomic::Ordering;
        if fragment.bytes.is_empty() {
            self.total_bytes
                .fetch_add(fragment.raw.len() as u64, Ordering::Relaxed);
        }
        self.total_bytes
            .fetch_add(fragment.bytes.len() as u64, Ordering::Relaxed);

        let mut findings: Vec<Finding> = Vec::new();
        let mut current_raw = fragment.raw.clone();
        let mut encoded_segments: Vec<codec::EncodedSegment> = Vec::new();
        let mut depth = 0usize;
        let mut decoder = codec::Decoder::new();

        loop {
            // Keyword prefilter: one pass marks every candidate rule.
            let mut marked = vec![false; self.rules_by_specificity.len()];
            self.prefilter.visit(&current_raw, |pattern_id, _, _| {
                if let Some(rules) = self.keyword_rule_indexes.get(pattern_id) {
                    for &ri in rules {
                        marked[ri] = true;
                    }
                }
                true
            });
            for &ri in &self.no_keyword_indexes {
                marked[ri] = true;
            }

            for (ri, rule_id) in self.rules_by_specificity.iter().enumerate() {
                if !marked[ri] {
                    continue;
                }
                let Some(rule) = self.config.rules.get(rule_id) else {
                    continue;
                };
                let produced = self.timed_detect_fragment_with_rule(
                    fragment,
                    &current_raw,
                    rule,
                    &encoded_segments,
                    &findings,
                );
                for f in produced {
                    if confidence::meets(&f.attr(confidence::ATTRIBUTE), &self.min_confidence) {
                        findings.push(f);
                    }
                }
            }

            depth += 1;
            if depth > self.max_decode_depth {
                break;
            }
            let (next_raw, segments) = decoder.decode(&current_raw, &encoded_segments);
            current_raw = next_raw;
            encoded_segments = segments;
            if encoded_segments.is_empty() {
                break;
            }
        }

        let findings = utils::filter(findings);

        // Suppression LAST, and in Go's order inside `AddFinding`: the
        // `.betterleaksignore` set first, then the baseline. Both run after a
        // finding is fully built and fingerprinted, because the fingerprint is
        // the ignore key and the baseline compares built fields.
        if self.gitleaks_ignore.is_empty() && self.baseline.is_empty() {
            return findings;
        }
        findings
            .into_iter()
            .filter(|f| !ignore::is_ignored(&self.gitleaks_ignore, f))
            .filter(|f| self.is_new_finding(f, self.redact))
            .collect()
    }

    /// Go `(*Detector).SkipFunc` (`detect/detect.go:436`) — the GLOBAL
    /// PREFILTER, evaluated against a fragment's attributes before it is read.
    ///
    /// This is not an optimisation. The shipped catalogue's `prefilter`
    /// excludes images, fonts, compiled binaries, `go.mod`/`go.sum`, `vendor/`,
    /// `node_modules/`, lockfiles and `.git` — content that is either
    /// unscannable or a reliable false-positive factory. A scan that skips this
    /// step reads more and reports worse.
    ///
    /// An expression that fails to evaluate does NOT skip (Go warns and returns
    /// false): when in doubt, scan.
    pub fn should_skip(&self, attrs: &std::collections::BTreeMap<String, String>) -> bool {
        // Go returns a NIL SkipFunc when there is no prefilter program, and a
        // nil SkipFunc skips nothing.
        let Some(program) = &self.prefilter_program else {
            return false;
        };
        let mut ctx = exprruntime::Context::new();
        ctx.attributes = attrs.clone();
        match exprruntime::eval_bool(program, &mut ctx) {
            Ok(skip) => skip,
            Err(e) => {
                logging::warn()
                    .err(&e)
                    .msg("prefilter eval error; not skipping");
                false
            }
        }
    }

    /// Go `(*Detector).AddGitleaksIgnore` — load a `.betterleaksignore` /
    /// `.gitleaksignore` file into the suppression set.
    ///
    /// Additive: the CLI calls this for the flag path, the flag directory and
    /// the scan target, and Go unions all three.
    ///
    /// Returns how many entries the file contributed.
    pub fn add_ignore_file(&mut self, path: &str) -> std::io::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let (entries, invalid) = ignore::parse_ignore_file(&content);
        for line in &invalid {
            logging::warn()
                .str("fingerprint", line)
                .msg("Invalid .betterleaksignore entry");
        }
        let n = entries.len();
        self.gitleaks_ignore.extend(entries);
        Ok(n)
    }

    /// Go `detectFragmentWithRuleTimed` (`detect/detect.go:804`).
    ///
    /// The clock is only read when a collector is attached. Go structures it
    /// the same way and for the same reason: two `time.Now()` calls per rule
    /// per fragment is 414 clock reads on every fragment, which is not free on
    /// a scan that reads millions of them.
    fn timed_detect_fragment_with_rule(
        &self,
        fragment: &Fragment,
        current_raw: &str,
        rule: &config::Rule,
        encoded_segments: &[codec::EncodedSegment],
        prior_findings: &[Finding],
    ) -> Vec<Finding> {
        let Some(collector) = &self.rule_timings else {
            return self.detect_fragment_with_rule(
                fragment,
                current_raw,
                rule,
                encoded_segments,
                prior_findings,
            );
        };
        let start = std::time::Instant::now();
        let findings = self.detect_fragment_with_rule(
            fragment,
            current_raw,
            rule,
            encoded_segments,
            prior_findings,
        );
        collector.record(&rule.rule_id, logging::duration::from_std(start.elapsed()));
        findings
    }

    /// Go `detectFragmentWithRule`.
    fn detect_fragment_with_rule(
        &self,
        fragment: &Fragment,
        current_raw: &str,
        rule: &config::Rule,
        encoded_segments: &[codec::EncodedSegment],
        prior_findings: &[Finding],
    ) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        if rule.skip_report && !fragment.inherited_from_finding {
            return findings;
        }

        // Path rules.
        if let Some(path_re) = &rule.path {
            let path_matches = rule_path_matches_fragment(path_re, fragment);
            if rule.regex.is_none() && encoded_segments.is_empty() {
                if path_matches {
                    findings.push(new_path_only_finding(rule, fragment));
                }
                return findings;
            }
            if !path_matches {
                return findings;
            }
        }

        let Some(regex) = &rule.regex else {
            return findings;
        };

        let Some(matches) = regex.find_all_index(current_raw, -1) else {
            return findings;
        };

        let mut newline_indices: Vec<[usize; 2]> = Vec::new();
        let mut newline_computed = false;

        for m in matches {
            let mut match_index = m;
            // Go: strings.Trim(currentRaw[a:b], "\n")
            let raw_slice = slice_str(current_raw, match_index[0], match_index[1]);
            let secret = raw_slice.trim_matches('\n').to_string();
            let (filter_match_start, filter_match_end) = (match_index[0], match_index[1]);

            let mut meta_tags: Vec<String> = Vec::new();
            let mut current_line = String::new();

            if !encoded_segments.is_empty() {
                let segments = codec::segments_with_decoded_overlap(
                    encoded_segments,
                    match_index[0] as i64,
                    match_index[1] as i64,
                );
                if segments.is_empty() {
                    // Already reported as part of an earlier finding.
                    continue;
                }
                let adjusted = codec::adjust_match_index(
                    &segments,
                    &[match_index[0] as i64, match_index[1] as i64],
                );
                match_index = [adjusted[0].max(0) as usize, adjusted[1].max(0) as usize];
                meta_tags.extend(codec::tags(&segments));
                current_line = codec::current_line(&segments, current_raw);
            } else {
                // gitleaks#1352 — drop a trailing newline the regex swallowed.
                match_index[1] = match_index[0] + secret.len();
            }

            if !newline_computed {
                newline_indices = utils::find_newline_indices(&fragment.raw);
                newline_computed = true;
            }
            let mut loc = location::location(&newline_indices, &fragment.raw, match_index);
            if match_index[1] > loc.end_line_index {
                loc.end_line_index = match_index[1];
            }

            let mut tags = rule.tags.clone();
            tags.extend(meta_tags);

            let mut finding = Finding {
                rule_id: rule.rule_id.clone(),
                description: rule.description.clone(),
                start_line: fragment.start_line + loc.start_line,
                end_line: fragment.start_line + loc.end_line,
                start_column: loc.start_column,
                end_column: loc.end_column,
                line: slice_str(&fragment.raw, loc.start_line_index, loc.end_line_index),
                r#match: secret.clone(),
                secret: secret.clone(),
                attributes: fragment.attributes.clone().into_iter().collect(),
                tags,
                rule_specificity: rule.specificity,
                ..Default::default()
            };
            if !rule.confidence.is_empty() {
                finding.set_attr(confidence::ATTRIBUTE, &rule.confidence);
            }

            // Allow signature — checked against the finding's LINE.
            if !self.ignore_gitleaks_allow && utils::contains_allow_signature(&finding.line) {
                continue;
            }
            finding.sync_deprecated_source_fields();

            if current_line.is_empty() {
                current_line = finding.line.clone();
            }

            // secretGroup / named captures.
            if let Some(groups) = regex.find_submatch(&finding.secret) {
                if groups.len() >= 2 {
                    if rule.secret_group > 0 {
                        if (groups.len() as i64) <= rule.secret_group {
                            continue; // config validation should prevent this
                        }
                        finding.secret = groups[rule.secret_group as usize].clone();
                    } else {
                        // First non-empty capture group wins.
                        for g in &groups[1..] {
                            if !g.is_empty() {
                                finding.secret = g.clone();
                                break;
                            }
                        }
                    }
                    if let Some(names) = regex.subexp_names() {
                        let mut captures = std::collections::HashMap::new();
                        for (i, name) in names.iter().enumerate() {
                            if i > 0 && !name.is_empty() && i < groups.len() && !groups[i].is_empty()
                            {
                                captures.insert(name.clone(), groups[i].clone());
                            }
                        }
                        if !captures.is_empty() {
                            finding.capture_groups = captures;
                        }
                    }
                }
            }

            if !prior_findings.is_empty()
                && utils::is_suppressed_by_higher_specificity_finding(&finding, prior_findings)
            {
                continue;
            }

            // Entropy is ALWAYS computed — reports show it regardless of filters.
            // Note this is detect's rune/byte hybrid, NOT the filter one.
            let entropy = utils::shannon_entropy(&finding.secret);
            finding.entropy = entropy as f32;

            finding.set_fingerprint();

            let rule_filter = self.rule_filters.get(&rule.rule_id);
            let has_any_filter = self.global_filter.is_some() || rule_filter.is_some();

            if has_any_filter {
                finding.set_expr_context(&contextwindow::extract(
                    &fragment.raw,
                    match_index,
                    &contextwindow::Spec {
                        mode: contextwindow::Mode::Box,
                        lines_before: 20,
                        lines_after: 20,
                        cols_before: 350,
                        cols_after: 350,
                    },
                ));
            }

            if has_any_filter {
                let mut ctx = exprruntime::Context::new();
                // Go `exprRuntime.SetTokenizerProvider(d.Tokenizer)`. Without
                // this, `filter.tokenRatio` returns 0 in all 121 expressions
                // that call it — which is a legal degradation but means those
                // filters decide nothing.
                ctx.tokenizer = self
                    .tokenizer
                    .map(|t| t as &dyn exprruntime::Tokenizer);
                for (k, v) in finding.to_expr_map() {
                    ctx.finding.insert(k, exprruntime::Value::Str(v));
                }
                ctx.finding
                    .insert("entropy".to_string(), exprruntime::Value::Str(format_go_float(entropy)));
                ctx.finding.insert(
                    "fragment_raw".to_string(),
                    exprruntime::Value::Str(current_raw.to_string()),
                );
                ctx.finding.insert(
                    "match_start_idx".to_string(),
                    exprruntime::Value::Num(filter_match_start as f64),
                );
                ctx.finding.insert(
                    "match_end_idx".to_string(),
                    exprruntime::Value::Num(filter_match_end as f64),
                );
                // Line bounds, used by the generic rule's slice windows.
                let line_start = current_raw[..filter_match_start]
                    .rfind(['\r', '\n'])
                    .map_or(0, |i| i + 1);
                let line_end = current_raw[filter_match_end..]
                    .find(['\r', '\n'])
                    .map_or(current_raw.len(), |i| filter_match_end + i);
                ctx.finding.insert(
                    "match_line_start_idx".to_string(),
                    exprruntime::Value::Num(line_start as f64),
                );
                ctx.finding.insert(
                    "match_line_end_idx".to_string(),
                    exprruntime::Value::Num(line_end as f64),
                );
                if !current_line.is_empty() {
                    ctx.finding
                        .insert("line".to_string(), exprruntime::Value::Str(current_line.clone()));
                }
                ctx.attributes = finding.attributes.clone().into_iter().collect();

                // Global filter, then rule filter. `true` means SKIP.
                // An eval ERROR must not drop the finding — Go logs and keeps
                // going, so a broken expression fails OPEN.
                if let Some(p) = &self.global_filter {
                    if matches!(exprruntime::eval_bool(p, &mut ctx), Ok(true)) {
                        continue;
                    }
                }
                if let Some(p) = rule_filter {
                    if matches!(exprruntime::eval_bool(p, &mut ctx), Ok(true)) {
                        continue;
                    }
                }
                // A filter may have written an attribute (filter.setConfidence).
                finding.attributes = ctx.attributes.into_iter().collect();
            }

            if !self.match_context.is_zero() {
                finding.match_context =
                    contextwindow::extract(&fragment.raw, match_index, &self.match_context);
            }

            findings.push(finding);
        }

        // Composite rules: attach nearby component matches and ENFORCE required
        // ones. Without this the engine over-reports — a lone AWS access-key id
        // would be a finding where the source drops it.
        if fragment.inherited_from_finding || rule.components.is_empty() {
            return findings;
        }
        self.process_components(fragment, current_raw, rule, encoded_segments, findings)
    }

    /// Go `processComponents`.
    fn process_components(
        &self,
        fragment: &Fragment,
        current_raw: &str,
        rule: &config::Rule,
        encoded_segments: &[codec::EncodedSegment],
        primary_findings: Vec<Finding>,
    ) -> Vec<Finding> {
        if primary_findings.is_empty() {
            return primary_findings;
        }

        // Collect each component rule's findings ONCE per fragment.
        let mut all_component_findings: HashMap<String, Vec<Finding>> = HashMap::new();
        let mut component_windows: HashMap<String, contextwindow::Spec> = HashMap::new();

        for component in &rule.components {
            let Ok(window) = contextwindow::parse(&component.within) else {
                // Go logs and skips; config validation should have caught it.
                continue;
            };
            component_windows.insert(component.rule_id.clone(), window);

            let Some(component_rule) = self.config.rules.get(&component.rule_id) else {
                continue;
            };

            // Mark the fragment inherited to stop infinite recursion — a
            // component rule may itself declare components.
            let inherited = Fragment {
                inherited_from_finding: true,
                ..fragment.clone()
            };
            let found = self.detect_fragment_with_rule(
                &inherited,
                current_raw,
                component_rule,
                encoded_segments,
                &[],
            );
            all_component_findings.insert(component.rule_id.clone(), found);
        }

        let mut final_findings = Vec::new();
        for primary in primary_findings {
            let mut component_findings: Vec<report::ComponentFinding> = Vec::new();

            for component in &rule.components {
                let Some(found_list) = all_component_findings.get(&component.rule_id) else {
                    continue;
                };
                let window = component_windows
                    .get(&component.rule_id)
                    .cloned()
                    .unwrap_or_default();
                for found in found_list {
                    if components::within_proximity(
                        &fragment.raw,
                        fragment.start_line,
                        &primary,
                        found,
                        &window,
                    ) {
                        component_findings
                            .push(components::to_component_finding(found, component.optional));
                    }
                }
            }

            if components::has_all_required_components(&component_findings, &rule.components) {
                let mut f = primary;
                f.build_component_sets(&component_findings, components::MAX_COMPONENT_SETS);
                final_findings.push(f);
            }
        }

        final_findings
    }
}

/// Go's `strconv.FormatFloat(entropy, 'g', -1, 64)` — the shortest
/// representation that round-trips, which is what `{}` gives for `f64`.
fn format_go_float(v: f64) -> String {
    format!("{v}")
}

/// Byte-safe substring. Go slices strings by bytes and never panics; a Rust
/// `&str` slice would on a mid-rune boundary.
fn slice_str(s: &str, lo: usize, hi: usize) -> String {
    let b = s.as_bytes();
    let lo = lo.min(b.len());
    let hi = hi.clamp(lo, b.len());
    String::from_utf8_lossy(&b[lo..hi]).into_owned()
}

/// Go `rulePathMatchesFragment`.
fn rule_path_matches_fragment(path_rule: &regexp::Regexp, fragment: &Fragment) -> bool {
    path_rule.is_match(fragment.attr(sources::ATTR_PATH))
}

/// Go `newPathOnlyFinding`.
fn new_path_only_finding(rule: &config::Rule, fragment: &Fragment) -> Finding {
    let mut f = Finding {
        rule_id: rule.rule_id.clone(),
        description: rule.description.clone(),
        start_line: 1,
        end_line: 1,
        r#match: format!("file detected: {}", fragment.attr(sources::ATTR_PATH)),
        attributes: fragment.attributes.clone().into_iter().collect(),
        tags: rule.tags.clone(),
        rule_specificity: rule.specificity,
        ..Default::default()
    };
    if !rule.confidence.is_empty() {
        f.set_attr(confidence::ATTRIBUTE, &rule.confidence);
    }
    f.sync_deprecated_source_fields();
    f.set_fingerprint();
    f
}

#[cfg(test)]
mod tests;
