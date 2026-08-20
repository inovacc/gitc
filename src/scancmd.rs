//! `gitc scan` — the local secret-scan command surface.
//!
//! Detect → classify → report over git-native readers ([`crate::gitindex`] /
//! [`crate::gitobj`]), the filesystem, or stdin, using the vendored `detect`
//! engine. Read-only and offline: it never performs secret-derived network
//! requests. This is a LIBRARY entry point — it returns the process exit code
//! for the binary to use and NEVER calls `process::exit` itself.
//!
//! Exit codes (stable contract):
//!   0  clean / success        3  scanner/runtime error
//!   1  findings               4  remediation verification failed (scrub)
//!   2  usage/config error     5  rewrite safety precondition failed (scrub)
//!
//! Implemented here: `stdin`, `dir`, `git` (`--staged`/`--working-tree`/`--history`/
//! `--all-refs`/`<commit>`/`<range>`/`--trace-finding`), `known`, `baseline`,
//! `explain`, `hooks`, `config`, plus an optional per-blob-OID incremental `--cache`.
//! Suppression follows the goal's §27 model — inline `betterleaks:allow`,
//! `.betterleaksignore`, and `--baseline` HIDE findings; `gitc:known` only
//! ACKNOWLEDGES. Destructive history remediation lives in the sibling `gitc scrub`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use detect::{global_fingerprint, masked, Detector};
use report::{CsvReporter, Finding, JsonReporter, JunitReporter, SarifReporter};
use sources::{Fragment, ATTR_GIT_SHA, ATTR_PATH};

pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_RUNTIME: i32 = 3;

/// Per-blob / total scan budgets (resource hardening, goal §33).
const MAX_BLOB_BYTES: usize = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Parsed `gitc scan …` options.
struct Opts {
    report_format: String, // human|json|sarif|junit|csv
    report_path: String,   // "" = stdout
    redact: u32,           // 0 = off
    exit_code: i32,        // exit code to use when findings exist (default 1)
    // git-mode selectors
    staged: bool,
    working_tree: bool,
    history: bool,                   // walk all commits reachable from HEAD
    all_refs: bool,                  // walk all commits reachable from every ref
    trace_finding: Option<String>,   // report a finding's introduction commit
    baseline: String,                // path to a baseline JSON report ("" = none)
    confidence: String,              // minimum confidence to report ("" = all)
    config_path: String,             // custom rule config (.toml); "" = built-in
    cache: bool,                     // reuse per-blob-OID scan results across runs
    max_blob_mb: Option<u64>,        // per-blob size cap (§33)
    max_total_mb: Option<u64>,       // whole-scan byte budget (§33)
    max_decode_depth: Option<usize>, // detector decode-recursion cap (§33)
    follow_symlinks: bool,           // follow symlinks in dir/working-tree walks (§33)
    pre_push: bool,                  // scan only outgoing (to-be-pushed) commits (§30/§31)
    remote: String,                  // tracking remote for --pre-push (default origin)
    jobs: usize,                     // bounded parallel history scan (§42); 1 = serial
    positional: Vec<String>,         // a <commit> or <range> for `git`
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            report_format: "human".to_string(),
            report_path: String::new(),
            redact: 0,
            exit_code: EXIT_FINDINGS,
            staged: false,
            working_tree: false,
            history: false,
            all_refs: false,
            trace_finding: None,
            baseline: String::new(),
            confidence: String::new(),
            config_path: String::new(),
            cache: false,
            max_blob_mb: None,
            max_total_mb: None,
            max_decode_depth: None,
            follow_symlinks: false,
            pre_push: false,
            remote: "origin".to_string(),
            jobs: 1,
            positional: Vec::new(),
        }
    }
}

/// Per-blob byte cap (§33): `--max-target-megabytes`, else the default.
fn blob_cap(o: &Opts) -> usize {
    o.max_blob_mb
        .map(|m| (m as usize).saturating_mul(1024 * 1024))
        .unwrap_or(MAX_BLOB_BYTES)
}

/// Whole-scan byte budget (§33): `--max-total-megabytes`, else the default.
fn total_cap(o: &Opts) -> u64 {
    o.max_total_mb
        .map(|m| m.saturating_mul(1024 * 1024))
        .unwrap_or(MAX_TOTAL_BYTES)
}

/// `gitc scan <subcommand> [args]`. `args` is everything AFTER `scan`.
pub fn run(args: &[String]) -> i32 {
    let Some((sub, rest)) = args.split_first() else {
        eprintln!("{}", usage());
        return EXIT_USAGE;
    };
    match sub.as_str() {
        "git" => match parse(rest) {
            Ok(o) => scan_git(&o),
            Err(e) => usage_err(&e),
        },
        "dir" | "directory" => match parse(rest) {
            Ok(o) => scan_dir(&o),
            Err(e) => usage_err(&e),
        },
        "stdin" => match parse(rest) {
            Ok(o) => scan_stdin(&o),
            Err(e) => usage_err(&e),
        },
        "known" => known_cmd(rest),
        "config" => config_cmd(rest),
        "baseline" => baseline_cmd(rest),
        "explain" => explain_cmd(rest),
        "hooks" => hooks_cmd(rest),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            EXIT_CLEAN
        }
        other => usage_err(&format!("unknown scan subcommand '{other}'")),
    }
}

fn usage() -> &'static str {
    "gitc scan — local secret detection (read-only, offline)\n\
     \n\
     USAGE:\n\
       gitc scan git [--staged | --working-tree]   scan the repo (staged set or working tree)\n\
       gitc scan git --history [--all-refs]        scan all reachable history (introduction-attributed)\n\
       gitc scan git <commit> | <A..B> | <A...B>   scan a commit or commit range\n\
       gitc scan git --trace-finding <fp>          trace a finding to its introducing commit\n\
       gitc scan git --pre-push [--remote <r>]     scan only outgoing commits (new leaks; §30/§31)\n\
       gitc scan dir <path>                        scan a directory tree\n\
       gitc scan stdin                             scan piped input\n\
       gitc scan known <file>:<line>               stamp a `// gitc:known [v1:…]` fingerprint\n\
       gitc scan baseline create [scope]           write a JSON baseline to suppress existing findings\n\
       gitc scan explain <rule-id>                 print a rule's description/regex/keywords\n\
       gitc scan hooks <install|uninstall|status>  manage the pre-commit secret-scan hook\n\
       gitc scan config <check|show|path> [file]   load + validate a rule config\n\
     \n\
     FLAGS:\n\
       --report-format <human|json|sarif|junit|csv>   default: human\n\
       --report-path <file>                            default: stdout\n\
       --config <file>                                 custom rule catalogue (.toml)\n\
       --confidence <low|medium|high>                  minimum confidence to report\n\
       --cache                                         reuse per-blob-OID results (fast re-scans)\n\
       --max-target-megabytes <n>                      per-blob size cap\n\
       --max-total-megabytes <n>                       whole-scan byte budget\n\
       --max-decode-depth <n>                          decode-recursion cap\n\
       --follow-symlinks                               follow symlinks in dir/working-tree walks\n\
       --jobs <n>                                      bounded parallel history scan (default 1)\n\
       --baseline <file>                               suppress findings recorded in a baseline\n\
       --redact [N]                                    mask secrets in output\n\
       --exit-code <n>                                 exit code when findings exist (default 1)\n\
     \n\
     Suppression (§27): inline `betterleaks:allow`, `.betterleaksignore`, and a\n\
     --baseline all HIDE findings; `gitc scan known` only ACKNOWLEDGES (still reported).\n\
     \n\
     To remove a found secret from history, see `gitc scrub` (destructive remediation)."
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("gitc scan: {msg}\n\n{}", usage());
    EXIT_USAGE
}

/// Flag parser. `--redact` takes an OPTIONAL value (bare `--redact` = 100).
fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--staged" | "--pre-commit" => o.staged = true,
            "--working-tree" => o.working_tree = true,
            "--history" => o.history = true,
            "--all-refs" => o.all_refs = true,
            "--trace-finding" => o.trace_finding = Some(take(args, &mut i, a)?),
            "--baseline" | "--baseline-path" => o.baseline = take(args, &mut i, a)?,
            "--confidence" | "--min-confidence" => o.confidence = take(args, &mut i, a)?,
            "--config" => o.config_path = take(args, &mut i, a)?,
            "--cache" | "--incremental" => o.cache = true,
            "--pre-push" => o.pre_push = true,
            "--remote" => o.remote = take(args, &mut i, a)?,
            "--jobs" | "-j" => {
                o.jobs = take(args, &mut i, a)?
                    .parse::<usize>()
                    .map_err(|_| format!("{a} needs a positive integer"))?
                    .max(1)
            }
            "--follow-symlinks" => o.follow_symlinks = true,
            "--max-target-megabytes" | "--max-blob-megabytes" => {
                o.max_blob_mb = Some(
                    take(args, &mut i, a)?
                        .parse()
                        .map_err(|_| format!("{a} needs an integer"))?,
                )
            }
            "--max-total-megabytes" => {
                o.max_total_mb = Some(
                    take(args, &mut i, a)?
                        .parse()
                        .map_err(|_| format!("{a} needs an integer"))?,
                )
            }
            "--max-decode-depth" => {
                o.max_decode_depth = Some(
                    take(args, &mut i, a)?
                        .parse()
                        .map_err(|_| format!("{a} needs an integer"))?,
                )
            }
            "--report-format" => o.report_format = take(args, &mut i, a)?,
            "--report-path" => o.report_path = take(args, &mut i, a)?,
            "--exit-code" => {
                o.exit_code = take(args, &mut i, a)?
                    .parse()
                    .map_err(|_| "--exit-code needs an integer".to_string())?
            }
            "--redact" => {
                // optional value: `--redact` or `--redact 50`
                if i + 1 < args.len() && args[i + 1].parse::<u32>().is_ok() {
                    i += 1;
                    o.redact = args[i].parse().unwrap();
                } else {
                    o.redact = 100;
                }
            }
            "-h" | "--help" => return Err("help".to_string()),
            s if s.starts_with('-') => return Err(format!("unknown flag '{s}'")),
            _ => o.positional.push(a.clone()),
        }
        i += 1;
    }
    Ok(o)
}

fn take(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

// ── scan modes ──────────────────────────────────────────────────────────────

fn scan_stdin(o: &Opts) -> i32 {
    let mut buf = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
        eprintln!("gitc scan: read stdin: {e}");
        return EXIT_RUNTIME;
    }
    let d = match make_detector(o, Path::new("."), "<stdin>") {
        Ok(d) => d,
        Err(e) => return usage_err(&e),
    };
    let mut hits = detect_frag(&d, &buf, "<stdin>", "");
    finish(o, &mut hits, Some(&d))
}

fn scan_dir(o: &Opts) -> i32 {
    let Some(root) = o.positional.first() else {
        return usage_err("`gitc scan dir` needs a <path>");
    };
    let d = match make_detector(o, Path::new(root), root) {
        Ok(d) => d,
        Err(e) => return usage_err(&e),
    };
    let mut hits = Vec::new();
    let mut total: u64 = 0;
    if let Err(e) = walk_files(o, Path::new(root), &d, "", &mut hits, &mut total, 0) {
        eprintln!("gitc scan: {e}");
        return EXIT_RUNTIME;
    }
    finish(o, &mut hits, Some(&d))
}

fn scan_git(o: &Opts) -> i32 {
    let gitdir = match discover_gitdir() {
        Ok(g) => g,
        Err(e) => return usage_err(&e),
    };
    // Introduction trace of a single finding wins over any bulk mode.
    if let Some(fp) = o.trace_finding.clone() {
        return scan_trace(&gitdir, o, &fp);
    }
    // History / all-refs / pre-push / an explicit <commit>|<range> → object scan.
    if o.history || o.all_refs || o.pre_push || !o.positional.is_empty() {
        return scan_history(&gitdir, o);
    }
    if o.working_tree {
        // Walk the repo working tree (excluding .git).
        let root = gitdir.parent().unwrap_or(&gitdir).to_path_buf();
        let d = match make_detector(o, &root, &root.to_string_lossy()) {
            Ok(d) => d,
            Err(e) => return usage_err(&e),
        };
        let mut hits = Vec::new();
        let mut total: u64 = 0;
        if let Err(e) = walk_files(o, &root, &d, "", &mut hits, &mut total, 0) {
            eprintln!("gitc scan: {e}");
            return EXIT_RUNTIME;
        }
        return finish(o, &mut hits, Some(&d));
    }
    // Default / --staged: scan the .git/index blob set.
    let root = gitdir.parent().unwrap_or(&gitdir).to_path_buf();
    let d = match make_detector(o, &root, &root.to_string_lossy()) {
        Ok(d) => d,
        Err(e) => return usage_err(&e),
    };
    match scan_staged(o, &d, &gitdir) {
        Ok(mut hits) => finish(o, &mut hits, Some(&d)),
        Err(e) => {
            eprintln!("gitc scan: staged scan: {e}");
            EXIT_RUNTIME
        }
    }
}

/// Scan every distinct blob reachable from the selected scope (HEAD by default,
/// every ref with `--all-refs`, or an explicit `<commit>`/`<A..B>` range), each
/// attributed to its introducing commit (goal §3, §30). No checkout, no
/// subprocess — pure git-object reads via [`crate::gitwalk`].
fn scan_history(gitdir: &Path, o: &Opts) -> i32 {
    let (tips, exclude) = match resolve_scope(gitdir, o) {
        Ok(v) => v,
        Err(e) => return usage_err(&e),
    };
    if tips.is_empty() {
        eprintln!("gitc scan: no commits in scope (empty or unborn history)");
        return finish(o, &mut Vec::new(), None);
    }
    let (intros, truncated) = crate::gitwalk::reachable_blob_intros(gitdir, &tips, &exclude);
    if truncated {
        eprintln!("gitc scan: history walk truncated (resource cap) — partial scan");
    }
    let root = gitdir.parent().unwrap_or(gitdir).to_path_buf();
    let d = match make_detector(o, &root, &root.to_string_lossy()) {
        Ok(d) => d,
        Err(e) => return usage_err(&e),
    };
    let mut cache = if o.cache {
        Some(ScanCache::load(gitdir, &d))
    } else {
        None
    };
    let result = scan_intros(o, &d, gitdir, &intros, cache.as_mut());
    if let Some(c) = &cache {
        c.save();
    }
    match result {
        Ok(mut hits) => finish(o, &mut hits, Some(&d)),
        Err(e) => {
            eprintln!("gitc scan: history scan: {e}");
            EXIT_RUNTIME
        }
    }
}

/// Trace one finding to its introduction: scan reachable history and report the
/// finding whose fingerprint matches `fp`, carrying the introducing commit
/// (goal §4). Scope follows `--all-refs`, else HEAD.
fn scan_trace(gitdir: &Path, o: &Opts, fp: &str) -> i32 {
    let tips = if o.all_refs {
        crate::gitwalk::all_ref_tips(gitdir)
    } else {
        crate::gitwalk::head_tip(gitdir).into_iter().collect()
    };
    if tips.is_empty() {
        eprintln!("gitc scan: no commits in scope to trace");
        return finish(o, &mut Vec::new(), None);
    }
    let (intros, _truncated) = crate::gitwalk::reachable_blob_intros(gitdir, &tips, &[]);
    let root = gitdir.parent().unwrap_or(gitdir).to_path_buf();
    let d = match make_detector(o, &root, &root.to_string_lossy()) {
        Ok(d) => d,
        Err(e) => return usage_err(&e),
    };
    let hits = match scan_intros(o, &d, gitdir, &intros, None) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("gitc scan: trace scan: {e}");
            return EXIT_RUNTIME;
        }
    };
    let mut matched: Vec<Finding> = hits
        .into_iter()
        .filter(|f| fingerprint_matches(f, fp))
        .collect();
    if matched.is_empty() {
        eprintln!("gitc scan: no finding matches fingerprint '{fp}' in reachable history");
        return finish(o, &mut Vec::new(), None);
    }
    finish(o, &mut matched, Some(&d))
}

/// A finding matches a trace query if the query equals its canonical fingerprint
/// (`[commit:]file:rule:line`), the same with a `v1:` acknowledgement prefix
/// stripped from either side, or a prefix thereof (abbreviated ids).
fn fingerprint_matches(f: &Finding, query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return false;
    }
    let full = f.fingerprint.as_str();
    let bare = full.strip_prefix("v1:").unwrap_or(full);
    full == q || bare == q || full.starts_with(q) || bare.starts_with(q)
}

/// Read + detect over a list of introduced blobs, bounded by the shared budget.
/// With a `cache`, a blob OID already scanned under the same ruleset skips the read
/// + detect entirely and its metadata is reused (goal §40/§41).
fn scan_intros(
    o: &Opts,
    d: &Detector,
    gitdir: &Path,
    intros: &[crate::gitwalk::BlobIntro],
    mut cache: Option<&mut ScanCache>,
) -> Result<Vec<Finding>, String> {
    // Bounded parallel path (§42): only when jobs>1 AND no cache (the cache is a
    // single-owner &mut). Deterministic report order is preserved by sorting on the
    // intro index; the byte budget is shared via an atomic.
    if o.jobs > 1 && cache.is_none() {
        return Ok(scan_intros_parallel(o, d, gitdir, intros));
    }
    let (blob_cap, total_cap) = (blob_cap(o), total_cap(o));
    let mut hits = Vec::new();
    let mut total: u64 = 0;
    for b in intros {
        // Cache hit: an immutable blob OID scanned before under this ruleset —
        // reuse its findings (metadata only; no secret bytes are ever cached).
        if let Some(c) = cache.as_deref() {
            if let Some(cached) = c.get(&b.oid_hex) {
                for cf in cached {
                    hits.push(cf.to_finding(&b.path, &b.commit));
                }
                continue;
            }
        }
        let content = match crate::gitobj::read_blob(gitdir, &b.oid_hex, blob_cap) {
            Ok(Some(c)) => c,
            Ok(None) => continue, // non-blob / oversized — skipped
            Err(e) => {
                eprintln!("gitc scan: skipped {} ({e})", b.path);
                continue;
            }
        };
        if is_binary(&content) {
            continue;
        }
        total += content.len() as u64;
        if total > total_cap {
            eprintln!("gitc scan: history scan truncated (exceeded {total_cap} bytes)");
            break;
        }
        let found = detect_frag(d, &content, &b.path, &b.commit);
        if let Some(c) = cache.as_deref_mut() {
            c.put(&b.oid_hex, &found);
        }
        hits.extend(found);
    }
    Ok(hits)
}

/// Bounded parallel history scan (§42). `o.jobs` worker threads pull blob indices
/// from a shared atomic cursor, read + detect concurrently, and record results
/// keyed by their intro index; the shared byte budget is an atomic. Report order is
/// the deterministic intros order (sort by index), independent of thread timing.
fn scan_intros_parallel(
    o: &Opts,
    d: &Detector,
    gitdir: &Path,
    intros: &[crate::gitwalk::BlobIntro],
) -> Vec<Finding> {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    let (blob_cap, total_cap) = (blob_cap(o), total_cap(o));
    let cursor = AtomicUsize::new(0);
    let total = AtomicU64::new(0);
    let results: Mutex<Vec<(usize, Vec<Finding>)>> = Mutex::new(Vec::new());
    let jobs = o.jobs.min(intros.len().max(1));

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| loop {
                let i = cursor.fetch_add(1, Ordering::Relaxed);
                if i >= intros.len() || total.load(Ordering::Relaxed) > total_cap {
                    break;
                }
                let b = &intros[i];
                let content = match crate::gitobj::read_blob(gitdir, &b.oid_hex, blob_cap) {
                    Ok(Some(c)) => c,
                    _ => continue,
                };
                if is_binary(&content) {
                    continue;
                }
                total.fetch_add(content.len() as u64, Ordering::Relaxed);
                let found = detect_frag(d, &content, &b.path, &b.commit);
                if !found.is_empty() {
                    results.lock().unwrap().push((i, found));
                }
            });
        }
    });

    let mut collected = results.into_inner().unwrap();
    collected.sort_by_key(|(i, _)| *i); // deterministic order regardless of timing
    collected.into_iter().flat_map(|(_, f)| f).collect()
}

// ── incremental object-ID scan cache (§40/§41) ───────────────────────────────

/// A per-blob-OID scan cache. Keyed by IMMUTABLE blob OID under a ruleset-version
/// tag, so a blob's scan result is reused across `--history` runs and invalidated
/// wholesale when the rule catalogue changes. Stores ONLY finding metadata (rule,
/// line span) — never the secret bytes (§37/§40) — so a fingerprint is recomputed
/// from the current path/commit, and the value is shown as elided.
struct ScanCache {
    version: String,
    entries: std::collections::HashMap<String, Vec<CachedFinding>>,
    path: PathBuf,
    dirty: bool,
}

/// A cached finding's non-secret metadata.
struct CachedFinding {
    rule_id: String,
    start_line: i64,
    end_line: i64,
}

impl CachedFinding {
    /// Rebuild a reportable [`Finding`] at the current path/commit — the value is
    /// elided (the cache never stored it), the fingerprint recomputed canonically.
    fn to_finding(&self, file: &str, commit: &str) -> Finding {
        let fp = if commit.is_empty() {
            format!("{}:{}:{}", file, self.rule_id, self.start_line)
        } else {
            format!("{}:{}:{}:{}", commit, file, self.rule_id, self.start_line)
        };
        Finding {
            rule_id: self.rule_id.clone(),
            start_line: self.start_line,
            end_line: self.end_line,
            file: file.to_string(),
            commit: commit.to_string(),
            fingerprint: fp,
            secret: "[cached — rescan without --cache for the value]".to_string(),
            ..Default::default()
        }
    }
}

impl ScanCache {
    /// The ruleset-version tag: bumping the format or the rule count invalidates.
    fn version_tag(d: &Detector) -> String {
        format!("gitc-scan-cache/1 rules={}", d.rule_count())
    }

    /// Load the cache at `<git-dir>/gitc-scan-cache`, discarding it if its version
    /// tag no longer matches the active ruleset.
    fn load(gitdir: &Path, d: &Detector) -> ScanCache {
        let version = Self::version_tag(d);
        let path = gitdir.join("gitc-scan-cache");
        let mut entries = std::collections::HashMap::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            let mut lines = text.lines();
            if lines.next() == Some(version.as_str()) {
                let mut cur: Option<(String, usize)> = None;
                let mut acc: Vec<CachedFinding> = Vec::new();
                for line in lines {
                    match cur.take() {
                        None => {
                            if let Some((oid, n)) = line.split_once(' ') {
                                let count: usize = n.trim().parse().unwrap_or(0);
                                if count == 0 {
                                    entries.insert(oid.to_string(), Vec::new());
                                } else {
                                    cur = Some((oid.to_string(), count));
                                }
                            }
                        }
                        Some((oid, remaining)) => {
                            let mut it = line.split('\t');
                            if let (Some(rule), Some(s), Some(e)) =
                                (it.next(), it.next(), it.next())
                            {
                                acc.push(CachedFinding {
                                    rule_id: rule.to_string(),
                                    start_line: s.parse().unwrap_or(0),
                                    end_line: e.parse().unwrap_or(0),
                                });
                            }
                            if remaining > 1 {
                                cur = Some((oid, remaining - 1));
                            } else {
                                entries.insert(oid, std::mem::take(&mut acc));
                            }
                        }
                    }
                }
            }
        }
        ScanCache {
            version,
            entries,
            path,
            dirty: false,
        }
    }

    fn get(&self, oid: &str) -> Option<&Vec<CachedFinding>> {
        self.entries.get(oid)
    }

    fn put(&mut self, oid: &str, findings: &[Finding]) {
        let recs = findings
            .iter()
            .map(|f| CachedFinding {
                rule_id: f.rule_id.clone(),
                start_line: f.start_line,
                end_line: f.end_line,
            })
            .collect();
        self.entries.insert(oid.to_string(), recs);
        self.dirty = true;
    }

    /// Persist the cache (best effort; a write failure only forfeits the speedup).
    fn save(&self) {
        if !self.dirty {
            return;
        }
        let mut out = String::new();
        out.push_str(&self.version);
        out.push('\n');
        for (oid, recs) in &self.entries {
            out.push_str(&format!("{oid} {}\n", recs.len()));
            for r in recs {
                out.push_str(&format!(
                    "{}\t{}\t{}\n",
                    r.rule_id, r.start_line, r.end_line
                ));
            }
        }
        let _ = std::fs::write(&self.path, out);
    }
}

/// Resolve the scan scope to (tips, exclude) commit-oid sets. An explicit
/// `<commit>`/`<range>` positional wins; else `--all-refs`; else HEAD.
fn resolve_scope(gitdir: &Path, o: &Opts) -> Result<(Vec<String>, Vec<String>), String> {
    // --pre-push: outgoing commits only — HEAD, excluding the branch's tracking tip
    // (`refs/remotes/<remote>/<branch>`). A first push (no tracking ref) treats all
    // of HEAD's history as new. This is the diff-aware, new-leak-only scope (§30/§31).
    if o.pre_push {
        let head = crate::gitwalk::head_tip(gitdir).ok_or("HEAD is unborn — nothing to push")?;
        let exclude = crate::gitwalk::current_branch(gitdir)
            .and_then(|b| {
                crate::gitwalk::resolve_ref(gitdir, &format!("refs/remotes/{}/{b}", o.remote))
            })
            .into_iter()
            .collect();
        return Ok((vec![head], exclude));
    }
    if let Some(rev) = o.positional.first() {
        if o.positional.len() > 1 {
            return Err("`gitc scan git` takes at most one <commit>/<range>".into());
        }
        return parse_rev_range(gitdir, rev);
    }
    if o.all_refs {
        return Ok((crate::gitwalk::all_ref_tips(gitdir), Vec::new()));
    }
    // `--history` (or bare `git` reaching here) → HEAD's reachable history.
    Ok((
        crate::gitwalk::head_tip(gitdir).into_iter().collect(),
        Vec::new(),
    ))
}

/// Parse a rev spec: `A..B` (exclude A, tip B), `A...B` (both sides), or a single
/// `<rev>`. An omitted side means HEAD. Returns (tips, exclude).
fn parse_rev_range(gitdir: &Path, spec: &str) -> Result<(Vec<String>, Vec<String>), String> {
    if let Some((a, b)) = spec.split_once("...") {
        let ta = resolve_commitish(gitdir, a)?;
        let tb = resolve_commitish(gitdir, b)?;
        return Ok((vec![ta, tb], Vec::new()));
    }
    if let Some((a, b)) = spec.split_once("..") {
        let exclude = resolve_commitish(gitdir, a)?;
        let tip = resolve_commitish(gitdir, b)?;
        return Ok((vec![tip], vec![exclude]));
    }
    Ok((vec![resolve_commitish(gitdir, spec)?], Vec::new()))
}

/// Resolve a commit-ish (empty/`HEAD` → HEAD, a full 40-hex oid, or a ref name in
/// the usual namespaces) to a 40-hex commit oid. Abbreviated oids are not resolved.
fn resolve_commitish(gitdir: &Path, s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() || s == "HEAD" {
        return crate::gitwalk::head_tip(gitdir).ok_or_else(|| "HEAD is unborn".to_string());
    }
    if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(s.to_string());
    }
    for cand in [
        format!("refs/heads/{s}"),
        format!("refs/tags/{s}"),
        format!("refs/remotes/{s}"),
        s.to_string(),
    ] {
        if let Some(oid) = crate::gitwalk::resolve_ref(gitdir, &cand) {
            return Ok(oid);
        }
    }
    Err(format!(
        "cannot resolve '{s}' to a commit (use a full 40-hex oid or a ref name)"
    ))
}

/// Scan the staged content (the `.git/index` blob set) — pure Rust, no checkout.
fn scan_staged(o: &Opts, d: &Detector, gitdir: &Path) -> Result<Vec<Finding>, String> {
    let index = std::fs::read(gitdir.join("index")).map_err(|e| format!("read index: {e}"))?;
    let entries = crate::gitindex::parse(&index)?;
    let (blob_cap, total_cap) = (blob_cap(o), total_cap(o));
    let mut hits = Vec::new();
    let mut total: u64 = 0;
    for entry in entries {
        let content = match crate::gitobj::read_blob(gitdir, &entry.oid_hex, blob_cap) {
            Ok(Some(c)) => c,
            Ok(None) => continue, // packed / non-blob / oversized
            Err(e) => {
                eprintln!("gitc scan: skipped {} ({e})", entry.path);
                continue;
            }
        };
        if is_binary(&content) {
            continue;
        }
        total += content.len() as u64;
        if total > total_cap {
            eprintln!("gitc scan: staged scan truncated (exceeded {total_cap} bytes)");
            break;
        }
        // Staged content has no commit yet → fingerprint is path:rule:line.
        hits.extend(detect_frag(d, &content, &entry.path, ""));
    }
    Ok(hits)
}

/// Depth cap for the filesystem walk — defeats symlink loops when `--follow-symlinks`
/// is on (§36) and bounds pathological directory nesting.
const MAX_WALK_DEPTH: u32 = 64;

/// Recursively scan regular files under `dir`, skipping `.git`, binaries, and
/// oversized files. Bounded by the configurable blob/total budget (§33). Symlinks
/// are skipped unless `--follow-symlinks`, and even then the depth cap prevents a
/// symlink loop from running away.
fn walk_files(
    o: &Opts,
    dir: &Path,
    d: &Detector,
    rel_prefix: &str,
    hits: &mut Vec<Finding>,
    total: &mut u64,
    depth: u32,
) -> Result<(), String> {
    if depth > MAX_WALK_DEPTH {
        eprintln!(
            "gitc scan: walk truncated at depth {MAX_WALK_DEPTH} ({})",
            dir.display()
        );
        return Ok(());
    }
    let (blob_cap, total_cap) = (blob_cap(o), total_cap(o));
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return Err(format!("read dir {}: {e}", dir.display())),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            continue;
        }
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Resolve the entry kind, following a symlink only when asked; a symlink
        // that isn't followed is skipped (no zip-slip / escape).
        let (is_dir, is_file) = if ft.is_symlink() {
            if !o.follow_symlinks {
                continue;
            }
            match std::fs::metadata(&path) {
                Ok(m) => (m.is_dir(), m.is_file()),
                Err(_) => continue,
            }
        } else {
            (ft.is_dir(), ft.is_file())
        };
        if is_dir {
            walk_files(o, &path, d, &rel, hits, total, depth + 1)?;
        } else if is_file {
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() as usize > blob_cap {
                continue;
            }
            let content = match std::fs::read(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if is_binary(&content) {
                continue;
            }
            *total += content.len() as u64;
            if *total > total_cap {
                eprintln!("gitc scan: scan truncated (exceeded {total_cap} bytes)");
                return Ok(());
            }
            hits.extend(detect_frag(d, &content, &rel, ""));
        }
    }
    Ok(())
}

/// Build the detector for a scan: the default rule catalogue, plus any
/// `.betterleaksignore`/`.gitleaksignore` discovered under `base`, plus an
/// optional `--baseline`. Ignore + baseline are the SUPPRESSION mechanisms of the
/// goal's §27 model (they hide findings); `gitc:known` is acknowledgement-only and
/// deliberately NOT wired here. `source` relativises the baseline for self-scan skip.
fn make_detector(o: &Opts, base: &Path, source: &str) -> Result<Detector, String> {
    let mut d = if o.config_path.is_empty() {
        Detector::with_default_rules()
    } else {
        let cfg = config::load_file(&o.config_path)
            .map_err(|e| format!("load config {}: {e}", o.config_path))?;
        Detector::new(cfg)
    };
    // Report only findings at/above this confidence; redact must be known here so
    // the baseline comparison can skip the (masked) secret field.
    d.min_confidence = o.confidence.clone();
    d.redact = o.redact;
    if let Some(depth) = o.max_decode_depth {
        d.max_decode_depth = depth;
    }
    for name in [".betterleaksignore", ".gitleaksignore"] {
        let p = base.join(name);
        if p.is_file() {
            match d.add_ignore_file(&p.to_string_lossy()) {
                Ok(n) => eprintln!(
                    "gitc scan: loaded {n} suppression entr{} from {name}",
                    if n == 1 { "y" } else { "ies" }
                ),
                Err(e) => eprintln!("gitc scan: {name}: {e}"),
            }
        }
    }
    if !o.baseline.is_empty() {
        d.add_baseline(&o.baseline, source)
            .map_err(|e| format!("baseline: {e}"))?;
    }
    Ok(d)
}

/// Detect over one blob's `content`, feeding the `file` path and (history) `commit`
/// into the fragment so the engine fingerprints canonically, applies the catalogue
/// prefilter (skip vendored/lockfile/binary paths), and applies `.betterleaksignore`
/// + baseline suppression itself — all keyed on the RIGHT file/commit.
fn detect_frag(d: &Detector, content: &[u8], file: &str, commit: &str) -> Vec<Finding> {
    // Catalogue prefilter (Go SkipFunc): images, vendored trees, lockfiles, etc.
    if !file.is_empty() {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert(ATTR_PATH.to_string(), file.to_string());
        if d.should_skip(&attrs) {
            return Vec::new();
        }
    }
    let raw = match std::str::from_utf8(content) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(content).into_owned(),
    };
    let mut frag = Fragment {
        raw,
        ..Default::default()
    };
    if !file.is_empty() {
        frag.set_attr(ATTR_PATH, file);
    }
    if !commit.is_empty() {
        frag.set_attr(ATTR_GIT_SHA, commit);
    }
    d.detect(&frag)
}

// ── reporting ────────────────────────────────────────────────────────────────

/// Apply redaction, emit the report, and return the exit code. `d` (when present)
/// supplies the rule catalogue for SARIF rule metadata.
fn finish(o: &Opts, hits: &mut [Finding], d: Option<&Detector>) -> i32 {
    if o.redact > 0 {
        for f in hits.iter_mut() {
            f.secret = masked(f);
            f.r#match = f.secret.clone();
        }
    }
    if let Err(e) = emit(o, hits, d) {
        eprintln!("gitc scan: write report: {e}");
        return EXIT_RUNTIME;
    }
    if hits.is_empty() {
        EXIT_CLEAN
    } else {
        o.exit_code
    }
}

fn emit(o: &Opts, hits: &[Finding], d: Option<&Detector>) -> std::io::Result<()> {
    let mut out: Box<dyn Write> = if o.report_path.is_empty() {
        Box::new(std::io::stdout())
    } else {
        Box::new(std::fs::File::create(&o.report_path)?)
    };
    match o.report_format.as_str() {
        "json" => JsonReporter.write(&mut out, hits),
        "sarif" => SarifReporter {
            ordered_rules: sarif_rules(d, hits),
        }
        .write(&mut out, hits),
        "junit" => JunitReporter.write(&mut out, hits),
        "csv" => CsvReporter.write(&mut out, hits),
        _ => write_human(&mut out, hits), // default
    }
}

/// The catalogue rules that produced these findings, in catalogue order — SARIF's
/// `tool.driver.rules` metadata. Empty when the detector isn't available (e.g. a
/// no-findings early return) or in a format that doesn't carry rule metadata.
fn sarif_rules(d: Option<&Detector>, hits: &[Finding]) -> Vec<config::Rule> {
    let Some(d) = d else {
        return Vec::new();
    };
    let present: std::collections::BTreeSet<&str> =
        hits.iter().map(|f| f.rule_id.as_str()).collect();
    d.config
        .ordered_rules
        .iter()
        .filter(|id| present.contains(id.as_str()))
        .filter_map(|id| d.config.rules.get(id.as_str()).cloned())
        .collect()
}

fn write_human(w: &mut dyn Write, hits: &[Finding]) -> std::io::Result<()> {
    if hits.is_empty() {
        return writeln!(w, "gitc scan: no secrets found");
    }
    for f in hits {
        let loc = if f.commit.is_empty() {
            f.file.clone()
        } else {
            format!("{}@{}", f.file, &f.commit[..f.commit.len().min(12)])
        };
        writeln!(
            w,
            "{loc}:{} [{}] {}  {}",
            f.start_line,
            f.rule_id,
            masked(f),
            f.fingerprint
        )?;
    }
    writeln!(w, "\ngitc scan: {} finding(s)", hits.len())
}

// ── `known` (acknowledge a finding by fingerprint — does NOT suppress) ───────

/// `gitc scan known <file>:<line>` — stamps `// gitc:known [v1:<fingerprint>]`
/// onto the line, choosing the comment syntax by extension. Acknowledgement
/// only: the detector still reports the secret (goal §27).
fn known_cmd(args: &[String]) -> i32 {
    if args.is_empty() {
        return usage_err("`gitc scan known` needs <file>:<line>");
    }
    let d = Detector::with_default_rules();
    let mut ok = true;
    for raw in args {
        let arg = raw.trim_matches(',');
        if arg.is_empty() {
            continue;
        }
        let Some((path_str, line_str)) = arg.rsplit_once(':') else {
            eprintln!("gitc scan known: invalid '{arg}', expected file:line");
            ok = false;
            continue;
        };
        let Ok(target): Result<i64, _> = line_str.parse() else {
            eprintln!("gitc scan known: invalid line '{line_str}'");
            ok = false;
            continue;
        };
        let path = Path::new(path_str);
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("gitc scan known: read '{path_str}': {e}");
                ok = false;
                continue;
            }
        };
        // Feed the path so the finding's global fingerprint is `file:rule:line`.
        let finding = detect_frag(&d, content.as_bytes(), path_str, "")
            .into_iter()
            .find(|f| target >= f.start_line && target <= f.end_line.max(f.start_line));
        let Some(f) = finding else {
            eprintln!("gitc scan known: no secret on {path_str}:{target}");
            ok = false;
            continue;
        };
        let marker = format!("gitc:known [v1:{}]", global_fingerprint(&f));
        let mut lines: Vec<String> = content.split('\n').map(str::to_string).collect();
        let idx = (target - 1) as usize;
        if idx >= lines.len() {
            eprintln!("gitc scan known: line {target} out of range in {path_str}");
            ok = false;
            continue;
        }
        stamp_marker(&mut lines[idx], &marker, path_str);
        if let Err(e) = std::fs::write(path, lines.join("\n")) {
            eprintln!("gitc scan known: write {path_str}: {e}");
            ok = false;
            continue;
        }
        println!("{path_str}:{target} -> {marker}");
    }
    if ok {
        EXIT_CLEAN
    } else {
        EXIT_RUNTIME
    }
}

/// Append/replace a `gitc:known [...]` comment on `line`, comment syntax by ext.
fn stamp_marker(line: &mut String, marker: &str, filename: &str) {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    let (prefix, suffix) = match ext.as_str() {
        "py" | "sh" | "rb" | "pl" | "yml" | "yaml" | "toml" | "conf" | "ini" | "ps1" => ("#", ""),
        "html" | "xml" | "md" => ("<!--", " -->"),
        "sql" | "lua" | "hs" => ("--", ""),
        _ => ("//", ""),
    };
    let mut cr = "";
    if line.ends_with('\r') {
        line.pop();
        cr = "\r";
    }
    // Replace an existing gitc:known block if present, else append.
    if let Some(start) = line.find("gitc:known [") {
        if let Some(end) = line[start..].find(']') {
            let end = start + end + 1;
            line.replace_range(start..end, marker);
            line.push_str(cr);
            return;
        }
    }
    if !line.ends_with(' ') && !line.is_empty() {
        line.push(' ');
    }
    line.push_str(prefix);
    line.push(' ');
    line.push_str(marker);
    line.push_str(suffix);
    line.push_str(cr);
}

// ── `baseline` (create a suppression baseline) ───────────────────────────────

/// `gitc scan baseline create [scope]` — run a scan and write its JSON report to a
/// baseline file (default `.betterleaks-baseline.json`). Adopt it on later scans
/// with `--baseline <file>` to suppress everything it already records (goal §27).
/// Writing a baseline is not itself a failure, so a clean write exits 0 even when
/// the scan found secrets.
fn baseline_cmd(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("create") | Some("save") => {
            let mut o = match parse(&args[1..]) {
                Ok(o) => o,
                Err(e) => return usage_err(&e),
            };
            o.report_format = "json".to_string();
            if o.report_path.is_empty() {
                o.report_path = ".betterleaks-baseline.json".to_string();
            }
            // A bare `baseline create` defaults to a full reachable-history scan.
            if !o.staged && !o.working_tree && !o.history && !o.all_refs && o.positional.is_empty() {
                o.history = true;
            }
            let code = scan_git(&o);
            if code == EXIT_USAGE || code == EXIT_RUNTIME {
                return code;
            }
            eprintln!("gitc scan: baseline written to {}", o.report_path);
            EXIT_CLEAN
        }
        _ => usage_err(
            "`gitc scan baseline` expects: create [--history|--all-refs|--staged|<rev>] [--report-path <file>]",
        ),
    }
}

// ── `hooks` (pre-commit secret-scan hook) ────────────────────────────────────

/// Marker identifying a gitc-managed hook, so uninstall/status never touch a
/// hook the user wrote themselves.
const HOOK_MARKER: &str = "gitc scan hooks (managed)";

fn hook_script() -> String {
    format!(
        "#!/bin/sh\n# {HOOK_MARKER} — pre-commit secret scan\nexec gitc scan git --pre-commit\n"
    )
}

fn hooks_cmd(args: &[String]) -> i32 {
    let gitdir = match discover_gitdir() {
        Ok(g) => g,
        Err(e) => return usage_err(&e),
    };
    let res = match args.first().map(String::as_str) {
        Some("install") | None => hooks_install(&gitdir),
        Some("uninstall") | Some("remove") => hooks_uninstall(&gitdir),
        Some("status") => {
            let (_installed, msg) = hooks_status(&gitdir);
            println!("gitc scan hooks: {msg}");
            return EXIT_CLEAN;
        }
        _ => return usage_err("`gitc scan hooks` expects: install | uninstall | status"),
    };
    match res {
        Ok(msg) => {
            println!("gitc scan hooks: {msg}");
            EXIT_CLEAN
        }
        Err(e) => {
            eprintln!("gitc scan hooks: {e}");
            EXIT_RUNTIME
        }
    }
}

/// Install (or reinstall) the pre-commit hook. A foreign existing hook is backed
/// up, never clobbered.
fn hooks_install(gitdir: &Path) -> Result<String, String> {
    let hooks = gitdir.join("hooks");
    std::fs::create_dir_all(&hooks).map_err(|e| format!("create hooks dir: {e}"))?;
    let pre = hooks.join("pre-commit");
    let mut note = String::new();
    if pre.exists() {
        let existing = std::fs::read_to_string(&pre).unwrap_or_default();
        if !existing.contains(HOOK_MARKER) {
            let backup = hooks.join("pre-commit.gitc-backup");
            std::fs::rename(&pre, &backup).map_err(|e| format!("back up existing hook: {e}"))?;
            note = format!(" (existing hook backed up to {})", backup.display());
        }
    }
    std::fs::write(&pre, hook_script()).map_err(|e| format!("write hook: {e}"))?;
    set_executable(&pre);
    Ok(format!(
        "installed pre-commit secret-scan hook at {}{note}",
        pre.display()
    ))
}

/// Remove the gitc pre-commit hook (restoring a backed-up foreign hook if present).
/// Refuses to remove a hook gitc did not install.
fn hooks_uninstall(gitdir: &Path) -> Result<String, String> {
    let hooks = gitdir.join("hooks");
    let pre = hooks.join("pre-commit");
    if !pre.exists() {
        return Ok("no pre-commit hook installed".to_string());
    }
    let existing = std::fs::read_to_string(&pre).unwrap_or_default();
    if !existing.contains(HOOK_MARKER) {
        return Err("pre-commit hook is not managed by gitc — leaving it untouched".to_string());
    }
    std::fs::remove_file(&pre).map_err(|e| format!("remove hook: {e}"))?;
    let backup = hooks.join("pre-commit.gitc-backup");
    let mut note = String::new();
    if backup.exists() {
        std::fs::rename(&backup, &pre).map_err(|e| format!("restore backup: {e}"))?;
        note = " (restored previous hook)".to_string();
    }
    Ok(format!("removed gitc pre-commit hook{note}"))
}

/// Whether a gitc-managed pre-commit hook is installed, and a human message.
fn hooks_status(gitdir: &Path) -> (bool, String) {
    let pre = gitdir.join("hooks").join("pre-commit");
    match std::fs::read_to_string(&pre) {
        Ok(c) if c.contains(HOOK_MARKER) => (true, "gitc pre-commit hook is installed".to_string()),
        Ok(_) => (false, "a non-gitc pre-commit hook is present".to_string()),
        Err(_) => (false, "no pre-commit hook installed".to_string()),
    }
}

/// Mark a hook file executable (POSIX). A no-op on Windows, where git runs the
/// hook through its bundled `sh` by shebang regardless of the mode bits.
fn set_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

// ── `config` / `explain` ─────────────────────────────────────────────────────

/// Load the active catalogue: `path` (empty → the built-in default). Parse errors
/// are surfaced (a SARIF/CSV file passed by mistake, a bad regex, …).
fn load_config_at(path: &str) -> Result<config::Config, String> {
    if path.is_empty() {
        config::default_config().map_err(|e| e.to_string())
    } else {
        config::load_file(path).map_err(|e| format!("load {path}: {e}"))
    }
}

/// The config file a `config`/`explain` invocation targets: `--config <file>`, else
/// a bare positional file, else "" (the built-in catalogue).
fn config_target(o: &Opts) -> String {
    if !o.config_path.is_empty() {
        o.config_path.clone()
    } else {
        o.positional.first().cloned().unwrap_or_default()
    }
}

fn config_cmd(args: &[String]) -> i32 {
    let Some((mode, rest)) = args.split_first() else {
        return usage_err("`gitc scan config` expects: check | show | path [<file>]");
    };
    let o = match parse(rest) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    let target = config_target(&o);
    let label = if target.is_empty() {
        "built-in catalogue".to_string()
    } else {
        target.clone()
    };
    match mode.as_str() {
        "path" => {
            let p = if target.is_empty() {
                default_config_path()
            } else {
                PathBuf::from(&target)
            };
            println!("{}", p.display());
            EXIT_CLEAN
        }
        "check" => match load_config_at(&target) {
            Ok(c) => {
                println!(
                    "gitc scan config: OK — {} rules loaded ({label})",
                    c.rules.len()
                );
                EXIT_CLEAN
            }
            Err(e) => {
                eprintln!("gitc scan config: invalid — {e}");
                EXIT_USAGE
            }
        },
        "show" => match load_config_at(&target) {
            Ok(c) => {
                println!("gitc scan config: {} rules ({label})", c.rules.len());
                for id in &c.ordered_rules {
                    println!("  {id}");
                }
                EXIT_CLEAN
            }
            Err(e) => {
                eprintln!("gitc scan config: {e}");
                EXIT_USAGE
            }
        },
        _ => usage_err("`gitc scan config` expects: check | show | path"),
    }
}

/// `gitc scan explain <rule-id>` — print a catalogue rule's metadata (description,
/// regex, keywords, entropy floor). `--config <file>` explains a custom catalogue.
fn explain_cmd(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return usage_err(&e),
    };
    // The rule id is the first positional that is not the (bare) config file.
    let target = if o.config_path.is_empty() {
        String::new()
    } else {
        o.config_path.clone()
    };
    let rule_id = o.positional.iter().find(|p| p.as_str() != target).cloned();
    let Some(rule_id) = rule_id else {
        return usage_err("`gitc scan explain` needs a <rule-id> (see `gitc scan config show`)");
    };
    let cfg = match load_config_at(&target) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gitc scan explain: {e}");
            return EXIT_USAGE;
        }
    };
    let Some(rule) = cfg.rules.get(rule_id.as_str()) else {
        eprintln!(
            "gitc scan explain: no rule '{rule_id}' in the catalogue ({} rules) — see `gitc scan config show`",
            cfg.rules.len()
        );
        return EXIT_USAGE;
    };
    println!("rule:        {}", rule.rule_id);
    if !rule.description.is_empty() {
        println!("description: {}", rule.description);
    }
    if let Some(re) = &rule.regex {
        println!("regex:       {}", re.as_str());
    }
    if rule.entropy > 0.0 {
        println!("entropy:     >= {}", rule.entropy);
    }
    if !rule.keywords.is_empty() {
        println!("keywords:    {}", rule.keywords.join(", "));
    }
    EXIT_CLEAN
}

fn default_config_path() -> PathBuf {
    // Discovery of a local `.betterleaks.toml`/`.gitleaks.toml` is roadmap; report
    // the conventional location relative to cwd.
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".gitleaks.toml")
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Find the `.git` directory by walking up from cwd. A `.git` FILE (worktree/
/// submodule pointer) is flagged as not-yet-supported.
fn discover_gitdir() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    loop {
        let candidate = dir.join(".git");
        if candidate.is_dir() {
            return Ok(candidate);
        }
        if candidate.is_file() {
            return Err(".git is a file (worktree/submodule) — not yet supported".into());
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => return Err("not inside a git repository".into()),
        }
    }
}

/// git's own binary heuristic: a NUL byte in the first 8 KB.
fn is_binary(content: &[u8]) -> bool {
    content.iter().take(8192).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn is_binary_detects_nul() {
        assert!(is_binary(b"abc\0def"));
        assert!(!is_binary(b"plain text"));
    }

    #[test]
    fn parse_redact_optional_value() {
        assert_eq!(parse(&s(&["--redact"])).unwrap().redact, 100);
        assert_eq!(parse(&s(&["--redact", "40"])).unwrap().redact, 40);
        // a non-numeric token after --redact is NOT its value.
        let o = parse(&s(&["--redact", "dir"])).unwrap();
        assert_eq!(o.redact, 100);
        assert_eq!(o.positional, vec!["dir".to_string()]);
    }

    #[test]
    fn parse_selectors_and_exit_code() {
        let o = parse(&s(&["--staged", "--exit-code", "7"])).unwrap();
        assert!(o.staged);
        assert_eq!(o.exit_code, 7);
        assert!(parse(&s(&["--nope"])).is_err());
    }

    #[test]
    fn parse_pre_push_and_remote() {
        let o = parse(&s(&["--pre-push", "--remote", "upstream"])).unwrap();
        assert!(o.pre_push);
        assert_eq!(o.remote, "upstream");
        assert_eq!(Opts::default().remote, "origin"); // default tracking remote
    }

    #[test]
    fn parse_history_selectors() {
        let o = parse(&s(&["--history", "--all-refs"])).unwrap();
        assert!(o.history);
        assert!(o.all_refs);
        let o = parse(&s(&["--trace-finding", "v1:deadbeef"])).unwrap();
        assert_eq!(o.trace_finding.as_deref(), Some("v1:deadbeef"));
        // --trace-finding requires a value.
        assert!(parse(&s(&["--trace-finding"])).is_err());
        // a bare rev is captured as a positional.
        let o = parse(&s(&["HEAD~3..HEAD"])).unwrap();
        assert_eq!(o.positional, vec!["HEAD~3..HEAD".to_string()]);
    }

    /// A realistic (non-example, so non-allowlisted) AWS key, assembled at runtime
    /// so the literal never appears contiguously in this file — the detector sees
    /// the joined string, GitHub push-protection sees only two harmless halves.
    fn aws_key() -> String {
        format!("AKIA{}", "Z3XQ7RTPKMWV4C2D")
    }

    fn unique_tmp() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("gitc_scan_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detect_frag_sets_canonical_fingerprint_and_fields() {
        let d = Detector::with_default_rules();
        let content = format!("aws_key = \"{}\"\n", aws_key());
        let hits = detect_frag(&d, content.as_bytes(), "src/app.rs", "abc123def456abc123");
        assert!(!hits.is_empty(), "assembled AWS key should be detected");
        let f = &hits[0];
        assert_eq!(f.file, "src/app.rs", "path fed via ATTR_PATH");
        assert_eq!(
            f.commit, "abc123def456abc123",
            "commit fed via ATTR_GIT_SHA"
        );
        // Canonical `commit:file:rule:line`, NOT a `v1:` id.
        assert!(
            f.fingerprint.starts_with("abc123def456abc123:src/app.rs:"),
            "got {}",
            f.fingerprint
        );
        assert!(!f.fingerprint.starts_with("v1:"));
    }

    #[test]
    fn betterleaksignore_suppresses_by_fingerprint() {
        let dir = unique_tmp();
        let content = format!("aws_key = \"{}\"\n", aws_key());
        // Learn the finding's global fingerprint (file:rule:line) with no ignore.
        let f = detect_frag(
            &Detector::with_default_rules(),
            content.as_bytes(),
            "src/app.rs",
            "",
        )
        .remove(0);
        let global = format!("{}:{}:{}", f.file, f.rule_id, f.start_line);
        std::fs::write(dir.join(".betterleaksignore"), format!("{global}\n")).unwrap();
        // make_detector loads it → the same finding is suppressed.
        let o = Opts::default();
        let d = make_detector(&o, &dir, "src/app.rs").unwrap();
        let hits = detect_frag(&d, content.as_bytes(), "src/app.rs", "");
        assert!(hits.is_empty(), "ignored fingerprint must be suppressed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_suppresses_recorded_findings() {
        let dir = unique_tmp();
        let content = format!("aws_key = \"{}\"\n", aws_key());
        let hits0 = detect_frag(
            &Detector::with_default_rules(),
            content.as_bytes(),
            "src/app.rs",
            "",
        );
        assert!(!hits0.is_empty());
        // A baseline is a prior JSON report.
        let baseline = dir.join("baseline.json");
        let mut buf = Vec::new();
        JsonReporter.write(&mut buf, &hits0).unwrap();
        std::fs::write(&baseline, &buf).unwrap();
        // Adopt it → the same finding is now suppressed.
        let o = Opts {
            baseline: baseline.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let d = make_detector(&o, &dir, "src/app.rs").unwrap();
        let hits = detect_frag(&d, content.as_bytes(), "src/app.rs", "");
        assert!(hits.is_empty(), "baselined finding must be suppressed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_resource_hardening_flags() {
        let o = parse(&s(&[
            "--max-target-megabytes",
            "10",
            "--max-total-megabytes",
            "256",
            "--max-decode-depth",
            "4",
            "--follow-symlinks",
        ]))
        .unwrap();
        assert_eq!(o.max_blob_mb, Some(10));
        assert_eq!(o.max_total_mb, Some(256));
        assert_eq!(o.max_decode_depth, Some(4));
        assert!(o.follow_symlinks);
        // caps convert MB → bytes; defaults fall back to the built-in budgets.
        assert_eq!(blob_cap(&o), 10 * 1024 * 1024);
        assert_eq!(total_cap(&o), 256 * 1024 * 1024);
        assert_eq!(blob_cap(&Opts::default()), MAX_BLOB_BYTES);
        assert_eq!(total_cap(&Opts::default()), MAX_TOTAL_BYTES);
        // non-integer values are usage errors.
        assert!(parse(&s(&["--max-target-megabytes", "big"])).is_err());
    }

    #[test]
    fn parse_confidence_and_config_flags() {
        let o = parse(&s(&["--confidence", "high", "--config", "rules.toml"])).unwrap();
        assert_eq!(o.confidence, "high");
        assert_eq!(o.config_path, "rules.toml");
    }

    #[test]
    fn config_check_show_path_load_builtin() {
        assert_eq!(config_cmd(&s(&["check"])), EXIT_CLEAN);
        assert_eq!(config_cmd(&s(&["show"])), EXIT_CLEAN);
        assert_eq!(config_cmd(&s(&["path"])), EXIT_CLEAN);
        // a missing config file is a usage error, not a panic
        assert_eq!(
            config_cmd(&s(&["check", "no-such-config-xyz.toml"])),
            EXIT_USAGE
        );
    }

    #[test]
    fn explain_known_and_unknown_rule() {
        let cfg = config::default_config().unwrap();
        let id = cfg.ordered_rules.first().unwrap().clone();
        assert_eq!(explain_cmd(&s(&[id.as_str()])), EXIT_CLEAN);
        assert_eq!(explain_cmd(&s(&["no-such-rule-xyz"])), EXIT_USAGE);
        assert_eq!(explain_cmd(&s(&[])), EXIT_USAGE); // missing rule id
    }

    #[test]
    fn sarif_rules_lists_only_present_rules() {
        let d = Detector::with_default_rules();
        let content = format!("aws_key = \"{}\"\n", aws_key());
        let hits = detect_frag(&d, content.as_bytes(), "src/app.rs", "");
        assert!(!hits.is_empty());
        let rules = sarif_rules(Some(&d), &hits);
        assert!(!rules.is_empty(), "must include the rule that fired");
        let present: std::collections::BTreeSet<&str> =
            hits.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.iter().all(|r| present.contains(r.rule_id.as_str())));
        assert!(
            sarif_rules(None, &hits).is_empty(),
            "no detector → no rules"
        );
    }

    #[test]
    fn parse_jobs_flag() {
        assert_eq!(parse(&s(&["--jobs", "8"])).unwrap().jobs, 8);
        assert_eq!(parse(&s(&["-j", "4"])).unwrap().jobs, 4);
        assert_eq!(parse(&s(&["--jobs", "0"])).unwrap().jobs, 1); // clamped to >=1
        assert!(parse(&s(&["--jobs", "x"])).is_err());
        assert_eq!(Opts::default().jobs, 1);
    }

    #[test]
    fn parallel_scan_equals_sequential_and_is_ordered() {
        let git = match std::env::var("GITC_TEST_GIT")
            .ok()
            .or_else(|| Some("git".to_string()))
            .filter(|g| {
                std::process::Command::new(g)
                    .arg("--version")
                    .output()
                    .is_ok_and(|o| o.status.success())
            }) {
            Some(g) => g,
            None => {
                eprintln!("skip parallel scan test: no git");
                return;
            }
        };
        let dir = unique_tmp();
        let run = |args: &[&str]| {
            std::process::Command::new(&git)
                .args(args)
                .current_dir(&dir)
                .env("GIT_AUTHOR_NAME", "T")
                .env("GIT_AUTHOR_EMAIL", "t@e.com")
                .env("GIT_COMMITTER_NAME", "T")
                .env("GIT_COMMITTER_EMAIL", "t@e.com")
                .output()
                .unwrap();
        };
        run(&["init", "-q", "-b", "main"]);
        // Distinct blobs (unique comment) each carrying a detectable key.
        for i in 0..8 {
            std::fs::write(
                dir.join(format!("f{i}.txt")),
                format!("// file {i}\naws_key = \"{}\"\n", aws_key()),
            )
            .unwrap();
        }
        run(&["add", "-A"]);
        run(&["-c", "commit.gpgsign=false", "commit", "-q", "-m", "c"]);

        let gitdir = dir.join(".git");
        let head = crate::gitwalk::head_tip(&gitdir).unwrap();
        let (intros, _) = crate::gitwalk::reachable_blob_intros(&gitdir, &[head], &[]);
        let d = Detector::with_default_rules();
        let seq = scan_intros(&Opts::default(), &d, &gitdir, &intros, None).unwrap();
        let par = scan_intros(
            &Opts {
                jobs: 4,
                ..Default::default()
            },
            &d,
            &gitdir,
            &intros,
            None,
        )
        .unwrap();
        assert!(!seq.is_empty(), "should find the planted keys");
        let fps = |v: &[Finding]| v.iter().map(|f| f.fingerprint.clone()).collect::<Vec<_>>();
        assert_eq!(
            fps(&seq),
            fps(&par),
            "parallel must match sequential, in order"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_bytes_never_panics_on_hostile_input() {
        // §50/§33: the detector must survive random + pathological input without a
        // panic (huge, all-NUL, all-'=', deeply repetitive).
        let d = Detector::with_default_rules();
        let mut x = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..1500 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x as usize) % 4096;
            let buf: Vec<u8> = (0..len).map(|i| ((x >> (i % 56)) & 0xff) as u8).collect();
            let _ = d.detect_bytes(&buf);
        }
        let _ = d.detect_bytes(&vec![b'='; 200_000]); // decoder-amplification bait
        let _ = d.detect_bytes(&vec![0u8; 50_000]); // binary-ish
        let _ = d.detect_bytes(&"A".repeat(100_000).into_bytes());
        let _ = d.detect_bytes(&[]); // empty
    }

    #[test]
    fn scan_cache_roundtrip_and_version_invalidation() {
        let dir = unique_tmp();
        let gitdir = dir.join(".git");
        std::fs::create_dir_all(&gitdir).unwrap();
        let d = Detector::with_default_rules();

        // Populate + persist a cache: one blob with a finding, one clean blob.
        let mut cache = ScanCache::load(&gitdir, &d);
        let content = format!("aws_key = \"{}\"\n", aws_key());
        let found = detect_frag(&d, content.as_bytes(), "src/app.rs", "c0ffee");
        assert!(!found.is_empty());
        cache.put("1111111111111111111111111111111111111111", &found);
        cache.put("2222222222222222222222222222222222222222", &[]); // clean blob
        cache.save();

        // Reload: hits reconstruct (value elided), clean blob is remembered as empty.
        let reloaded = ScanCache::load(&gitdir, &d);
        let hit = reloaded
            .get("1111111111111111111111111111111111111111")
            .expect("cached finding");
        assert_eq!(hit.len(), found.len());
        let f = hit[0].to_finding("src/app.rs", "c0ffee");
        assert_eq!(f.rule_id, found[0].rule_id);
        assert!(f.fingerprint.starts_with("c0ffee:src/app.rs:"));
        assert!(
            !f.secret.contains(&aws_key()),
            "cache must not store the secret"
        );
        assert_eq!(
            reloaded
                .get("2222222222222222222222222222222222222222")
                .map(|v| v.len()),
            Some(0)
        );

        // A version-tag change (e.g. different rule count) discards the whole cache:
        // write under a bumped tag, then load under the real tag → empty.
        let mut bumped = ScanCache {
            version: "gitc-scan-cache/1 rules=999999".to_string(),
            entries: std::collections::HashMap::new(),
            path: gitdir.join("gitc-scan-cache"),
            dirty: false,
        };
        bumped.put("3333333333333333333333333333333333333333", &found);
        bumped.save();
        let after = ScanCache::load(&gitdir, &d);
        assert!(
            after
                .get("3333333333333333333333333333333333333333")
                .is_none(),
            "mismatched version tag must invalidate the cache"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_install_status_uninstall_roundtrip() {
        let dir = unique_tmp();
        let gitdir = dir.join(".git");
        std::fs::create_dir_all(gitdir.join("hooks")).unwrap();
        assert!(!hooks_status(&gitdir).0, "not installed initially");
        assert!(hooks_install(&gitdir).is_ok());
        let pre = gitdir.join("hooks").join("pre-commit");
        assert!(pre.exists());
        assert!(std::fs::read_to_string(&pre).unwrap().contains(HOOK_MARKER));
        assert!(hooks_status(&gitdir).0, "installed");
        assert!(hooks_install(&gitdir).is_ok(), "reinstall is idempotent");
        assert!(hooks_uninstall(&gitdir).is_ok());
        assert!(!pre.exists());
        assert!(!hooks_status(&gitdir).0, "uninstalled");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hooks_backs_up_and_restores_foreign_hook() {
        let dir = unique_tmp();
        let gitdir = dir.join(".git");
        let hooks = gitdir.join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let pre = hooks.join("pre-commit");
        std::fs::write(&pre, "#!/bin/sh\necho custom-hook\n").unwrap();
        hooks_install(&gitdir).unwrap();
        assert!(std::fs::read_to_string(&pre).unwrap().contains(HOOK_MARKER));
        assert!(
            hooks.join("pre-commit.gitc-backup").exists(),
            "foreign hook backed up"
        );
        hooks_uninstall(&gitdir).unwrap();
        assert!(
            std::fs::read_to_string(&pre)
                .unwrap()
                .contains("echo custom-hook"),
            "foreign hook restored on uninstall"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_matches_full_bare_and_prefix() {
        let f = Finding {
            fingerprint: "v1:deadbeef".to_string(),
            ..Default::default()
        };
        assert!(fingerprint_matches(&f, "v1:deadbeef")); // full
        assert!(fingerprint_matches(&f, "deadbeef")); // bare hash
        assert!(fingerprint_matches(&f, "dead")); // abbreviated prefix
        assert!(fingerprint_matches(&f, "v1:dead")); // prefixed abbreviation
        assert!(!fingerprint_matches(&f, "cafe")); // unrelated
        assert!(!fingerprint_matches(&f, "")); // empty never matches
    }

    #[test]
    fn stamp_marker_appends_and_replaces() {
        // Rust file → C-style comment appended.
        let mut line = "let k = \"AKIA...\";".to_string();
        stamp_marker(&mut line, "gitc:known [v1:abc]", "creds.rs");
        assert_eq!(line, "let k = \"AKIA...\"; // gitc:known [v1:abc]");
        // Re-stamping replaces the existing marker in place (idempotent id swap).
        stamp_marker(&mut line, "gitc:known [v1:xyz]", "creds.rs");
        assert_eq!(line, "let k = \"AKIA...\"; // gitc:known [v1:xyz]");
        // YAML → '#' comment.
        let mut y = "token: abc".to_string();
        stamp_marker(&mut y, "gitc:known [v1:q]", "conf.yaml");
        assert_eq!(y, "token: abc # gitc:known [v1:q]");
    }

    #[test]
    fn stamp_marker_preserves_crlf() {
        let mut line = "x=1\r".to_string();
        stamp_marker(&mut line, "gitc:known [v1:a]", "a.rs");
        assert!(line.ends_with('\r'));
        assert!(line.contains("// gitc:known [v1:a]"));
    }

    // ── shared test helpers for the new coverage-raising tests ───────────────

    /// The betterleaks detector + a non-empty `Vec<Finding>` from a planted key,
    /// carrying a file + commit so every report format has something to emit.
    fn planted() -> (Detector, Vec<Finding>) {
        let d = Detector::with_default_rules();
        let content = format!("aws_key = \"{}\"\n", aws_key());
        let hits = detect_frag(&d, content.as_bytes(), "src/app.rs", "abc123def4567890abcd");
        assert!(!hits.is_empty(), "planted key must be detected");
        (d, hits)
    }

    /// Emit `hits` in `format` to a temp file (exercising `emit`'s file branch)
    /// and return the written text.
    fn emit_to_file(format: &str, hits: &[Finding], d: Option<&Detector>) -> String {
        let dir = unique_tmp();
        let path = dir.join("report.out");
        let o = Opts {
            report_format: format.to_string(),
            report_path: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        emit(&o, hits, d).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        text
    }

    /// The scoop/system git, or `None` when no usable git is present (test skips).
    fn maybe_git() -> Option<String> {
        std::env::var("GITC_TEST_GIT")
            .ok()
            .or_else(|| Some("git".to_string()))
            .filter(|g| {
                std::process::Command::new(g)
                    .arg("--version")
                    .output()
                    .is_ok_and(|o| o.status.success())
            })
    }

    /// Build a real temp repo on `main` with a committed file carrying an AWS key,
    /// returning `(workdir, gitdir)`. `None` when git is unavailable.
    fn repo_with_committed_key() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        let git = maybe_git()?;
        let dir = unique_tmp();
        let run = |args: &[&str]| {
            std::process::Command::new(&git)
                .args(args)
                .current_dir(&dir)
                .env("GIT_AUTHOR_NAME", "T")
                .env("GIT_AUTHOR_EMAIL", "t@e.com")
                .env("GIT_COMMITTER_NAME", "T")
                .env("GIT_COMMITTER_EMAIL", "t@e.com")
                .output()
                .unwrap();
        };
        run(&["init", "-q", "-b", "main"]);
        std::fs::write(
            dir.join("creds.txt"),
            format!("aws_key = \"{}\"\n", aws_key()),
        )
        .unwrap();
        run(&["add", "-A"]);
        run(&["-c", "commit.gpgsign=false", "commit", "-q", "-m", "c"]);
        let gitdir = dir.join(".git");
        Some((dir, gitdir))
    }

    // ── report emitters (json / sarif / junit / csv / human) ─────────────────

    #[test]
    fn emit_json_is_wellformed_and_has_fields() {
        let (d, hits) = planted();
        let text = emit_to_file("json", &hits, Some(&d));
        // A single-space-indented JSON array (Go `SetIndent("", " ")`).
        assert!(text.trim_start().starts_with('['), "json array: {text}");
        assert!(text.trim_end().ends_with(']'));
        assert!(text.contains("\"RuleID\""));
        assert!(text.contains("\"Fingerprint\""));
        assert!(text.contains(&hits[0].rule_id));
    }

    #[test]
    fn emit_sarif_is_wellformed_and_has_driver() {
        let (d, hits) = planted();
        let text = emit_to_file("sarif", &hits, Some(&d));
        assert!(text.contains("\"version\": \"2.1.0\""), "sarif version: {text}");
        assert!(text.contains("$schema"));
        assert!(text.contains("\"runs\""));
        assert!(text.contains("\"ruleId\""));
        // The driver's rules metadata carries the rule that fired.
        assert!(text.contains(&hits[0].rule_id));
    }

    #[test]
    fn emit_junit_is_xml_testsuites() {
        let (d, hits) = planted();
        let text = emit_to_file("junit", &hits, Some(&d));
        assert!(text.contains("<testsuites"));
        assert!(text.contains("<testsuite"));
        assert!(text.contains("<testcase"));
        assert!(text.contains("<failure"));
    }

    #[test]
    fn emit_csv_has_header_and_row() {
        let (d, hits) = planted();
        let text = emit_to_file("csv", &hits, Some(&d));
        let mut lines = text.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("RuleID,Commit,File"));
        assert!(header.contains("Fingerprint"));
        let row = lines.next().expect("one data row");
        assert!(row.contains(&hits[0].rule_id));
    }

    #[test]
    fn emit_default_and_unknown_format_use_human() {
        let (d, hits) = planted();
        // An unrecognized format falls back to the human writer (the `_` arm).
        let text = emit_to_file("no-such-format", &hits, Some(&d));
        assert!(text.contains("finding(s)"));
        assert!(text.contains(&hits[0].rule_id));
    }

    #[test]
    fn write_human_empty_and_populated() {
        // Empty → the "no secrets found" line.
        let mut buf = Vec::new();
        write_human(&mut buf, &[]).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "gitc scan: no secrets found\n");
        // Populated with a commit → `file@<short-sha>` location prefix.
        let with_commit = Finding {
            rule_id: "r".to_string(),
            file: "a.rs".to_string(),
            commit: "0123456789abcdef0123".to_string(),
            start_line: 3,
            fingerprint: "fp".to_string(),
            secret: "s".to_string(),
            ..Default::default()
        };
        let no_commit = Finding {
            rule_id: "r2".to_string(),
            file: "b.rs".to_string(),
            start_line: 9,
            fingerprint: "fp2".to_string(),
            secret: "s2".to_string(),
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_human(&mut buf, &[with_commit, no_commit]).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("a.rs@0123456789ab:3"), "short-sha location: {text}");
        assert!(text.contains("b.rs:9"), "no-commit location: {text}");
        assert!(text.contains("gitc scan: 2 finding(s)"));
    }

    // ── finish() : redaction + exit codes ────────────────────────────────────

    #[test]
    fn finish_redacts_and_returns_exit_code() {
        let (d, mut hits) = planted();
        let dir = unique_tmp();
        let path = dir.join("r.json");
        let o = Opts {
            report_format: "json".to_string(),
            report_path: path.to_string_lossy().into_owned(),
            redact: 100,
            exit_code: 7,
            ..Default::default()
        };
        let code = finish(&o, &mut hits, Some(&d));
        assert_eq!(code, 7, "findings → the configured exit code");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(&aws_key()),
            "redaction must mask the raw secret in the report"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finish_clean_returns_exit_clean() {
        let dir = unique_tmp();
        let path = dir.join("r.json");
        let o = Opts {
            report_format: "json".to_string(),
            report_path: path.to_string_lossy().into_owned(),
            exit_code: 9,
            ..Default::default()
        };
        assert_eq!(finish(&o, &mut Vec::new(), None), EXIT_CLEAN);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── run() dispatch + usage/help/error branches ───────────────────────────

    #[test]
    fn run_help_and_no_args() {
        assert_eq!(run(&[]), EXIT_USAGE); // no subcommand
        assert_eq!(run(&s(&["help"])), EXIT_CLEAN);
        assert_eq!(run(&s(&["-h"])), EXIT_CLEAN);
        assert_eq!(run(&s(&["--help"])), EXIT_CLEAN);
        assert_eq!(run(&s(&["totally-unknown-sub"])), EXIT_USAGE);
    }

    #[test]
    fn run_parse_error_paths_per_mode() {
        // A bad flag makes `parse` fail → usage error, before any scanning.
        assert_eq!(run(&s(&["git", "--nope"])), EXIT_USAGE);
        assert_eq!(run(&s(&["dir", "--nope"])), EXIT_USAGE);
        assert_eq!(run(&s(&["stdin", "--nope"])), EXIT_USAGE);
    }

    #[test]
    fn usage_and_usage_err_are_nonempty() {
        assert!(usage().contains("gitc scan"));
        assert_eq!(usage_err("boom"), EXIT_USAGE);
    }

    // ── scan_dir + walk_files (dir mode end-to-end) ──────────────────────────

    #[test]
    fn scan_dir_missing_path_is_usage_error() {
        assert_eq!(scan_dir(&Opts::default()), EXIT_USAGE);
    }

    #[test]
    fn scan_dir_bad_config_is_usage_error() {
        let dir = unique_tmp();
        let o = Opts {
            positional: vec![dir.to_string_lossy().into_owned()],
            config_path: "no-such-config-file-xyz.toml".to_string(),
            ..Default::default()
        };
        assert_eq!(scan_dir(&o), EXIT_USAGE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_dir_finds_planted_key_and_skips_git_binary_subdirs() {
        let root = unique_tmp();
        // A nested dir with a planted key; a .git dir (skipped); a binary file (skipped).
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(
            root.join("sub").join("creds.txt"),
            format!("aws_key = \"{}\"\n", aws_key()),
        )
        .unwrap();
        std::fs::write(root.join(".git").join("planted.txt"), format!("aws_key = \"{}\"\n", aws_key())).unwrap();
        std::fs::write(root.join("blob.bin"), b"\x00\x01secret\x00").unwrap();
        let report = root.join("out.json");
        let o = Opts {
            positional: vec![root.to_string_lossy().into_owned()],
            report_format: "json".to_string(),
            report_path: report.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert_eq!(scan_dir(&o), EXIT_FINDINGS);
        let text = std::fs::read_to_string(&report).unwrap();
        assert!(text.contains("sub/creds.txt"), "reports the nested file: {text}");
        assert!(
            !text.contains(".git/planted.txt"),
            ".git must be skipped by walk_files"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_dir_clean_tree_is_exit_clean() {
        let root = unique_tmp();
        std::fs::write(root.join("readme.txt"), "nothing to see here\n").unwrap();
        let report = root.join("out.json");
        let o = Opts {
            positional: vec![root.to_string_lossy().into_owned()],
            report_format: "json".to_string(),
            report_path: report.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert_eq!(scan_dir(&o), EXIT_CLEAN);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── make_detector error path ─────────────────────────────────────────────

    #[test]
    fn make_detector_bad_config_errors() {
        let o = Opts {
            config_path: "definitely-not-a-real-config.toml".to_string(),
            ..Default::default()
        };
        assert!(make_detector(&o, Path::new("."), ".").is_err());
    }

    // ── config_target / load_config_at with a real custom file ───────────────

    fn write_min_config() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = unique_tmp();
        let path = dir.join("rules.toml");
        std::fs::write(
            &path,
            "title = \"test\"\n\n[[rules]]\nid = \"my-test-rule\"\ndescription = \"a test rule\"\nregex = '''secret-[A-Z0-9]{10}'''\nkeywords = [\"secret-\"]\n",
        )
        .unwrap();
        (dir, path)
    }

    #[test]
    fn config_check_show_custom_file() {
        let (dir, path) = write_min_config();
        let p = path.to_string_lossy().into_owned();
        assert_eq!(config_cmd(&s(&["check", p.as_str()])), EXIT_CLEAN);
        assert_eq!(config_cmd(&s(&["show", p.as_str()])), EXIT_CLEAN);
        assert_eq!(config_cmd(&s(&["path", p.as_str()])), EXIT_CLEAN);
        // --config wins over a bare positional for the target.
        assert_eq!(config_cmd(&s(&["check", "--config", p.as_str()])), EXIT_CLEAN);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_usage_and_error_branches() {
        assert_eq!(config_cmd(&s(&[])), EXIT_USAGE); // no mode
        assert_eq!(config_cmd(&s(&["show", "--nope"])), EXIT_USAGE); // parse error
        assert_eq!(config_cmd(&s(&["bogus-mode"])), EXIT_USAGE); // unknown mode
        assert_eq!(config_cmd(&s(&["show", "no-such-file-xyz.toml"])), EXIT_USAGE);
    }

    #[test]
    fn config_target_prefers_config_flag() {
        let o = Opts {
            config_path: "flag.toml".to_string(),
            positional: vec!["pos.toml".to_string()],
            ..Default::default()
        };
        assert_eq!(config_target(&o), "flag.toml");
        let o2 = Opts {
            positional: vec!["pos.toml".to_string()],
            ..Default::default()
        };
        assert_eq!(config_target(&o2), "pos.toml");
        assert_eq!(config_target(&Opts::default()), "");
        // The conventional built-in path is under cwd.
        assert!(default_config_path().ends_with(".gitleaks.toml"));
    }

    #[test]
    fn explain_with_custom_config_file() {
        let (dir, path) = write_min_config();
        let p = path.to_string_lossy().into_owned();
        // `explain <rule> --config <file>` reads the custom catalogue; the config
        // file positional must not be mistaken for the rule id.
        assert_eq!(
            explain_cmd(&s(&["my-test-rule", "--config", p.as_str()])),
            EXIT_CLEAN
        );
        assert_eq!(
            explain_cmd(&s(&["no-such-rule", "--config", p.as_str()])),
            EXIT_USAGE
        );
        // A bad config surfaces as a usage error.
        assert_eq!(
            explain_cmd(&s(&["any-rule", "--config", "no-such-file.toml"])),
            EXIT_USAGE
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── known_cmd error + success paths ──────────────────────────────────────

    #[test]
    fn known_cmd_error_paths() {
        assert_eq!(known_cmd(&[]), EXIT_USAGE); // no args
        assert_eq!(known_cmd(&s(&["no-colon-here"])), EXIT_RUNTIME); // no file:line
        assert_eq!(known_cmd(&s(&["file.rs:notaline"])), EXIT_RUNTIME); // bad line
        assert_eq!(known_cmd(&s(&["no-such-file-xyz.rs:1"])), EXIT_RUNTIME); // unreadable
        // A clean file has no secret on the requested line.
        let dir = unique_tmp();
        let clean = dir.join("clean.rs");
        std::fs::write(&clean, "let x = 1;\n").unwrap();
        assert_eq!(
            known_cmd(&s(&[format!("{}:1", clean.to_string_lossy()).as_str()])),
            EXIT_RUNTIME
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_cmd_stamps_a_real_finding() {
        // `gitc scan known <file>:<line>` acknowledges a secret the scanner already
        // reported. The `<line>` a user passes is exactly what `gitc scan` printed —
        // and the detection engine reports line numbers 0-based (a secret on the
        // third file line is reported as line 2). So the test derives `target` from
        // the finding's own `start_line`, mirroring the copy-from-report workflow,
        // rather than hard-coding a 1-based line. The secret is placed off the first
        // line so `start_line > 0` (a first-line finding reports line 0, which the
        // `<file>:<line>` CLI form cannot express).
        let dir = unique_tmp();
        let file = dir.join("creds.rs");
        let content = format!("line one\nline two\naws_key = \"{}\"\nline four\n", aws_key());
        std::fs::write(&file, &content).unwrap();
        let path_str = file.to_string_lossy().into_owned();

        // Sanity + the reported line: `known` acknowledges what detection surfaces.
        let f = detect_frag(&Detector::with_default_rules(), content.as_bytes(), &path_str, "")
            .into_iter()
            .next()
            .expect("input must be detectable for the known test to be meaningful");
        let target = f.start_line;
        assert!(target > 0, "secret should not be on the first (line-0) line");

        let arg = format!("{path_str}:{target}");
        assert_eq!(known_cmd(&s(&[arg.as_str()])), EXIT_CLEAN);
        let after = std::fs::read_to_string(&file).unwrap();
        assert!(
            after.contains("gitc:known [v1:"),
            "an acknowledged finding must be stamped with a marker: {after}"
        );
        // Re-acknowledging the same line is idempotent (still exactly one marker).
        assert_eq!(known_cmd(&s(&[arg.as_str()])), EXIT_CLEAN);
        let after2 = std::fs::read_to_string(&file).unwrap();
        assert_eq!(
            after2.matches("gitc:known [").count(),
            1,
            "re-acknowledging must not duplicate the marker"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── baseline_cmd usage/error dispatch (no repo scan) ─────────────────────

    #[test]
    fn baseline_cmd_usage_and_parse_error() {
        assert_eq!(baseline_cmd(&s(&["bogus"])), EXIT_USAGE); // unknown subcommand
        assert_eq!(baseline_cmd(&[]), EXIT_USAGE); // no subcommand
        assert_eq!(baseline_cmd(&s(&["create", "--nope"])), EXIT_USAGE); // parse error
    }

    // ── hooks_cmd dispatch error (does not touch any hook) ────────────────────

    #[test]
    fn hooks_cmd_unknown_subcommand_is_usage_error() {
        // `bogus` never reaches install/uninstall/status, so no hook is written.
        assert_eq!(hooks_cmd(&s(&["bogus-hook-arg"])), EXIT_USAGE);
    }

    // ── CachedFinding::to_finding empty-commit fingerprint ───────────────────

    #[test]
    fn cached_finding_empty_commit_fingerprint() {
        let cf = CachedFinding {
            rule_id: "r".to_string(),
            start_line: 4,
            end_line: 4,
        };
        let f = cf.to_finding("a.rs", "");
        assert_eq!(f.fingerprint, "a.rs:r:4", "no commit → file:rule:line");
        let f2 = cf.to_finding("a.rs", "deadbeef");
        assert_eq!(f2.fingerprint, "deadbeef:a.rs:r:4");
        assert!(f.secret.contains("cached"));
    }

    // ── git-repo backed: scope resolution + object scans ─────────────────────

    #[test]
    fn resolve_commitish_and_rev_range() {
        let Some((dir, gitdir)) = repo_with_committed_key() else {
            eprintln!("skip resolve_commitish: no git");
            return;
        };
        let head = crate::gitwalk::head_tip(&gitdir).unwrap();
        // HEAD, empty, a full 40-hex oid, and a branch name all resolve.
        assert_eq!(resolve_commitish(&gitdir, "HEAD").unwrap(), head);
        assert_eq!(resolve_commitish(&gitdir, "").unwrap(), head);
        assert_eq!(resolve_commitish(&gitdir, &head).unwrap(), head);
        assert_eq!(resolve_commitish(&gitdir, "main").unwrap(), head);
        // An unresolvable ref is an error.
        assert!(resolve_commitish(&gitdir, "no-such-ref").is_err());
        // Rev ranges: `A..B` (exclude+tip), `A...B` (both tips), single rev.
        let (tips, excl) = parse_rev_range(&gitdir, "HEAD..HEAD").unwrap();
        assert_eq!(tips, vec![head.clone()]);
        assert_eq!(excl, vec![head.clone()]);
        let (tips3, excl3) = parse_rev_range(&gitdir, "HEAD...HEAD").unwrap();
        assert_eq!(tips3, vec![head.clone(), head.clone()]);
        assert!(excl3.is_empty());
        let (tips1, excl1) = parse_rev_range(&gitdir, "HEAD").unwrap();
        assert_eq!(tips1, vec![head.clone()]);
        assert!(excl1.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_scope_variants() {
        let Some((dir, gitdir)) = repo_with_committed_key() else {
            eprintln!("skip resolve_scope: no git");
            return;
        };
        let head = crate::gitwalk::head_tip(&gitdir).unwrap();
        // Default (history/HEAD).
        let (tips, excl) = resolve_scope(&gitdir, &Opts::default()).unwrap();
        assert_eq!(tips, vec![head.clone()]);
        assert!(excl.is_empty());
        // --all-refs.
        let (tips_ar, _) = resolve_scope(
            &gitdir,
            &Opts {
                all_refs: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(tips_ar.contains(&head));
        // --pre-push with no tracking ref → all of HEAD is "outgoing", no exclude.
        let (tips_pp, excl_pp) = resolve_scope(
            &gitdir,
            &Opts {
                pre_push: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(tips_pp, vec![head.clone()]);
        assert!(excl_pp.is_empty());
        // An explicit single rev positional.
        let (tips_rev, _) = resolve_scope(
            &gitdir,
            &Opts {
                positional: vec!["HEAD".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(tips_rev, vec![head.clone()]);
        // More than one positional rev is a usage error.
        assert!(resolve_scope(
            &gitdir,
            &Opts {
                positional: vec!["a".to_string(), "b".to_string()],
                ..Default::default()
            },
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_staged_reads_index_blobs() {
        let Some((dir, gitdir)) = repo_with_committed_key() else {
            eprintln!("skip scan_staged: no git");
            return;
        };
        let d = Detector::with_default_rules();
        let hits = scan_staged(&Opts::default(), &d, &gitdir).unwrap();
        assert!(!hits.is_empty(), "the staged key must be found");
        // Staged content has no commit → fingerprint is path:rule:line.
        assert!(hits.iter().all(|f| f.commit.is_empty()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_history_end_to_end_reports_findings() {
        let Some((dir, gitdir)) = repo_with_committed_key() else {
            eprintln!("skip scan_history: no git");
            return;
        };
        let report = dir.join("hist.json");
        let o = Opts {
            history: true,
            report_format: "json".to_string(),
            report_path: report.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert_eq!(scan_history(&gitdir, &o), EXIT_FINDINGS);
        let text = std::fs::read_to_string(&report).unwrap();
        assert!(text.contains("creds.txt"), "history report names the file");
        // With --cache the second run reuses the per-OID cache (still reports).
        let o2 = Opts {
            cache: true,
            ..o
        };
        assert_eq!(scan_history(&gitdir, &o2), EXIT_FINDINGS);
        assert!(gitdir.join("gitc-scan-cache").exists(), "cache persisted");
        // A third run hits the cache path.
        assert_eq!(scan_history(&gitdir, &o2), EXIT_FINDINGS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_trace_matches_and_misses() {
        let Some((dir, gitdir)) = repo_with_committed_key() else {
            eprintln!("skip scan_trace: no git");
            return;
        };
        // Discover a real finding's fingerprint via a history scan.
        let d = Detector::with_default_rules();
        let head = crate::gitwalk::head_tip(&gitdir).unwrap();
        let (intros, _) = crate::gitwalk::reachable_blob_intros(&gitdir, &[head], &[]);
        let hits = scan_intros(&Opts::default(), &d, &gitdir, &intros, None).unwrap();
        assert!(!hits.is_empty());
        let fp = hits[0].fingerprint.clone();
        let report = dir.join("trace.json");
        let o = Opts {
            trace_finding: Some(fp),
            report_format: "json".to_string(),
            report_path: report.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert_eq!(scan_trace(&gitdir, &o, o.trace_finding.as_deref().unwrap()), EXIT_FINDINGS);
        // A fingerprint that matches nothing → clean exit (no findings emitted).
        assert_eq!(
            scan_trace(&gitdir, &o, "ffffffffffffffffffffffffffffffffffffffff:none:1"),
            EXIT_CLEAN
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
