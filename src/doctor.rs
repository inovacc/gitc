//! Port of Go `internal/doctor` — `git doctor`: a one-shot health check of the
//! gitc install, the resolved git backend, the PATH shim, and the audit DB.
//!
//! The command layer passes the values it owns (version + resolved paths) via
//! [`Config`], so this module stays independent of the binary crate — exactly as
//! the Go package stays independent of `package main`.
//!
//! ## Faithfulness & documented deviations
//!
//! - **lipgloss styling dropped (PARITY).** The Go source renders a violet title
//!   banner, colored status badges, and a subtle footer via `charmbracelet/lipgloss`.
//!   No maintained, drop-in ANSI-styling crate is pulled in here (DEPS: none), and
//!   lipgloss itself strips ANSI when output is piped or `NO_COLOR` is set — the CI
//!   and pipe case. This port renders the **same text content** without ANSI color:
//!   badges `[ ok ]` / `[warn]` / `[fail]`, and the summary lines
//!   `all checks passed.` / `passed with warnings.` / `one or more checks failed.`
//!   (verbatim from Go). Only the terminal color escapes are absent; the tested
//!   contract (badge/summary text + exit code) is byte-identical.
//! - **`git --version` timeout dropped (PARITY).** Go wraps the probe in a 10s
//!   `context` timeout; `std::process::Command` has no built-in timeout. Dropped per
//!   the pack's context→explicit-params rule — `git --version` is a fast, bounded
//!   probe. Behaviorally identical for every realistic backend.
//! - **`exec.LookPath` hand-ported** ([`look_path`]): std has no PATH resolver, so
//!   this is a small self-contained port of Go's `exec.LookPath` (PATHEXT-aware on
//!   Windows, exec-bit-aware on Unix). Not a new dependency.

use std::path::{Path, PathBuf};

use crate::backend::{self, Backend};
use crate::paths;
use crate::store;

/// Carries the command-layer values the checks need, so the doctor module does not
/// reach back into the binary crate. Go `Config`.
#[derive(Debug, Clone)]
pub struct Config {
    /// gitc's own version. Go `Version`.
    pub version: String,
    /// Newest cached managed git, or `None`. Go `ManagedGitPath` (`""` → `None`).
    pub managed_git_path: Option<PathBuf>,
    /// Resolved audit DB path. Go `AuditDBPath`.
    pub audit_db_path: PathBuf,
}

/// The outcome level of one doctor check. Go `checkStatus` (`iota` OK/Warn/Fail);
/// ordering (`Ok < Warn < Fail`) reproduces Go's `if s > worst` worst-status roll-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CheckStatus {
    /// Go `statusOK`.
    Ok,
    /// Go `statusWarn`.
    Warn,
    /// Go `statusFail`.
    Fail,
}

impl CheckStatus {
    /// The status pill for a check. Go `(s checkStatus) badge()` — the fixed
    /// 6-visible-column text, minus lipgloss's ANSI color (see module docs).
    fn badge(self) -> String {
        match self {
            CheckStatus::Ok => "[ ok ]".to_string(),
            CheckStatus::Warn => "[warn]".to_string(),
            CheckStatus::Fail => "[fail]".to_string(),
        }
    }
}

/// One collected doctor check: outcome, a short label, and a detail string (which
/// also carries any remediation hint). Go `checkResult`.
#[derive(Debug, Clone)]
struct CheckResult {
    status: CheckStatus,
    label: String,
    detail: String,
}

/// Accumulates check results and tracks the worst status seen. Replaces Go's
/// `report func(...)` closure captured over `results`/`worst`, which does not port
/// cleanly to Rust's borrow rules.
struct Reporter {
    results: Vec<CheckResult>,
    worst: CheckStatus,
}

impl Reporter {
    fn new() -> Self {
        Reporter {
            results: Vec::new(),
            worst: CheckStatus::Ok,
        }
    }

    /// Records one check, rolling the worst status forward. Go's inner `report`.
    fn report(&mut self, s: CheckStatus, name: &str, detail: impl Into<String>) {
        if s > self.worst {
            self.worst = s;
        }
        self.results.push(CheckResult {
            status: s,
            label: name.to_string(),
            detail: detail.into(),
        });
    }
}

/// Health-checks the gitc install and its backend and prints a one-shot styled
/// checklist. Exits non-zero if any critical (fail) check does not pass, so it
/// stays usable in CI or a post-install verification step. Go `Run`.
///
/// The `args` slice is unused (Go `_ []string`); kept for signature parity.
pub fn run(cfg: Config, _args: &[String]) -> i32 {
    let (results, worst) = collect_checks(&cfg);

    // Title banner + a trailing blank line (Go: Render(...) + "\n", then Println).
    println!("◆ gitc doctor {}\n", cfg.version);

    for r in &results {
        // Go: fmt.Printf("%s  %-22s %s\n", badge, label, detail).
        println!("{}  {:<22} {}", r.status.badge(), r.label, r.detail);
    }

    println!("\n{}", summary_line(worst));
    println!("checks only — no repo data read; `git where` shows resolved paths.");

    exit_code_for(worst)
}

/// Renders the overall verdict text. Go `summaryLine` (minus lipgloss color).
fn summary_line(worst: CheckStatus) -> String {
    match worst {
        CheckStatus::Ok => "all checks passed.".to_string(),
        CheckStatus::Warn => "passed with warnings.".to_string(),
        CheckStatus::Fail => "one or more checks failed.".to_string(),
    }
}

/// Runs every doctor check and returns the results plus the worst status seen.
/// Go `collectChecks`.
fn collect_checks(cfg: &Config) -> (Vec<CheckResult>, CheckStatus) {
    let mut r = Reporter::new();

    r.report(CheckStatus::Ok, "gitc version", cfg.version.clone());

    check_shim(&mut r);
    let b = check_backend(&mut r, cfg.managed_git_path.as_deref());
    check_git_runs(&mut r, b.as_ref());
    check_shell(&mut r, b.as_ref());
    check_audit(&mut r, &cfg.audit_db_path);

    (r.results, r.worst)
}

/// Maps the worst check status to a process exit code (fail → 1). Go `exitCodeFor`.
fn exit_code_for(worst: CheckStatus) -> i32 {
    if worst == CheckStatus::Fail {
        1
    } else {
        0
    }
}

/// Verifies the PATH shim exists and that plain `git` resolves to it. Go `checkShim`.
fn check_shim(r: &mut Reporter) {
    let shim = paths::shim_git_path();

    if std::fs::metadata(&shim).is_err() {
        r.report(
            CheckStatus::Warn,
            "shim installed",
            "not found; run `git install --apply`",
        );
        return;
    }

    r.report(
        CheckStatus::Ok,
        "shim installed",
        shim.display().to_string(),
    );

    // On Windows the shim is a tiny launcher that execs the canonical gitc.exe;
    // verify that target exists (its absence would break every shimmed call).
    if cfg!(windows) {
        let canonical = paths::canonical_path();
        if std::fs::metadata(&canonical).is_ok() {
            r.report(
                CheckStatus::Ok,
                "launcher target",
                canonical.display().to_string(),
            );
        } else {
            r.report(
                CheckStatus::Warn,
                "launcher target",
                "canonical gitc.exe missing; run `git install`",
            );
        }
    }

    let resolved = match look_path("git") {
        Some(p) => p,
        None => {
            r.report(CheckStatus::Warn, "git on PATH", "no git resolved on PATH");
            return;
        }
    };

    let resolved_str = resolved.to_string_lossy().into_owned();
    if same_path(&resolved_str, &shim.to_string_lossy()) {
        r.report(CheckStatus::Ok, "shim shadows git", resolved_str);
    } else {
        r.report(
            CheckStatus::Warn,
            "shim shadows git",
            format!("PATH resolves git to {resolved_str} (not the shim); restart shell"),
        );
    }
}

/// Resolves the git backend and reports its path and kind. Returns the resolved
/// backend on success (`None` when a fail was reported). Go `checkBackend` — its
/// `(Backend, bool)` collapses to `Option<Backend>` here (the zero-value Backend the
/// Go path returns on failure is never inspected by callers).
fn check_backend(r: &mut Reporter, managed: Option<&Path>) -> Option<Backend> {
    // Go: self, _ := os.Executable() — the error is ignored (self may be "").
    let self_path = std::env::current_exe().unwrap_or_default();

    let b = match backend::resolve(managed, &self_path) {
        Ok(b) => b,
        Err(e) => {
            r.report(
                CheckStatus::Fail,
                "git backend",
                format!("{e}; run `git fetch-git`"),
            );
            return None;
        }
    };

    if std::fs::metadata(&b.path).is_err() {
        r.report(
            CheckStatus::Fail,
            "git backend",
            format!("{} ({}) missing on disk", b.path.display(), b.kind),
        );
        return None;
    }

    r.report(
        CheckStatus::Ok,
        "git backend",
        format!("{} ({})", b.path.display(), b.kind),
    );

    Some(b)
}

/// Executes `git --version` through the resolved backend. Go `checkGitRuns`.
fn check_git_runs(r: &mut Reporter, b: Option<&Backend>) {
    let Some(b) = b else {
        r.report(CheckStatus::Fail, "git executes", "no backend to run");
        return;
    };

    // PARITY: Go bounds this with a 10s context timeout; std::process has no
    // built-in timeout (dropped per the pack's context→explicit rule). `--version`
    // is a fast, bounded probe.
    match std::process::Command::new(&b.path)
        .arg("--version")
        .output()
    {
        // Go's .Output() treats a non-zero exit as an error, so only a clean exit
        // is the OK path.
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            r.report(CheckStatus::Ok, "git executes", text.trim().to_string());
        }
        Ok(out) => {
            // Mirrors Go *exec.ExitError's "exit status N" message.
            r.report(
                CheckStatus::Fail,
                "git executes",
                format!("exit status {}", out.status.code().unwrap_or(-1)),
            );
        }
        Err(e) => {
            r.report(CheckStatus::Fail, "git executes", e.to_string());
        }
    }
}

/// Reports whether the resolved backend can run POSIX git hooks. git-for-windows
/// finds its shell in its own install tree (not the caller's PATH), so this is
/// independent of whether `sh`/`bash` resolve in your shell. Go `checkShell`.
fn check_shell(r: &mut Reporter, b: Option<&Backend>) {
    if !cfg!(windows) {
        r.report(CheckStatus::Ok, "shell (hooks)", "system /bin/sh");
        return;
    }

    let Some(b) = b else {
        r.report(CheckStatus::Warn, "shell (hooks)", "no backend to inspect");
        return;
    };

    // <version>/cmd/git.exe -> <version>
    let root = b.path.parent().and_then(|p| p.parent());
    let has = |rel: &[&str]| -> bool {
        match root {
            Some(root) => {
                let mut p = root.to_path_buf();
                for seg in rel {
                    p.push(seg);
                }
                std::fs::metadata(&p).is_ok()
            }
            None => false,
        }
    };

    let bash = has(&["usr", "bin", "bash.exe"]);
    let sh = has(&["usr", "bin", "sh.exe"]);
    let busybox = has(&["mingw64", "bin", "busybox.exe"]) || has(&["mingw64", "bin", "ash.exe"]);

    if bash && sh {
        r.report(
            CheckStatus::Ok,
            "shell (hooks)",
            "bash + sh (#!/bin/sh and #!/bin/bash)",
        );
    } else if sh {
        r.report(CheckStatus::Ok, "shell (hooks)", "sh (#!/bin/sh)");
    } else if busybox {
        r.report(
            CheckStatus::Ok,
            "shell (hooks)",
            "sh via busybox (#!/bin/sh)",
        );
    } else {
        r.report(
            CheckStatus::Warn,
            "shell (hooks)",
            "none — hooks won't run; run `git fetch-git --full`",
        );
    }
}

/// Verifies the audit log opens (creating it if needed). Go `checkAudit`.
fn check_audit(r: &mut Reporter, path: &Path) {
    match store::open(path) {
        Ok(st) => {
            let _ = st.close();
            r.report(CheckStatus::Ok, "audit log", path.display().to_string());
        }
        Err(e) => {
            r.report(CheckStatus::Fail, "audit log", e.to_string());
        }
    }
}

/// Compares two filesystem paths, resolving symlinks and case where possible, so a
/// shim reached via a resolved or 8.3 path still matches. Go `samePath` —
/// `EqualFold(Clean(EvalSymlinks(a)), Clean(EvalSymlinks(b)))`. The `EqualFold`
/// comparison is case-insensitive on ALL platforms (as the Go test asserts), not
/// just Windows.
fn same_path(a: &str, b: &str) -> bool {
    let a = eval_symlinks(a);
    let b = eval_symlinks(b);
    clean(&a).eq_ignore_ascii_case(&clean(&b))
}

/// Go `filepath.EvalSymlinks` (best effort): resolve symlinks when possible,
/// otherwise keep the input (Go ignores the error).
fn eval_symlinks(p: &str) -> String {
    match std::fs::canonicalize(p) {
        Ok(rp) => rp.to_string_lossy().into_owned(),
        Err(_) => p.to_string(),
    }
}

/// Lightweight lexical clean sufficient for path comparison: normalizes separators
/// to the OS separator, collapses separator runs, and drops `.` segments —
/// reproducing the parts of `filepath.Clean` the doctor relies on. Full `..`
/// collapsing is not reproduced; real doctor inputs are already canonicalized by
/// [`eval_symlinks`], so this only shapes the fallback for non-existent paths.
fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }

    let is_win = cfg!(windows);
    let is_sep = |c: char| c == '/' || (is_win && c == '\\');
    let sep = std::path::MAIN_SEPARATOR;

    // Preserve a leading root separator.
    let mut chars = p.chars().peekable();
    let mut root = String::new();
    while let Some(&c) = chars.peek() {
        if is_sep(c) {
            root.push(sep);
            chars.next();
        } else {
            break;
        }
    }

    let rest: String = chars.collect();
    let segs: Vec<&str> = rest
        .split(is_sep)
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    let joined = segs.join(std::path::MAIN_SEPARATOR_STR);
    let out = format!("{root}{joined}");
    if out.is_empty() {
        ".".to_string()
    } else {
        out
    }
}

/// Hand-port of Go `exec.LookPath("git")` — std has no PATH resolver. Returns the
/// first executable named `file` found on PATH (PATHEXT-aware on Windows,
/// exec-bit-aware on Unix), or `None`.
fn look_path(file: &str) -> Option<PathBuf> {
    let has_sep = file.contains('/') || (cfg!(windows) && file.contains('\\'));
    if has_sep {
        return find_executable(Path::new(file));
    }

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        // Go: an empty PATH element means the current directory.
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        if let Some(p) = find_executable(&dir.join(file)) {
            return Some(p);
        }
    }
    None
}

#[cfg(windows)]
fn find_executable(path: &Path) -> Option<PathBuf> {
    let is_file = |p: &Path| std::fs::metadata(p).map(|m| !m.is_dir()).unwrap_or(false);

    // If the name already carries an extension, try it as-is first (Go behavior).
    if path.extension().is_some() && is_file(path) {
        return Some(path.to_path_buf());
    }

    let raw = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    for ext in raw.split(';').filter(|s| !s.is_empty()) {
        let ext = if ext.starts_with('.') {
            ext.to_string()
        } else {
            format!(".{ext}")
        };
        let cand = PathBuf::from(format!("{}{}", path.display(), ext));
        if is_file(&cand) {
            return Some(cand);
        }
    }
    None
}

#[cfg(not(windows))]
fn find_executable(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    if meta.is_dir() {
        return None;
    }
    // Go findExecutable: regular file with any execute bit set.
    if meta.permissions().mode() & 0o111 != 0 {
        Some(path.to_path_buf())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Go TestExitCodeFor.
    #[test]
    fn exit_code_for_mapping() {
        assert_eq!(
            exit_code_for(CheckStatus::Fail),
            1,
            "a failed worst status must exit 1"
        );
        assert_eq!(exit_code_for(CheckStatus::Ok), 0, "ok must exit 0");
        assert_eq!(exit_code_for(CheckStatus::Warn), 0, "warn must exit 0");
    }

    // Go TestSummaryLineAndBadge.
    #[test]
    fn summary_line_and_badge() {
        for s in [CheckStatus::Ok, CheckStatus::Warn, CheckStatus::Fail] {
            assert!(!summary_line(s).is_empty(), "summary_line({s:?}) is empty");
            assert!(!s.badge().is_empty(), "badge({s:?}) is empty");
        }
    }

    // Go TestSamePath.
    #[test]
    fn same_path_cases() {
        assert!(
            same_path(r"C:\gitc\shim\git.exe", r"C:\gitc\shim\git.exe"),
            "identical paths must match"
        );

        // Case-insensitive via EqualFold — holds cross-platform for this
        // identical-modulo-case comparison.
        assert!(
            same_path(r"C:\GITC\git.exe", r"C:\gitc\git.exe"),
            "case-differing paths should match (EqualFold)"
        );

        assert!(
            !same_path(r"C:\a\git.exe", r"C:\b\git.exe"),
            "distinct paths must not match"
        );
    }

    // Go TestExitCodeForString.
    #[test]
    fn exit_code_for_string() {
        assert!(
            summary_line(CheckStatus::Fail)
                .to_lowercase()
                .contains("fail"),
            "fail summary should mention failure"
        );
    }
}
