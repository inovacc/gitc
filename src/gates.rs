//! Port of Go root `gates.go` (package `main`) — the SECURITY enforcement gate.
//!
//! [`enforce_gates`] applies the machine/org policy (`policy.json`) to a
//! passthrough git command:
//!
//! - a pre-flight secret scan on every `commit` (staged content + working tree),
//!   warn-by-default and block only under a policy `secretGate` in block mode;
//! - a working-tree secret scan before a gated command (commit/push) that refuses
//!   (or warns) per policy;
//! - a remote allowlist that blocks push/fetch/clone to a host that is not on the
//!   approved list, resolving named remotes via git and refusing any config
//!   override (or command-line alias) that could rewrite the remote past the check.
//!
//! **Fail-closed is the invariant.** A broken/unreadable policy where the ENFORCE
//! marker is present fails CLOSED (blocks); a remote the allowlist cannot resolve
//! to a URL because git could not be run to a verdict (timeout / missing binary /
//! killed) is blocked rather than allowed unverified. Only a genuine git-level
//! rejection (an unknown remote git itself will reject) is allowed to fall
//! through. Never weaken a gate; when in doubt, block.
//!
//! ## Port notes (Go → Rust)
//!
//! - Go's `internal/scan` package (`scan.New`/`ScanDir`/`ScanBytes`/`Mask`,
//!   returning `report.Finding`) is NOT the shape of this crate's `crate::scan`,
//!   so the gate's scanning is rebuilt here directly on the betterleaks `detect`
//!   engine ([`Scanner`] wraps [`detect::Detector`]). Findings are `report::Finding`
//!   (cross-module type identity with `detect`/`report`).
//! - The `gitQuery` / `gitBytes` package-var seams (stubbed in the Go tests) are
//!   modelled as `thread_local` seams — parallel-test-safe, no `static mut`.
//! - Go's `*exec.ExitError`-vs-other error classification ([`is_exec_failure`]) is
//!   modelled as [`GitError`] (`Exit` = git's own verdict; `Failure` = an exec
//!   failure that fails closed).
//! - FLAG: the 5s `context` timeout on the real git queries is not reproduced —
//!   `std::process::Command` has no built-in deadline (see [`real_git_query`]).

use std::io::Write;
use std::path::Path;

use crate::gitargs::subcommand_index;
use crate::policy::{is_remote_url, Policy};
use report::Finding;

/// Per-blob size ceiling for the working-tree scan (Go `scan.maxFileSize`, 10 MiB).
const MAX_FILE_SIZE: u64 = 10 << 20;

// ── error model ─────────────────────────────────────────────────────────────

/// The outcome of a read-only git query. Splits git's OWN verdict from an exec
/// failure, exactly as Go distinguishes a `*exec.ExitError` from every other
/// error (see [`is_exec_failure`]).
#[derive(Debug)]
enum GitError {
    /// git ran and exited non-zero — a genuine git verdict (e.g. an unknown
    /// remote name git itself rejects). The `*exec.ExitError` analog; NOT an exec
    /// failure, so the allowlist lets it fall through to git.
    Exit,
    /// git could not be run to a clean verdict — a timeout/cancellation, a missing
    /// binary, or a killed process. The allowlist FAILS CLOSED on this.
    Failure(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::Exit => write!(f, "git exited non-zero"),
            GitError::Failure(m) => write!(f, "{m}"),
        }
    }
}

/// An error resolving the enforcement policy (Go returned `error`).
#[derive(Debug)]
enum Error {
    /// The policy file failed to load/parse.
    Policy(crate::policy::Error),
    /// The ENFORCE marker is present but no `policy.json` was found (fail closed).
    EnforcementRequired {
        /// The marker path that demanded enforcement.
        marker: String,
        /// Where a machine policy was expected.
        machine: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Policy(e) => write!(f, "{e}"),
            Error::EnforcementRequired { marker, machine } => write!(
                f,
                "enforcement required ({marker} present) but no policy.json found at {machine}"
            ),
        }
    }
}

impl std::error::Error for Error {}

// ── git-query seams (package vars in Go, stubbed by the tests) ──────────────

type GitQueryFn = Box<dyn Fn(&str, &[&str]) -> Result<String, GitError>>;
type GitBytesFn = Box<dyn Fn(&str, &[&str]) -> Result<Vec<u8>, GitError>>;

thread_local! {
    static GIT_QUERY: std::cell::RefCell<Option<GitQueryFn>> = const { std::cell::RefCell::new(None) };
    static GIT_BYTES: std::cell::RefCell<Option<GitBytesFn>> = const { std::cell::RefCell::new(None) };
}

/// Runs a read-only git command against `git_path` and returns trimmed stdout.
/// A package-var seam in Go so tests can stub git resolution.
fn git_query(git_path: &str, args: &[&str]) -> Result<String, GitError> {
    if let Some(r) = GIT_QUERY.with(|c| c.borrow().as_ref().map(|f| f(git_path, args))) {
        return r;
    }
    real_git_query(git_path, args)
}

/// Runs a read-only git command and returns raw stdout. A package-var seam in Go
/// so the staged scan can be stubbed in tests.
fn git_bytes(git_path: &str, args: &[&str]) -> Result<Vec<u8>, GitError> {
    if let Some(r) = GIT_BYTES.with(|c| c.borrow().as_ref().map(|f| f(git_path, args))) {
        return r;
    }
    real_git_bytes(git_path, args)
}

/// The real read-only git query.
///
/// FLAG (divergence from Go): Go bounds this with a 5s `context` timeout; std's
/// `Command` has no built-in deadline, so the timeout is not reproduced here. The
/// tests stub this seam, so parity is unaffected; a production hang on a wedged
/// git is the only behavioral gap. A spawn failure → [`GitError::Failure`] (exec
/// failure, fails closed); a non-zero exit → [`GitError::Exit`] (git's verdict).
fn real_git_query(git_path: &str, args: &[&str]) -> Result<String, GitError> {
    let out = std::process::Command::new(git_path)
        .args(args)
        .output()
        .map_err(|e| GitError::Failure(e.to_string()))?;
    if !out.status.success() {
        return Err(GitError::Exit);
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The real raw-stdout git query (see [`real_git_query`] for the timeout FLAG).
fn real_git_bytes(git_path: &str, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let out = std::process::Command::new(git_path)
        .args(args)
        .output()
        .map_err(|e| GitError::Failure(e.to_string()))?;
    if !out.status.success() {
        return Err(GitError::Exit);
    }
    Ok(out.stdout)
}

// ── the entry point ─────────────────────────────────────────────────────────

/// Applies the machine/org policy to a passthrough command. Returns
/// `(exit_code, true)` to refuse, `(0, false)` to allow. A broken policy file
/// fails closed. Faithful port of Go `enforceGates`.
pub fn enforce_gates(args: &[String], git_path: &str) -> (i32, bool) {
    let (pol, _path) = match load_enforcement_policy() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("gitc: policy: {e}");
            return (1, true);
        }
    };

    // Always-on pre-flight secret scan on commit — staged content AND working
    // tree — regardless of policy. Warn by default; a block-mode secretGate
    // escalates to a hard refusal.
    if subcommand(args) == "commit" {
        return preflight_commit_scan(args, git_path, &pol);
    }

    // Enforcement is opt-in; with neither gate enabled there is nothing else to do.
    if !pol.secret_gate.enabled && !pol.remote_allow.enabled {
        return (0, false);
    }

    // A command-line alias can hide a gated verb from classification (SEC-6):
    // `git -c alias.p=push p` is seen as subcommand "p" and neither gate fires.
    if let Some(key) = alias_injection(args) {
        eprintln!(
            "gitc: BLOCKED by policy: command-line alias {key:?} runs a gated command and is not permitted"
        );
        return (1, true);
    }

    let (code, blocked) = enforce_remote_allowlist(&pol, args, git_path);
    if blocked {
        return (code, true);
    }

    enforce_secret_gate(&pol, args, git_path)
}

/// The git subcommands the gates care about (secret gate + remote allowlist, plus
/// the low-level exfil plumbing). Faithful port of Go `gatedVerbs`.
fn gated_verb(v: &str) -> bool {
    matches!(
        v,
        "push" | "commit" | "fetch" | "pull" | "clone" | "remote" | "send-pack" | "http-push"
    )
}

/// Reports whether `args` inject a command-line alias (`-c alias.<name>=<value>`)
/// that is the current subcommand and expands to a gated verb or a shell command,
/// returning the alias key. The precise SEC-6 command-line vector. Faithful port
/// of Go `aliasInjection` (Go's `(key, bool)` → `Option<String>`).
fn alias_injection(args: &[String]) -> Option<String> {
    let idx = subcommand_index(args)?;
    let sub = &args[idx];
    let key = format!("alias.{sub}");

    let mut i = 0;
    while i < args.len() {
        if args[i] != "-c" || i + 1 >= args.len() {
            i += 1;
            continue;
        }

        let (k, v, ok) = cut(&args[i + 1], '=');
        i += 1; // consume the value token (Go's inner i++)

        if !ok || !k.eq_ignore_ascii_case(&key) {
            i += 1; // Go's for-post
            continue;
        }

        let val = v.trim();
        if val.starts_with('!') {
            // shell alias — opaque, refuse
            return Some(k.to_string());
        }
        if let Some(first) = val.split_whitespace().next() {
            if gated_verb(first) {
                return Some(k.to_string());
            }
        }

        i += 1; // Go's for-post
    }

    None
}

/// Splits `s` at the first `sep` (Go `strings.Cut`): `(before, after, found)`.
fn cut(s: &str, sep: char) -> (&str, &str, bool) {
    match s.find(sep) {
        Some(i) => (&s[..i], &s[i + sep.len_utf8()..], true),
        None => (s, "", false),
    }
}

// ── policy resolution (fail-closed) ─────────────────────────────────────────

/// Resolves the machine/org policy, defending against an agent relocating it via
/// its user environment (SEC-2/H-27): machine-wide policy first, then the
/// deprecated per-user path. Faithful port of Go `loadEnforcementPolicy`.
fn load_enforcement_policy() -> Result<(Policy, String), Error> {
    resolve_policy(
        &crate::paths::machine_policy_path(),
        &crate::paths::policy_path(),
        &crate::paths::enforce_marker_path(),
    )
}

/// The resolved enforcement-policy path (empty when no policy governs this
/// machine), for recording on every audit row so a policy relocation is
/// forensically visible (SEC-2). Mirrors Go `main.go`'s use of
/// `loadEnforcementPolicy()`'s third (path) return; a load error yields "" (the
/// gate itself fails closed independently on the next command).
/// The external pre/post stage commands the machine policy names, or empty when no
/// policy is in effect or it fails to load.
///
/// [`crate::stage`] reads these ONCE, before git core runs, so no stage has to
/// touch the filesystem during process teardown. A load failure yields no commands
/// here on purpose: refusing the command is [`enforce_gates`]'s job, and it reports
/// the same error — duplicating the refusal here would double the diagnostic.
pub(crate) fn policy_stage_commands() -> (Vec<crate::policy::StageCmd>, Vec<crate::policy::StageCmd>)
{
    match load_enforcement_policy() {
        Ok((pol, _path)) => (pol.stages.pre, pol.stages.post),
        Err(_) => (Vec::new(), Vec::new()),
    }
}

/// The resolved enforcement policy path, or `""`.
pub fn enforcement_policy_path() -> String {
    load_enforcement_policy()
        .map(|(_, path)| path)
        .unwrap_or_default()
}

/// The path-injected core of [`load_enforcement_policy`] (testable without the
/// real machine dirs). Order: machine policy, then the deprecated per-user
/// policy. If neither exists and the ENFORCE marker is present, it fails CLOSED.
/// Faithful port of Go `resolvePolicy` (Go's `(Policy, string, error)`).
fn resolve_policy(
    machine_path: &Path,
    user_path: &Path,
    marker_path: &Path,
) -> Result<(Policy, String), Error> {
    if file_exists(machine_path) {
        let pol = crate::policy::load_policy(machine_path).map_err(Error::Policy)?;
        return Ok((pol, machine_path.display().to_string()));
    }

    if file_exists(user_path) {
        eprintln!(
            "gitc: warning: per-user policy.json is deprecated (removal 2026-09-01); move it to {}",
            machine_path.display()
        );
        let pol = crate::policy::load_policy(user_path).map_err(Error::Policy)?;
        return Ok((pol, user_path.display().to_string()));
    }

    if file_exists(marker_path) {
        return Err(Error::EnforcementRequired {
            marker: marker_path.display().to_string(),
            machine: machine_path.display().to_string(),
        });
    }

    Ok((Policy::default(), String::new()))
}

/// Reports whether `path` is an existing regular file. Faithful port of Go
/// `fileExists`.
fn file_exists(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(m) => !m.is_dir(),
        Err(_) => false,
    }
}

// ── remote allowlist ────────────────────────────────────────────────────────

/// Resolves the effective remote URL(s) of a remote-facing command and blocks any
/// whose host/owner is not on the approved list. Fails CLOSED on an exec failure;
/// a git-level rejection falls through. Faithful port of Go
/// `enforceRemoteAllowlist`.
fn enforce_remote_allowlist(pol: &Policy, args: &[String], git_path: &str) -> (i32, bool) {
    let (refs, uses_default) = pol.remote_refs(args);

    if refs.is_empty() && !uses_default {
        return (0, false); // not a remote-facing command under the allowlist
    }

    // A config override that rewrites where the command actually connects would let
    // an allowed URL be swapped for an attacker host AFTER the allowlist resolved
    // the clean URL. Refuse it on a remote-facing command — fail closed.
    if let Some(key) = remote_rewrite_override(args) {
        eprintln!(
            "gitc: BLOCKED by policy: config override {key:?} can rewrite the remote past the allowlist"
        );
        return (1, true);
    }

    let mut urls: Vec<String> = Vec::new();

    for ref_ in &refs {
        if is_remote_url(ref_) {
            urls.push(ref_.clone());
            continue;
        }
        match resolve_remote_url(git_path, ref_) {
            Ok(u) => urls.push(u),
            Err(e) if is_exec_failure(Some(&e)) => {
                return block_unverifiable(&format!("remote {ref_:?}"), &e)
            }
            Err(_) => {} // git-level rejection (unknown remote) — git itself will error
        }
    }

    if uses_default {
        match resolve_default_remote(git_path) {
            Ok(u) => urls.push(u),
            Err(e) if is_exec_failure(Some(&e)) => {
                return block_unverifiable("the default remote", &e)
            }
            Err(_) => {}
        }
    }

    for u in &urls {
        if !pol.remote_allowed(u) {
            eprintln!("gitc: BLOCKED by policy: remote {u:?} is not on the allowed list");
            return (1, true);
        }
    }

    (0, false)
}

/// Reports whether `args` or the environment supply a git config override that can
/// rewrite where a remote-facing command connects, returning the offending key.
/// Faithful port of Go `remoteRewriteOverride`.
fn remote_rewrite_override(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if (a == "-c" || a == "--config-env") && i + 1 < args.len() {
            // both `-c KEY=VAL` and `--config-env KEY=ENVVAR` consume the next arg
            let k = config_key_of(&args[i + 1]);
            if remote_rewrite_config(&k) {
                return Some(k);
            }
            i += 1;
        } else if let Some(rest) = a.strip_prefix("--config-env=") {
            let k = config_key_of(rest);
            if remote_rewrite_config(&k) {
                return Some(k);
            }
        }
        i += 1;
    }

    env_remote_rewrite_override()
}

/// Checks `GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_PARAMETERS` for a remote-rewriting
/// override. Faithful port of Go `envRemoteRewriteOverride`.
fn env_remote_rewrite_override() -> Option<String> {
    for (k, v) in std::env::vars() {
        if k.starts_with("GIT_CONFIG_KEY_") && remote_rewrite_config(&v) {
            return Some(v);
        }
        if k == "GIT_CONFIG_PARAMETERS" && params_have_rewrite(&v) {
            return Some("GIT_CONFIG_PARAMETERS".to_string());
        }
    }
    None
}

/// Returns the key part of a `key=value` git config override. Faithful port of Go
/// `configKeyOf`.
fn config_key_of(kv: &str) -> String {
    match kv.find('=') {
        Some(i) => kv[..i].to_string(),
        None => kv.to_string(),
    }
}

/// Reports whether a git config key can rewrite a remote's effective URL. Faithful
/// port of Go `remoteRewriteConfig`.
fn remote_rewrite_config(key: &str) -> bool {
    let k = key.trim().to_lowercase();
    if k.starts_with("url.") && (k.ends_with(".insteadof") || k.ends_with(".pushinsteadof")) {
        return true;
    }
    if k.starts_with("remote.") && (k.ends_with(".url") || k.ends_with(".pushurl")) {
        return true;
    }
    false
}

/// Coarsely detects a remote-rewriting key inside the shell-quoted
/// `GIT_CONFIG_PARAMETERS` blob; a false positive only over-blocks (fail closed).
/// Faithful port of Go `paramsHaveRewrite`.
fn params_have_rewrite(s: &str) -> bool {
    let l = s.to_lowercase();
    l.contains(".insteadof")
        || l.contains(".pushinsteadof")
        || l.contains(".pushurl")
        || (l.contains("remote.") && l.contains(".url"))
}

/// Reports a fail-closed block for a remote the allowlist could not resolve.
/// Faithful port of Go `blockUnverifiable`.
fn block_unverifiable(what: &str, err: &GitError) -> (i32, bool) {
    eprintln!("gitc: BLOCKED by policy: cannot verify {what} against the allowlist: {err}");
    (1, true)
}

/// Reports whether `err` means git could not be run to a clean verdict (a
/// timeout, a missing binary, a killed process) as opposed to git running fine
/// and exiting non-zero. Faithful port of Go `isExecFailure` (Go's nil `error`
/// case → `None`).
fn is_exec_failure(err: Option<&GitError>) -> bool {
    match err {
        None => false,
        Some(GitError::Exit) => false,
        Some(GitError::Failure(_)) => true,
    }
}

/// Runs `git remote get-url <name>`. Faithful port of Go `resolveRemoteURL`.
fn resolve_remote_url(git_path: &str, name: &str) -> Result<String, GitError> {
    git_query(git_path, &["remote", "get-url", name])
}

/// Resolves the current branch's push remote to a URL, falling back to origin. An
/// exec failure while probing `@{push}` propagates (caller fails closed); a
/// git-level "no upstream" falls back to origin. Faithful port of Go
/// `resolveDefaultRemote`.
fn resolve_default_remote(git_path: &str) -> Result<String, GitError> {
    match git_query(
        git_path,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{push}",
        ],
    ) {
        Ok(reference) => {
            let name = match reference.find('/') {
                Some(i) => &reference[..i],
                None => reference.as_str(),
            };
            resolve_remote_url(git_path, name)
        }
        Err(e) => {
            if is_exec_failure(Some(&e)) {
                return Err(e);
            }
            resolve_remote_url(git_path, "origin")
        }
    }
}

// ── secret gate ─────────────────────────────────────────────────────────────

/// Runs a working-tree secret scan before a gated command and refuses when
/// anything is found — or, in warn mode, reports and proceeds. Faithful port of
/// Go `enforceSecretGate`.
fn enforce_secret_gate(pol: &Policy, args: &[String], git_path: &str) -> (i32, bool) {
    if !pol.secret_gate_applies(args) {
        return (0, false);
    }

    let sc = match Scanner::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gitc: secret gate: {e}");
            return (1, true);
        }
    };

    let dir = secret_scan_dir(args, git_path);
    let findings = match scan_dir(&sc, Path::new(&dir)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("gitc: secret gate: {e}");
            return (1, true);
        }
    };

    if findings.is_empty() {
        return (0, false);
    }

    eprintln!(
        "gitc: secret gate: {} secret(s) in the working tree:",
        findings.len()
    );
    for f in &findings {
        let loc = if f.start_line > 0 {
            format!("{}:{}", f.file, f.start_line)
        } else {
            f.file.clone()
        };
        eprintln!("  {}\t{}\t{}", f.rule_id, loc, mask(&f.secret));
    }

    if !pol.secret_gate.blocks() {
        eprintln!("gitc: secret gate (warn mode): proceeding despite findings.");
        return (0, false);
    }

    eprintln!("gitc: BLOCKED — remove or scrub the secret(s), then retry.");
    (1, true)
}

/// Returns the git subcommand token past any leading global flags, or "".
/// Faithful port of Go `subcommand`.
fn subcommand(args: &[String]) -> &str {
    match subcommand_index(args) {
        Some(idx) => &args[idx],
        None => "",
    }
}

/// The always-on pre-flight secret scan for a commit: staged content AND working
/// tree, warn-by-default, block only under a block-mode `secretGate`. Faithful
/// port of Go `preflightCommitScan`.
fn preflight_commit_scan(args: &[String], git_path: &str, pol: &Policy) -> (i32, bool) {
    let sc = match Scanner::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gitc: pre-flight scan: {e}");
            // A scanner build failure blocks only under an explicit block-mode
            // policy; otherwise a tool problem must not wedge every commit.
            if pol.secret_gate_applies(args) && pol.secret_gate.blocks() {
                return (1, true);
            }
            return (0, false);
        }
    };

    let mut all = scan_staged(&sc, git_path);
    all.extend(scan_tree(&sc, args, git_path));
    let findings = dedupe_findings(all);
    let block_mode = pol.secret_gate_applies(args) && pol.secret_gate.blocks();

    let mut err = std::io::stderr();
    commit_preflight_verdict(&findings, block_mode, &mut err)
}

/// Scans the working tree the commit targets. Faithful port of Go `scanTree`.
fn scan_tree(sc: &Scanner, args: &[String], git_path: &str) -> Vec<Finding> {
    let dir = secret_scan_dir(args, git_path);
    scan_dir(sc, Path::new(&dir)).unwrap_or_default()
}

/// Scans the staged blob content of each added/modified path — exactly what the
/// commit will record. Faithful port of Go `scanStaged` (uses the [`git_bytes`]
/// seam).
fn scan_staged(sc: &Scanner, git_path: &str) -> Vec<Finding> {
    let names = match git_bytes(
        git_path,
        &["diff", "--cached", "--name-only", "--diff-filter=ACM"],
    ) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };

    let names = String::from_utf8_lossy(&names);
    let mut findings = Vec::new();

    for name in names.trim().split('\n') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let show_arg = format!(":{name}");
        let content = match git_bytes(git_path, &["show", &show_arg]) {
            Ok(c) => c,
            Err(_) => continue,
        };
        findings.extend(scan_bytes(sc, name, &content));
    }

    findings
}

/// Collapses identical findings (the same secret can surface in both the staged
/// blob and the working-tree copy). Faithful port of Go `dedupeFindings` — same
/// key `file|rule_id|secret|start_line`, first occurrence wins.
fn dedupe_findings(fs: Vec<Finding>) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::with_capacity(fs.len());
    let mut out = Vec::new();
    for f in fs {
        let key = format!("{}|{}|{}|{}", f.file, f.rule_id, f.secret, f.start_line);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        out.push(f);
    }
    out
}

/// Reports findings (credential-masked) and decides the gate result: block when
/// `block_mode`, otherwise warn and proceed. Pure. Faithful port of Go
/// `commitPreflightVerdict`.
fn commit_preflight_verdict(
    findings: &[Finding],
    block_mode: bool,
    w: &mut dyn Write,
) -> (i32, bool) {
    if findings.is_empty() {
        return (0, false);
    }

    let _ = writeln!(
        w,
        "gitc: pre-flight secret scan: {} secret(s) in the commit / working tree:",
        findings.len()
    );
    for f in findings {
        let loc = if f.start_line > 0 {
            format!("{}:{}", f.file, f.start_line)
        } else {
            f.file.clone()
        };
        let _ = writeln!(w, "  {}\t{}\t{}", f.rule_id, loc, mask(&f.secret));
    }

    if block_mode {
        let _ = writeln!(
            w,
            "gitc: BLOCKED — remove or scrub the secret(s), then retry."
        );
        return (1, true);
    }

    let _ = writeln!(
        w,
        "gitc: pre-flight scan (warn): commit proceeding. Enable a policy.json secretGate (block mode) to enforce."
    );
    (0, false)
}

/// Resolves the working tree the command will actually operate on, honoring the
/// command's own `-C`/`--git-dir`/`--work-tree` globals (SEC-7), by asking git
/// (`<globals> rev-parse --show-toplevel`), falling back to "." Faithful port of
/// Go `secretScanDir`.
fn secret_scan_dir(args: &[String], git_path: &str) -> String {
    let globals: &[String] = match subcommand_index(args) {
        Some(idx) if idx > 0 => &args[..idx],
        _ => &[],
    };

    let mut q: Vec<&str> = globals.iter().map(String::as_str).collect();
    q.push("rev-parse");
    q.push("--show-toplevel");

    match git_query(git_path, &q) {
        Ok(out) if !out.is_empty() => out,
        _ => ".".to_string(),
    }
}

/// Display-safe rendering of a detected secret: the first few characters then a
/// fixed run of asterisks. Faithful port of Go `scan.Mask`.
///
/// Divergence (noted): Go operates on BYTE length/slicing; this uses CHAR
/// count/slicing so a multi-byte secret cannot panic (a Rust `String` cannot hold
/// the invalid UTF-8 a byte split would produce). Identical for ASCII secrets.
fn mask(secret: &str) -> String {
    if secret.is_empty() {
        return "<redacted>".to_string();
    }
    const KEEP: usize = 4;
    let len = secret.chars().count();
    if len <= KEEP {
        return "*".repeat(len);
    }
    let head: String = secret.chars().take(KEEP).collect();
    format!("{head}{}", "*".repeat(6))
}

// ── the scanner (rebuilt on `detect`, since crate::scan has a different shape) ─

/// Runs betterleaks `detect` secret detection over strings and directory trees.
/// The gate's analog of Go `internal/scan.Scanner` (that package's exact API is
/// not what this crate's `crate::scan` exposes, so it is rebuilt here directly on
/// [`detect::Detector`]).
struct Scanner {
    detector: detect::Detector,
}

impl Scanner {
    /// Builds a scanner from the embedded default ruleset. Faithful port of Go
    /// `scan.New` (its `error` path preserved).
    fn new() -> Result<Scanner, String> {
        let detector = detect::Detector::with_default_config()
            .map_err(|e| format!("scan: building detector: {e}"))?;
        Ok(Scanner { detector })
    }
}

/// Directory names skipped by default (VCS metadata + large vendored trees).
/// Faithful port of Go `scan.skipDirs`.
fn skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".svn" | ".hg" | "node_modules" | "vendor" | "third_party"
    )
}

/// Scans raw bytes attributed to `file_path` and returns any findings, with the
/// path recorded on each finding. Faithful port of Go `Scanner.ScanBytes`.
fn scan_bytes(sc: &Scanner, file_path: &str, content: &[u8]) -> Vec<Finding> {
    let slashed = to_slash(file_path);
    let mut frag = sources::Fragment {
        raw: String::from_utf8_lossy(content).into_owned(),
        ..Default::default()
    };
    frag.set_attr(sources::ATTR_PATH, &slashed);

    let mut findings = sc.detector.detect(&frag);
    for f in &mut findings {
        if f.file.is_empty() {
            f.file = slashed.clone();
        }
    }
    findings
}

/// Go `filepath.ToSlash` — replaces the OS path separator with `/`.
fn to_slash(p: &str) -> String {
    if std::path::MAIN_SEPARATOR == '/' {
        p.to_string()
    } else {
        p.replace(std::path::MAIN_SEPARATOR, "/")
    }
}

/// Walks `root` (skipping VCS/vendor dirs) and scans each regular, reasonably
/// sized, non-binary file, aggregating findings with their paths. A missing/
/// unreadable ROOT is a hard error (the gate blocks on it); an unreadable SUBTREE
/// is skipped. Detection-only. Faithful port of the gate-relevant behavior of Go
/// `Scanner.ScanDir` (its `Result.Skipped` accounting — used only by `git scan
/// --strict`, never by the gate — is intentionally not tracked here).
fn scan_dir(sc: &Scanner, root: &Path) -> Result<Vec<Finding>, String> {
    let meta =
        std::fs::metadata(root).map_err(|e| format!("scan: walking {}: {e}", root.display()))?;

    let mut findings = Vec::new();
    if meta.is_dir() {
        walk_dir(sc, root, root, &mut findings);
    } else if meta.is_file() {
        scan_file(sc, root, root, &mut findings);
    }
    Ok(findings)
}

/// Recursively walks `dir`, visiting entries in name order (Go `WalkDir` is
/// lexical), skipping `skip_dir` names.
fn walk_dir(sc: &Scanner, root: &Path, dir: &Path, findings: &mut Vec<Finding>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return, // unreadable subtree — skipped (gate ignores Skipped)
    };

    let mut entries: Vec<std::fs::DirEntry> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_dir() {
            let name = entry.file_name();
            if skip_dir(&name.to_string_lossy()) {
                continue;
            }
            walk_dir(sc, root, &path, findings);
        } else if ft.is_file() {
            scan_file(sc, root, &path, findings);
        }
        // else: not a regular file — skipped
    }
}

/// Scans one file: skip empty/oversized/binary, attribute findings to the path
/// relative to `root`.
fn scan_file(sc: &Scanner, root: &Path, path: &Path, findings: &mut Vec<Finding>) {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let size = meta.len();
    if size == 0 || size > MAX_FILE_SIZE {
        return; // intentional policy skip, not an error
    }
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    if is_binary(&content) {
        return;
    }

    let rel = path.strip_prefix(root).unwrap_or(path);
    let rel = rel.to_string_lossy();
    findings.extend(scan_bytes(sc, &rel, &content));
}

/// Reports whether content looks binary (a NUL in the first chunk). Faithful port
/// of Go `scan.isBinary` (8000-byte window).
fn is_binary(content: &[u8]) -> bool {
    let n = content.len().min(8000);
    content[..n].contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{RemoteAllowlist, SecretGate};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    // These tests mutate/read process-global env (GIT_CONFIG_*) via the remote
    // allowlist; serialize every allowlist test that reaches the env probe.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── seam stubs (Go stubGitQuery / gitBytes override) ────────────────────

    struct GitQueryGuard;
    impl Drop for GitQueryGuard {
        fn drop(&mut self) {
            GIT_QUERY.with(|c| *c.borrow_mut() = None);
        }
    }
    fn stub_git_query<F>(f: F) -> GitQueryGuard
    where
        F: Fn(&str, &[&str]) -> Result<String, GitError> + 'static,
    {
        GIT_QUERY.with(|c| *c.borrow_mut() = Some(Box::new(f)));
        GitQueryGuard
    }

    struct GitBytesGuard;
    impl Drop for GitBytesGuard {
        fn drop(&mut self) {
            GIT_BYTES.with(|c| *c.borrow_mut() = None);
        }
    }
    fn stub_git_bytes<F>(f: F) -> GitBytesGuard
    where
        F: Fn(&str, &[&str]) -> Result<Vec<u8>, GitError> + 'static,
    {
        GIT_BYTES.with(|c| *c.borrow_mut() = Some(Box::new(f)));
        GitBytesGuard
    }

    // ── temp dir + env helpers (Go t.TempDir / t.Setenv) ────────────────────

    struct TempDir {
        path: std::path::PathBuf,
    }
    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut path = std::env::temp_dir();
            path.push(format!("{tag}_{}_{}", std::process::id(), n));
            std::fs::create_dir_all(&path).unwrap();
            TempDir { path }
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvVarGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            EnvVarGuard { key, prev }
        }
    }
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn plant_secret_repo() -> TempDir {
        let dir = TempDir::new("gitc_gates_plant");
        // Assemble the token from split literals so THIS source file never carries
        // a contiguous provider-format secret; the full token is written at runtime.
        let body = format!(
            "stripe_key = sk_{}{}\n",
            "live_", "4eC39HqLyjWDarjtT1zdp7dc"
        );
        std::fs::write(dir.path().join("config.env"), body).unwrap();
        dir
    }

    fn allowlist_policy(hosts: &[&str]) -> Policy {
        Policy {
            remote_allow: RemoteAllowlist {
                enabled: true,
                hosts: hosts.iter().map(|s| s.to_string()).collect(),
            },
            ..Default::default()
        }
    }

    // ── TestCommitPreflightVerdict ──────────────────────────────────────────
    #[test]
    fn commit_preflight_verdict_cases() {
        let mut sink = std::io::sink();

        let (code, blocked) = commit_preflight_verdict(&[], false, &mut sink);
        assert!(!blocked && code == 0, "no findings must allow the commit");

        let f = vec![Finding {
            rule_id: "stripe".into(),
            file: "config.env".into(),
            secret: "sk_live_x".into(),
            start_line: 1,
            ..Default::default()
        }];

        let (code, blocked) = commit_preflight_verdict(&f, false, &mut sink);
        assert!(
            !blocked && code == 0,
            "warn mode must let the commit proceed despite findings"
        );

        let (code, blocked) = commit_preflight_verdict(&f, true, &mut sink);
        assert!(
            blocked && code == 1,
            "block mode must refuse the commit on a finding"
        );
    }

    // ── TestScanStagedDetects ───────────────────────────────────────────────
    #[test]
    fn scan_staged_detects() {
        let sc = Scanner::new().expect("scanner");
        let secret = format!("stripe = sk_{}{}", "live_", "4eC39HqLyjWDarjtT1zdp7dc");
        let _g = stub_git_bytes(move |_gp, args| match args[0] {
            "diff" => Ok(b"config.env\n".to_vec()),
            "show" => Ok(secret.as_bytes().to_vec()),
            _ => Ok(Vec::new()),
        });

        let findings = scan_staged(&sc, "git");
        assert!(
            !findings.is_empty(),
            "a secret in staged content must be detected"
        );
    }

    // ── TestDedupeFindings ──────────────────────────────────────────────────
    #[test]
    fn dedupe_findings_test() {
        let f = Finding {
            rule_id: "r".into(),
            file: "f".into(),
            secret: "s".into(),
            start_line: 1,
            ..Default::default()
        };
        let out = dedupe_findings(vec![f.clone(), f]);
        assert_eq!(out.len(), 1, "dedupeFindings should collapse duplicates");
    }

    // ── TestSecretGateBlocksAndWarns ────────────────────────────────────────
    #[test]
    fn secret_gate_blocks_and_warns() {
        let dir = plant_secret_repo();
        let dir_str = dir.path().to_string_lossy().into_owned();
        let _g = stub_git_query(move |_, _| Ok(dir_str.clone())); // secretScanDir -> dir

        let block = Policy {
            secret_gate: SecretGate {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let (code, blocked) = enforce_secret_gate(&block, &argv(&["commit", "-m", "x"]), "git");
        assert!(
            blocked && code == 1,
            "secret gate must block a planted secret, got code={code} blocked={blocked}"
        );

        let warn = Policy {
            secret_gate: SecretGate {
                enabled: true,
                mode: "warn".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let (_c, blocked) = enforce_secret_gate(&warn, &argv(&["commit"]), "git");
        assert!(!blocked, "warn mode must proceed despite findings");

        let (_c, blocked) = enforce_secret_gate(&block, &argv(&["status"]), "git");
        assert!(
            !blocked,
            "secret gate must not apply to a non-gated command"
        );
    }

    // ── TestResolveDefaultRemoteFollowsPush ─────────────────────────────────
    #[test]
    fn resolve_default_remote_follows_push() {
        let _g = stub_git_query(|_gp, args| match args[0] {
            "rev-parse" => Ok("upstream/main".to_string()),
            "remote" => {
                assert_eq!(
                    args[2], "upstream",
                    "default remote should resolve @{{push}}'s remote 'upstream'"
                );
                Ok("https://internal.example/x".to_string())
            }
            _ => Ok(String::new()),
        });

        let url = resolve_default_remote("git").expect("resolveDefaultRemote");
        assert_eq!(url, "https://internal.example/x");
    }

    // ── TestResolvePolicyMalformedFailsClosed ───────────────────────────────
    #[test]
    fn resolve_policy_malformed_fails_closed() {
        let dir = TempDir::new("gitc_gates_rp1");
        let machine = dir.path().join("policy.json");
        std::fs::write(&machine, "{ this is not valid json").unwrap();

        let r = resolve_policy(
            &machine,
            &dir.path().join("u.json"),
            &dir.path().join("ENFORCE"),
        );
        assert!(
            r.is_err(),
            "a malformed policy must return an error (fail closed), got Ok"
        );
    }

    // ── TestResolvePolicy ───────────────────────────────────────────────────
    #[test]
    fn resolve_policy_precedence() {
        let dir = TempDir::new("gitc_gates_rp2");
        let machine = dir.path().join("machine.json");
        let user = dir.path().join("user.json");
        let marker = dir.path().join("ENFORCE");
        let valid =
            r#"{"version":1,"remoteAllowlist":{"enabled":true,"hosts":["internal.example"]}}"#;

        // Machine policy present -> used.
        std::fs::write(&machine, valid).unwrap();
        let (pol, path) =
            resolve_policy(&machine, &user, &marker).expect("machine policy should win");
        assert_eq!(path, machine.display().to_string());
        assert!(pol.remote_allow.enabled);

        // Only the deprecated per-user policy present -> used as fallback.
        std::fs::remove_file(&machine).unwrap();
        std::fs::write(&user, valid).unwrap();
        let (_pol, path) = resolve_policy(&machine, &user, &marker).expect("user fallback");
        assert_eq!(path, user.display().to_string());

        // Neither policy, but the ENFORCE marker is present -> fail CLOSED.
        std::fs::remove_file(&user).unwrap();
        std::fs::write(&marker, "1").unwrap();
        assert!(
            resolve_policy(&machine, &user, &marker).is_err(),
            "ENFORCE marker with no policy must fail closed"
        );

        // Neither policy nor marker -> no enforcement (backwards compatible).
        std::fs::remove_file(&marker).unwrap();
        let (pol, path) = resolve_policy(&machine, &user, &marker)
            .expect("no policy + no marker must be no-enforcement");
        assert_eq!(path, "");
        assert!(!pol.remote_allow.enabled);
    }

    // ── TestRemoteAllowlistFailsClosedOnExecError ───────────────────────────
    #[test]
    fn remote_allowlist_fails_closed_on_exec_error() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = stub_git_query(|_, _| Err(GitError::Failure("context deadline exceeded".into())));

        let (code, blocked) = enforce_remote_allowlist(
            &allowlist_policy(&["internal.example"]),
            &argv(&["push", "origin"]),
            "git",
        );
        assert!(
            blocked && code == 1,
            "an exec failure must FAIL CLOSED (block), got code={code} blocked={blocked}"
        );
    }

    // ── TestRemoteAllowlistFallsThroughOnUnknownRemote ──────────────────────
    #[test]
    fn remote_allowlist_falls_through_on_unknown_remote() {
        let _lock = ENV_LOCK.lock().unwrap();
        // A git-level rejection (unknown remote) — a real *exec.ExitError analog.
        let _g = stub_git_query(|_, _| Err(GitError::Exit));

        let (_c, blocked) = enforce_remote_allowlist(
            &allowlist_policy(&["internal.example"]),
            &argv(&["push", "origin"]),
            "git",
        );
        assert!(
            !blocked,
            "a git-level unknown-remote rejection should fall through to git, not be blocked"
        );
    }

    // ── TestRemoteAllowlistBlocksDisallowedHost ─────────────────────────────
    #[test]
    fn remote_allowlist_blocks_disallowed_host() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = stub_git_query(|_, _| Ok("https://github.com/evil/x".to_string()));

        let (code, blocked) = enforce_remote_allowlist(
            &allowlist_policy(&["internal.example"]),
            &argv(&["push", "origin"]),
            "git",
        );
        assert!(
            blocked && code == 1,
            "push to a non-allowlisted host must be blocked, got code={code} blocked={blocked}"
        );
    }

    // ── TestRemoteAllowlistAllowsApprovedHost ───────────────────────────────
    #[test]
    fn remote_allowlist_allows_approved_host() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = stub_git_query(|_, _| Ok("https://internal.example/team/x".to_string()));

        let (_c, blocked) = enforce_remote_allowlist(
            &allowlist_policy(&["internal.example"]),
            &argv(&["push", "origin"]),
            "git",
        );
        assert!(!blocked, "push to an allowlisted host must be allowed");
    }

    // ── TestRemoteRewriteOverrideBlocked ────────────────────────────────────
    #[test]
    fn remote_rewrite_override_blocked() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = stub_git_query(|_, _| Ok("https://internal.example/team/x".to_string())); // the clean, allowed URL
        let pol = allowlist_policy(&["internal.example"]);

        let cases: &[&[&str]] = &[
            &[
                "-c",
                "url.https://127.0.0.1/.insteadOf=https://internal.example/",
                "push",
                "origin",
                "main",
            ],
            &[
                "-c",
                "remote.origin.pushurl=https://evil.example/x",
                "push",
                "origin",
            ],
            &["--config-env", "url.x.insteadOf=EVIL", "push", "origin"],
            &["--config-env=url.x.pushInsteadOf=EVIL", "push", "origin"],
        ];

        for args in cases {
            let (code, blocked) = enforce_remote_allowlist(&pol, &argv(args), "git");
            assert!(
                blocked && code == 1,
                "rewrite override must block: args={args:?} code={code} blocked={blocked}"
            );
        }
    }

    // ── TestBenignConfigNotBlocked ──────────────────────────────────────────
    #[test]
    fn benign_config_not_blocked() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = stub_git_query(|_, _| Ok("https://internal.example/team/x".to_string()));
        let pol = allowlist_policy(&["internal.example"]);

        let (_c, blocked) = enforce_remote_allowlist(
            &pol,
            &argv(&["-c", "core.pager=less", "push", "origin"]),
            "git",
        );
        assert!(!blocked, "a benign -c override must not be blocked");
    }

    // ── TestRemoteRewriteViaEnv ─────────────────────────────────────────────
    #[test]
    fn remote_rewrite_via_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = stub_git_query(|_, _| Ok("https://internal.example/team/x".to_string()));
        let _env = EnvVarGuard::set("GIT_CONFIG_KEY_0", "url.https://evil/.insteadOf");

        let pol = allowlist_policy(&["internal.example"]);
        let (code, blocked) = enforce_remote_allowlist(&pol, &argv(&["push", "origin"]), "git");
        assert!(
            blocked && code == 1,
            "GIT_CONFIG_KEY rewrite must block: code={code} blocked={blocked}"
        );
    }

    // ── TestAliasInjection ──────────────────────────────────────────────────
    #[test]
    fn alias_injection_cases() {
        let block: &[&[&str]] = &[
            &["-c", "alias.p=push", "p", "origin"], // alias -> gated verb
            &["-c", "alias.x=!git push --force", "x"], // shell alias
            &["-c", "alias.s=send-pack", "s", "evil:repo"], // alias -> plumbing exfil verb
        ];
        for a in block {
            assert!(
                alias_injection(&argv(a)).is_some(),
                "should block alias injection: {a:?}"
            );
        }

        let allow: &[&[&str]] = &[
            &["-c", "alias.co=checkout", "co"], // benign alias, non-gated verb
            &["push", "origin"],                // no alias at all
            &["-c", "core.pager=less", "status"], // unrelated -c override
            &["-c", "alias.p=push", "status"],  // alias defined but NOT the invoked subcommand
        ];
        for a in allow {
            let got = alias_injection(&argv(a));
            assert!(got.is_none(), "should NOT block {a:?} (flagged {got:?})");
        }
    }

    // ── TestSecretScanDirHonorsGlobals ──────────────────────────────────────
    #[test]
    fn secret_scan_dir_honors_globals() {
        let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let cap = captured.clone();
        let _g = stub_git_query(move |_gp, args| {
            *cap.borrow_mut() = args.iter().map(|s| s.to_string()).collect();
            Ok("/resolved/top".to_string())
        });

        let dir = secret_scan_dir(&argv(&["-C", "/repo", "commit", "-m", "x"]), "git");
        assert_eq!(
            dir, "/resolved/top",
            "scan dir should be the git-resolved toplevel"
        );

        let got = captured.borrow();
        assert!(
            got.len() >= 4 && got[0] == "-C" && got[1] == "/repo",
            "the -C global must be forwarded to rev-parse: {got:?}"
        );
        assert_eq!(
            got.last().map(String::as_str),
            Some("--show-toplevel"),
            "expected a rev-parse --show-toplevel query, got {got:?}"
        );
    }

    // ── TestSecretScanDirFallsBackToCwd ─────────────────────────────────────
    #[test]
    fn secret_scan_dir_falls_back_to_cwd() {
        let _g = stub_git_query(|_, _| Err(GitError::Failure("context deadline exceeded".into())));
        assert_eq!(
            secret_scan_dir(&argv(&["commit"]), "git"),
            ".",
            "fallback scan dir should be \".\""
        );
    }

    // ── TestIsExecFailure ───────────────────────────────────────────────────
    #[test]
    fn is_exec_failure_cases() {
        assert!(!is_exec_failure(None), "nil is not a failure");
        assert!(
            is_exec_failure(Some(&GitError::Failure("context deadline exceeded".into()))),
            "a timeout/context error is an exec failure (fail closed)"
        );
        assert!(
            !is_exec_failure(Some(&GitError::Exit)),
            "a git-level non-zero exit is NOT an exec failure (git's verdict)"
        );
    }
}
