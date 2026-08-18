//! Port of Go `sources/git.go` — the git source (M19).
//!
//! Scanning git history is the whole point of a leak scanner: a secret deleted
//! in the current tree is still in the history, and still valid. This source
//! runs `git log -p` (or `git diff`), parses the stream with [`gitdiff`], and
//! yields ONE fragment per hunk containing only that hunk's ADDED lines.
//!
//! ## Deviations from Go, all deliberate
//!
//! * **Serial, not concurrent.** Go fans the per-file work out over a
//!   `semgroup.Group` while ranging the diff channel. This port processes files
//!   in order. The yielded fragments are the same set; only throughput differs.
//! * **Buffered, not streamed.** Go pipes git's stdout straight into an
//!   incremental parser. This port takes git's complete output and parses it,
//!   because [`gitdiff::parse`] is a whole-input parser. On a very large history
//!   that is a real memory cost — recorded in PORT-TRACK.md, not hidden here.
//! * **Archives are skipped.** Go re-reads an archive blob via `git cat-file`
//!   and descends into it. Archive support is deferred workspace-wide (see
//!   `file.rs`), so every binary is skipped. That is a MISSED-FINDING gap (a
//!   secret inside a committed `.zip`), never a false positive.
//! * **stderr is delivered at the end.** Go reads stderr concurrently and can
//!   abort mid-stream; buffered execution means a real git error surfaces after
//!   the fragments that git did manage to emit.
//!
//! Zero third-party dependencies — `gitdiff` and `scm` are sibling ports.

use crate::{
    Fragment, FragmentsFunc, SkipFunc, Source, ATTR_GIT_AUTHOR_EMAIL, ATTR_GIT_AUTHOR_NAME,
    ATTR_GIT_DATE, ATTR_GIT_MESSAGE, ATTR_GIT_PLATFORM, ATTR_GIT_REMOTE_URL, ATTR_GIT_SHA,
    ATTR_PATH, ATTR_RESOURCE, RESOURCE_GIT_PATCH_CONTENT,
};
use std::collections::BTreeMap;
use std::fmt;
use std::process::Command;

/// What can go wrong reaching git.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    /// `--log-opts` could not be tokenised. Go returns this BEFORE spawning git.
    LogOpts(String),
    /// git could not be started at all (not on PATH, permission denied).
    Spawn(String),
    /// git wrote something to stderr that is not a known-benign warning.
    Stderr(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::LogOpts(m) => write!(f, "invalid --log-opts: {m}"),
            GitError::Spawn(m) => write!(f, "{m}"),
            GitError::Stderr(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for GitError {}

// ── the environment git runs in ─────────────────────────────────────────────

/// Go `gitConfigIsolationEnv` — the overrides that stop git reading the user's
/// or the system's configuration.
///
/// Without these, a scan inherits the operator's credential helpers, URL rewrite
/// rules and replace-objects — so it could authenticate as them, or read a
/// different history than the one on disk.
///
/// **Go duplicates this exact set** in `sources/scm/clone.go` as `gitCloneEnv`;
/// the port keeps one copy and reuses it, which is why the values live in `scm`.
pub fn git_config_isolation_env() -> BTreeMap<String, String> {
    scm::git_clone_env(&[])
}

fn apply_isolation(cmd: &mut Command) {
    for (k, v) in git_config_isolation_env() {
        cmd.env(k, v);
    }
}

// ── path cleaning ───────────────────────────────────────────────────────────

/// Number of leading bytes that form a volume name (`C:` on Windows).
///
/// UNC paths (`\\server\share`) are NOT handled — flagged rather than guessed,
/// since a wrong volume length would corrupt the whole cleaned path.
fn volume_name_len(b: &[u8]) -> usize {
    if cfg!(windows) && b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        2
    } else {
        0
    }
}

/// Go `filepath.Clean` — lexical path cleaning, no filesystem access.
///
/// Ported rather than approximated because it decides what `git -C <path>`
/// receives, and because Go's exact rules are load-bearing at the edges: a
/// LEADING `..` survives (it cannot be resolved without knowing the cwd) while a
/// ROOTED `..` is dropped (`/..` is `/`). Like Go, separators are normalised to
/// the platform's.
pub fn clean_path(path: &str) -> String {
    let is_sep = |c: u8| c == b'/' || (cfg!(windows) && c == b'\\');
    let sep: u8 = if cfg!(windows) { b'\\' } else { b'/' };

    let bytes = path.as_bytes();
    let vol = volume_name_len(bytes);
    let (volume, rest) = bytes.split_at(vol);
    let mut prefix = String::from_utf8_lossy(volume).into_owned();

    if rest.is_empty() {
        prefix.push('.');
        return prefix;
    }

    let rooted = is_sep(rest[0]);
    let n = rest.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut r = 0usize;
    // Everything before `dotdot` is fixed: either the root, or leading `..`
    // segments that can never be cancelled.
    let mut dotdot = 0usize;
    if rooted {
        out.push(sep);
        r = 1;
        dotdot = 1;
    }

    while r < n {
        if is_sep(rest[r]) {
            // empty path element
            r += 1;
        } else if rest[r] == b'.' && (r + 1 == n || is_sep(rest[r + 1])) {
            // "." element
            r += 1;
        } else if rest[r] == b'.'
            && r + 1 < n
            && rest[r + 1] == b'.'
            && (r + 2 == n || is_sep(rest[r + 2]))
        {
            // ".." element — back up over the previous one
            r += 2;
            if out.len() > dotdot {
                // Drop the last element AND the separator in front of it.
                let mut w = out.len() - 1;
                while w > dotdot && !is_sep(out[w]) {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                // Nothing to back up over, and no root to absorb it: keep it.
                if !out.is_empty() {
                    out.push(sep);
                }
                out.push(b'.');
                out.push(b'.');
                dotdot = out.len();
            }
            // A rooted ".." with nothing to cancel is simply discarded.
        } else {
            // A real path element — copy it.
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(sep);
            }
            while r < n && !is_sep(rest[r]) {
                out.push(rest[r]);
                r += 1;
            }
        }
    }

    if out.is_empty() {
        out.push(b'.');
    }
    prefix.push_str(&String::from_utf8_lossy(&out));
    prefix
}

// ── --log-opts tokenizer ────────────────────────────────────────────────────

/// Go `splitGitLogOpts` — a small shell-inspired tokenizer for `--log-opts`.
///
/// Intentionally NOT a shell: no variable expansion, command substitution or
/// globbing. Whitespace splits unless quoted; single and double quotes group and
/// are removed; a backslash escapes the next character OUTSIDE single quotes.
///
/// Quirk kept from the source: a standalone empty quoted token (`''`) is dropped
/// rather than becoming an empty argument.
pub fn split_git_log_opts(input: &str) -> Result<Vec<String>, GitError> {
    let mut args: Vec<String> = Vec::new();
    let mut curr = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            curr.push(ch);
            escaped = false;
        } else if ch == '\\' && !in_single {
            escaped = true;
        } else if ch == '\'' && !in_double {
            in_single = !in_single;
        } else if ch == '"' && !in_single {
            in_double = !in_double;
        } else if ch.is_whitespace() && !in_single && !in_double {
            if !curr.is_empty() {
                args.push(std::mem::take(&mut curr));
            }
        } else {
            curr.push(ch);
        }
    }

    if escaped {
        return Err(GitError::LogOpts("unterminated escape in --log-opts".to_string()));
    }
    if in_single || in_double {
        return Err(GitError::LogOpts("unterminated quote in --log-opts".to_string()));
    }
    if !curr.is_empty() {
        args.push(curr);
    }
    Ok(args)
}

// ── argument construction ───────────────────────────────────────────────────

/// Go `NewGitLogCmdContext`'s argument list.
///
/// `-U0` means ZERO context lines. That is what makes each hunk contain only
/// changed lines, so a secret is attributed to the commit that introduced it
/// instead of being re-reported as context on every commit that touched the
/// file afterwards.
///
/// With no `--log-opts`, the defaults scan `--full-history --all` filtered to
/// `--diff-filter=tuxdb` (types, unmerged, unknown, deleted, broken). User opts
/// REPLACE that range rather than extending it.
pub fn git_log_args(source: &str, log_opts: &str) -> Result<Vec<String>, GitError> {
    let clean = clean_path(source);
    let mut args = vec![
        "-C".to_string(),
        clean,
        "log".to_string(),
        "-p".to_string(),
        "-U0".to_string(),
    ];
    if log_opts.is_empty() {
        args.push("--full-history".to_string());
        args.push("--all".to_string());
        args.push("--diff-filter=tuxdb".to_string());
    } else {
        args.extend(split_git_log_opts(log_opts)?);
    }
    Ok(args)
}

/// Go `NewGitDiffCmdContext`'s argument list — the working tree (or the index).
///
/// `--no-ext-diff` disables any external diff driver, which could otherwise run
/// arbitrary configured commands during a scan.
pub fn git_diff_args(source: &str, staged: bool) -> Vec<String> {
    let mut args = vec![
        "-C".to_string(),
        clean_path(source),
        "diff".to_string(),
        "-U0".to_string(),
        "--no-ext-diff".to_string(),
    ];
    if staged {
        args.push("--staged".to_string());
    }
    args.push(".".to_string());
    args
}

// ── stderr classification ───────────────────────────────────────────────────

/// Go `listenForStdErr`'s tolerated-warning list.
///
/// git writes these to stderr and KEEPS STREAMING the diff. Treating them as
/// fatal would abort a whole-history scan partway and report the partial result
/// as clean — the worst failure mode a secret scanner has.
pub fn is_benign_stderr(line: &str) -> bool {
    line.contains("exhaustive rename detection was skipped")
        || line.contains("inexact rename detection was skipped")
        || line.contains("you may want to set your diff.renameLimit")
        || line.contains("See \"git help gc\" for manual housekeeping")
        || line.contains("Auto packing the repository in background for optimum performance")
}

/// Go's `fmt.Errorf("git stderr: %s", strings.Join(errLines, "; "))` — `None`
/// when every line was benign (or there were none).
pub fn stderr_error(lines: &[&str]) -> Option<String> {
    let real: Vec<&str> = lines.iter().copied().filter(|l| !is_benign_stderr(l)).collect();
    if real.is_empty() {
        None
    } else {
        Some(format!("git stderr: {}", real.join("; ")))
    }
}

// ── remote resolution ───────────────────────────────────────────────────────

/// Go's `sshUrlpat` rewrite + `.git` trim + userinfo removal, as one function.
///
/// `git@host:owner/repo.git` becomes `https://host/owner/repo`. Any `user:pass@`
/// is dropped, because this URL is embedded in finding links — a remote
/// configured with an inline token must not turn the report itself into a leak.
///
/// Returns `None` when there is no usable URL.
pub fn normalize_remote_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // Go: ^git@([a-zA-Z0-9.-]+):(?:\d{1,5}/)?([\w/.-]+?)(?:\.git)?$
    let url = if let Some(rest) = raw.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return None;
        }
        // An optional ssh port is consumed and DISCARDED, matching the Go
        // pattern's non-capturing group.
        let path = match path.split_once('/') {
            Some((maybe_port, rest))
                if !maybe_port.is_empty()
                    && maybe_port.len() <= 5
                    && maybe_port.chars().all(|c| c.is_ascii_digit()) =>
            {
                rest
            }
            _ => path,
        };
        if path.is_empty() {
            return None;
        }
        format!("https://{host}/{path}")
    } else {
        raw.to_string()
    };

    let url = url.strip_suffix(".git").unwrap_or(&url).to_string();

    // Strip userinfo: scheme://user:pass@host/... -> scheme://host/...
    let cleaned = match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('/') {
            Some((authority, path)) => match authority.rsplit_once('@') {
                Some((_, host)) => format!("{scheme}://{host}/{path}"),
                None => url.clone(),
            },
            None => match rest.rsplit_once('@') {
                Some((_, host)) => format!("{scheme}://{host}"),
                None => url.clone(),
            },
        },
        None => url.clone(),
    };

    Some(cleaned)
}

/// Go `platformFromHost` — a known SCM host, or `Unknown`.
///
/// `Unknown` is honest: a self-hosted GitLab is not guessed at, because a wrong
/// platform produces a broken finding link.
pub fn platform_from_host(host: &str) -> scm::Platform {
    match host.to_lowercase().as_str() {
        "github.com" => scm::Platform::GitHub,
        "gitlab.com" => scm::Platform::GitLab,
        "dev.azure.com" | "visualstudio.com" => scm::Platform::AzureDevOps,
        "gitea.com" | "code.forgejo.org" | "codeberg.org" => scm::Platform::Gitea,
        "bitbucket.org" => scm::Platform::Bitbucket,
        _ => scm::Platform::Unknown,
    }
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or("");
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    // Drop a port, and the brackets of an IPv6 literal.
    match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    }
}

/// Go `ResolveRemote` — ask git for the first remote's URL and derive the
/// platform from its host.
///
/// A repository with NO remote is not an error: the platform becomes `None` and
/// findings simply carry no links.
pub fn resolve_remote(platform: scm::Platform, source: &str) -> (scm::Platform, String) {
    if platform == scm::Platform::None {
        return (platform, String::new());
    }

    let mut cmd = Command::new("git");
    cmd.args(["ls-remote", "--quiet", "--get-url"]);
    apply_isolation(&mut cmd);
    if source != "." {
        cmd.current_dir(source);
    }

    let out = match cmd.output() {
        Ok(o) => o,
        Err(_) => return (platform, String::new()),
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("No remote configured") {
            return (scm::Platform::None, String::new());
        }
        return (platform, String::new());
    }

    let url = match normalize_remote_url(&String::from_utf8_lossy(&out.stdout)) {
        Some(u) => u,
        None => return (platform, String::new()),
    };

    let platform = if platform == scm::Platform::Unknown {
        platform_from_host(host_of(&url))
    } else {
        platform
    };
    (platform, url)
}

// ── commit dates ────────────────────────────────────────────────────────────

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`). Exact for all years, leap rules included.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse git's default `Date:` format and render it as RFC 3339 in UTC.
///
/// Go gets this for free: `go-gitdiff` parses the header into a `time.Time` and
/// `git.go` formats `AuthorDate.UTC().Format(time.RFC3339)`. Reproducing it here
/// is a small self-contained slice rather than a date-library dependency —
/// git's own default format is fixed (`Mon Jan 2 15:04:05 2006 -0700`), and the
/// config that could change it is exactly what the isolation environment
/// disables.
///
/// Normalising to UTC matters: otherwise a finding's timestamp depends on the
/// committer's timezone, and two findings from the same moment sort differently.
pub fn parse_git_date(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    // parts[0] is the day-of-week, which carries no information we need.
    let month = MONTHS.iter().position(|m| *m == parts[1])? as i64 + 1;
    let day: i64 = parts[2].parse().ok()?;
    if !(1..=31).contains(&day) {
        return None;
    }

    let hms: Vec<&str> = parts[3].split(':').collect();
    if hms.len() != 3 {
        return None;
    }
    let hour: i64 = hms[0].parse().ok()?;
    let min: i64 = hms[1].parse().ok()?;
    let sec: i64 = hms[2].parse().ok()?;
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }

    let year: i64 = parts[4].parse().ok()?;

    // Offset: +HHMM / -HHMM.
    let off = parts[5].as_bytes();
    if off.len() != 5 || (off[0] != b'+' && off[0] != b'-') {
        return None;
    }
    let off_h: i64 = parts[5][1..3].parse().ok()?;
    let off_m: i64 = parts[5][3..5].parse().ok()?;
    let mut off_secs = off_h * 3600 + off_m * 60;
    if off[0] == b'-' {
        off_secs = -off_secs;
    }

    // Local wall clock -> epoch seconds -> UTC wall clock.
    let epoch = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec - off_secs;
    let days = epoch.div_euclid(86_400);
    let rem = epoch.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    Some(format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    ))
}

// ── the source ──────────────────────────────────────────────────────────────

/// Go `sources.Git` — yields fragments from a git repository.
pub struct Git<'a> {
    /// The parsed diff. Go holds a channel fed by a running git process; this
    /// port holds the already-parsed result (see the module docs).
    pub files: Vec<gitdiff::File>,
    /// The SCM platform, used only to label findings.
    pub platform: scm::Platform,
    /// The remote URL, used only to build finding links. Empty means none.
    pub remote_url: String,
    /// Archive descent depth. Always effectively 0 — archives are deferred.
    pub max_archive_depth: usize,
    /// Prefilter consulted with a file's commit attributes BEFORE any fragment
    /// is built. Returns true to SKIP.
    pub should_skip: Option<SkipFunc<'a>>,
    /// A real (non-benign) git stderr, surfaced after the fragments.
    pub stderr: Option<String>,
}

impl<'a> Git<'a> {
    /// Build a source from an already-captured diff. This is what the tests
    /// drive, and what a caller with a diff from elsewhere uses.
    pub fn from_diff_text(text: &str) -> Git<'a> {
        Git {
            files: gitdiff::parse(text),
            platform: scm::Platform::Unknown,
            remote_url: String::new(),
            max_archive_depth: 0,
            should_skip: None,
            stderr: None,
        }
    }

    /// Go `NewGitLogCmdContext` — run `git log -p` over a repository's history.
    ///
    /// Like Go, a git process that STARTS but then fails is not an error here:
    /// the failure surfaces through [`Source::fragments`], because git may have
    /// emitted usable output before failing.
    pub fn from_log(source: &str, log_opts: &str) -> Result<Git<'a>, GitError> {
        Self::run(git_log_args(source, log_opts)?)
    }

    /// Go `NewGitDiffCmdContext` — diff the working tree (or the index).
    pub fn from_diff(source: &str, staged: bool) -> Result<Git<'a>, GitError> {
        Self::run(git_diff_args(source, staged))
    }

    /// Go `newGitLogCommitsCmd` — `git log -p --no-walk --stdin` over an
    /// explicit set of commits.
    ///
    /// The SHAs go in on STDIN rather than the command line, which is the only
    /// form that scales: a partition of a large repository is tens of thousands
    /// of SHAs, far past any platform's argument limit — and on Windows that
    /// limit is low enough to hit on an ordinary repository.
    ///
    /// `--no-walk` is what makes the partition exact: without it each SHA would
    /// pull in its ancestors and the workers would scan overlapping history.
    pub fn from_log_commits(source: &str, commits: &[String]) -> Result<Git<'a>, GitError> {
        use std::io::Write;

        let clean = clean_path(source);
        let mut cmd = Command::new("git");
        cmd.args([
            "-C",
            &clean,
            "log",
            "-p",
            "-U0",
            "--no-walk",
            "--stdin",
            "--diff-filter=tuxdb",
        ]);
        apply_isolation(&mut cmd);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        logging::debug().msg(&format!(
            "executing: git -C {clean} log -p -U0 --no-walk --stdin ({} commits via stdin)",
            commits.len()
        ));

        let mut child = cmd
            .spawn()
            .map_err(|e| GitError::Spawn(format!("failed to start git: {e}")))?;

        // The SHAs are written from a THREAD. git streams its output while it
        // reads, so writing them inline would deadlock the moment the output
        // pipe fills — which it does immediately on any real repository.
        let shas: Vec<String> = commits.to_vec();
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| GitError::Spawn("git stdin unavailable".to_string()))?;
        let writer = std::thread::spawn(move || {
            for sha in &shas {
                if writeln!(stdin, "{sha}").is_err() {
                    // git exited early; there is nothing useful to do and the
                    // real error comes from its stderr.
                    return;
                }
            }
        });

        let out = child
            .wait_with_output()
            .map_err(|e| GitError::Spawn(format!("git failed: {e}")))?;
        let _ = writer.join();

        let stderr_text = String::from_utf8_lossy(&out.stderr).into_owned();
        let lines: Vec<&str> = stderr_text.lines().collect();
        let stdout = String::from_utf8_lossy(&out.stdout);

        let mut g = Git::from_diff_text(&stdout);
        g.stderr = stderr_error(&lines);
        Ok(g)
    }

    /// Run an arbitrary `git` invocation and return its stdout.
    ///
    /// Used by the parallel source's `rev-list`. Separate from [`Git::run`]
    /// because that one parses a diff; this one just needs the bytes.
    pub fn output(args: &[String]) -> Result<String, GitError> {
        let mut cmd = Command::new("git");
        cmd.args(args);
        apply_isolation(&mut cmd);
        let out = cmd
            .output()
            .map_err(|e| GitError::Spawn(format!("failed to start git: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let lines: Vec<&str> = stderr.lines().collect();
            if let Some(msg) = stderr_error(&lines) {
                return Err(GitError::Stderr(msg));
            }

            return Err(GitError::Spawn(format!(
                "git exited with {}",
                out.status
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn run(args: Vec<String>) -> Result<Git<'a>, GitError> {
        let mut cmd = Command::new("git");
        cmd.args(&args);
        apply_isolation(&mut cmd);
        let out = cmd
            .output()
            .map_err(|e| GitError::Spawn(format!("failed to start git: {e}")))?;

        let stderr_text = String::from_utf8_lossy(&out.stderr).into_owned();
        let lines: Vec<&str> = stderr_text.lines().collect();

        // git's diff output is not guaranteed to be UTF-8 — a committed file can
        // hold any bytes. Lossy conversion keeps the scan running; the
        // replacement char cannot create a false match, only mask a byte
        // sequence that was not text to begin with.
        let stdout = String::from_utf8_lossy(&out.stdout);

        let mut g = Git::from_diff_text(&stdout);
        g.stderr = stderr_error(&lines);
        Ok(g)
    }

    /// Go `(*GitCmd).NewBlobReaderContext` — read one blob out of the
    /// repository. Go uses this only for archive descent; kept because it is the
    /// seam archive support will plug into.
    pub fn read_blob(repo: &str, commit: &str, path: &str) -> Result<Vec<u8>, GitError> {
        let mut cmd = Command::new("git");
        cmd.args([
            "-C",
            &clean_path(repo),
            "cat-file",
            "blob",
            &format!("{commit}:{path}"),
        ]);
        apply_isolation(&mut cmd);
        let out = cmd
            .output()
            .map_err(|e| GitError::Spawn(format!("failed to start git: {e}")))?;
        if !out.status.success() {
            return Err(GitError::Stderr(format!(
                "git cat-file blob {commit}:{path}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }
}

impl Source for Git<'_> {
    type Error = GitError;

    fn fragments(&self, yield_fn: FragmentsFunc<'_, Self::Error>) -> Result<(), Self::Error> {
        for file in &self.files {
            // A file removed by this commit introduces nothing.
            if file.is_delete {
                continue;
            }
            // Binary: Go descends into it when it is an archive. Not here.
            if file.is_binary {
                continue;
            }

            // Commit attributes are built ONCE per file, and — matching Go —
            // only when there is a commit header at all. A plain `git diff` of
            // the working tree has none.
            let mut commit_attrs: BTreeMap<String, String> = BTreeMap::new();
            if let Some(h) = &file.patch_header {
                commit_attrs.insert(ATTR_GIT_SHA.to_string(), h.sha.clone());
                commit_attrs.insert(ATTR_GIT_MESSAGE.to_string(), h.message.clone());
                commit_attrs.insert(
                    ATTR_RESOURCE.to_string(),
                    RESOURCE_GIT_PATCH_CONTENT.to_string(),
                );
                commit_attrs.insert(ATTR_PATH.to_string(), file.new_name.clone());
                if !self.remote_url.is_empty() {
                    commit_attrs.insert(ATTR_GIT_REMOTE_URL.to_string(), self.remote_url.clone());
                    commit_attrs
                        .insert(ATTR_GIT_PLATFORM.to_string(), self.platform.to_string());
                }
                if let Some(date) = parse_git_date(&h.author_date) {
                    commit_attrs.insert(ATTR_GIT_DATE.to_string(), date);
                }
                if !h.author_name.is_empty() || !h.author_email.is_empty() {
                    commit_attrs
                        .insert(ATTR_GIT_AUTHOR_NAME.to_string(), h.author_name.clone());
                    commit_attrs
                        .insert(ATTR_GIT_AUTHOR_EMAIL.to_string(), h.author_email.clone());
                }

                // The prefilter runs here — before any fragment memory is
                // allocated. Note it is INSIDE the header branch, exactly as in
                // Go: a headerless diff is never prefiltered.
                if let Some(skip) = self.should_skip {
                    if skip(&commit_attrs) {
                        continue;
                    }
                }
            }

            for tf in &file.text_fragments {
                // Go clones nothing here — every fragment of a file shares one
                // attribute map. Cloning per fragment is observably identical
                // (the only later write sets the same path) and avoids handing
                // out aliased state.
                let mut fragment = Fragment {
                    raw: tf.raw(gitdiff::Op::Add),
                    start_line: tf.new_position,
                    attributes: commit_attrs.clone(),
                    ..Default::default()
                };
                fragment.set_attr(ATTR_PATH, &file.new_name);
                yield_fn(Ok(fragment))?;
            }
        }

        // Buffered execution means a real git error arrives after whatever git
        // did manage to emit, rather than aborting mid-stream as in Go.
        if let Some(err) = &self.stderr {
            return yield_fn(Err(GitError::Stderr(err.clone())));
        }
        Ok(())
    }
}
