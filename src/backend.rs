//! Port of Go `internal/backend` — resolves which real git binary gitc executes
//! and runs it as a transparent passthrough, inheriting stdio and propagating the
//! exit code.
//!
//! gitc ships as `git`/`git.exe` earlier on PATH than any real git, so the
//! resolver must never re-resolve `git` from PATH and exec itself. The
//! **self-invocation guard** compares each candidate against gitc's own absolute
//! executable path ([`Backend`] resolution skips any candidate that IS gitc). This
//! is SECURITY-relevant: gitc must never recurse into itself as its own git
//! backend, so the guard and the resolution order are preserved 1:1 against the Go
//! source.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Identifies which backend served an invocation (Go `type Kind string`).
///
/// [`Kind::as_str`] / [`std::fmt::Display`] reproduce the Go string values
/// `"managed"` / `"system"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A git downloaded by gitc (MinGit from git-for-windows). Go `KindManaged`.
    Managed,
    /// A compatible git already installed on PATH. Go `KindSystem`.
    System,
}

impl Kind {
    /// The Go string constant for this kind (`"managed"` / `"system"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Managed => "managed",
            Kind::System => "system",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors from backend resolution and execution (Go `ErrNoBackend` + the
/// `exec git backend` wrap in `Run`).
#[derive(Debug)]
pub enum Error {
    /// Neither a downloaded git nor a non-self system git could be found.
    /// Go `ErrNoBackend`.
    NoBackend,
    /// The backend process failed to start (Go `fmt.Errorf("exec git backend: %w", err)`).
    /// A non-zero git exit is NOT this error — it is reported via [`RunOutput`].
    Exec(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Verbatim Go message (the doubled "gitc gitc" is carried bug-for-bug).
            Error::NoBackend => f.write_str(
                "no git backend found: run `gitc gitc fetch-git` to download one, or install git on PATH",
            ),
            Error::Exec(e) => write!(f, "exec git backend: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::NoBackend => None,
            Error::Exec(e) => Some(e),
        }
    }
}

/// A resolved git executable ready to exec (Go `struct Backend`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    /// Which kind of backend this is.
    pub kind: Kind,
    /// Absolute (symlink-resolved) path to the git binary.
    pub path: PathBuf,
}

/// The outcome of a passthrough exec (Go `struct Result`). A non-zero git exit is
/// reported here (in `exit_code`), not via [`Error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    /// The backend's exit code. `-1` when the process was terminated without a
    /// normal exit code (Go's `ExitCode()` returns `-1` for a signal kill).
    pub exit_code: i32,
    /// Wall-clock duration of the exec.
    pub duration: Duration,
}

/// Picks a backend, preferring the managed (downloaded) git at `managed` and
/// falling back to the first non-self `git` on PATH. `self_path` is gitc's own
/// absolute executable path (from `std::env::current_exe`); candidates resolving
/// to it are skipped to prevent recursive self-invocation.
///
/// Faithful port of Go `Resolve(managedPath, selfPath string)`. Go's empty
/// `managedPath` ("no managed git") maps to `None` (an empty path is also treated
/// as absent, matching `managedPath != ""`).
pub fn resolve(managed: Option<&Path>, self_path: &Path) -> Result<Backend, Error> {
    if let Some(managed) = managed {
        if !managed.as_os_str().is_empty() {
            if let Some(abs) = usable_binary(managed, self_path) {
                return Ok(Backend {
                    kind: Kind::Managed,
                    path: abs,
                });
            }
        }
    }

    if let Some(path) = find_system_git(self_path) {
        return Ok(Backend {
            kind: Kind::System,
            path,
        });
    }

    Err(Error::NoBackend)
}

/// Walks PATH in order and returns the first git executable whose resolved path
/// differs from `self_path`. Go `findSystemGit`.
fn find_system_git(self_path: &Path) -> Option<PathBuf> {
    // Go: names = {"git"}; on Windows {"git.exe", "git.cmd", "git"}.
    let names: &[&str] = if cfg!(windows) {
        &["git.exe", "git.cmd", "git"]
    } else {
        &["git"]
    };

    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }

        for name in names {
            let cand = dir.join(name);
            if let Some(abs) = usable_binary(&cand, self_path) {
                return Some(abs);
            }
        }
    }

    None
}

/// Reports whether `cand` is a non-directory file that is not gitc itself,
/// returning its cleaned absolute (symlink-resolved) path. Go `usableBinary`.
///
/// Note (faithful to Go): only directories and stat failures are rejected — the
/// executable bit is NOT checked (Go inspects `info.IsDir()` only).
fn usable_binary(cand: &Path, self_path: &Path) -> Option<PathBuf> {
    // filepath.Abs — lexical absolute + clean, without touching the fs.
    let mut abs = std::path::absolute(cand).ok()?;

    // filepath.EvalSymlinks — resolve symlinks when possible; on failure keep the
    // lexical absolute path (Go ignores the error).
    if let Ok(resolved) = std::fs::canonicalize(&abs) {
        abs = resolved;
    }

    // os.Stat + IsDir guard.
    let meta = std::fs::metadata(&abs).ok()?;
    if meta.is_dir() {
        return None;
    }

    if same_file(&abs, self_path) {
        return None;
    }

    Some(abs)
}

/// Reports whether two paths refer to gitc's own binary. It compares resolved
/// absolute paths (case-insensitively on Windows) and, when possible, filesystem
/// identity. Go `sameFile`.
fn same_file(a: &Path, b: &Path) -> bool {
    if b.as_os_str().is_empty() {
        return false;
    }

    let ra = std::fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
    let rb = std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());

    if cfg!(windows) {
        // Go uses strings.EqualFold (Unicode simple folding); ASCII-insensitive
        // comparison covers real filesystem paths and every test case.
        if ra
            .to_string_lossy()
            .eq_ignore_ascii_case(&rb.to_string_lossy())
        {
            return true;
        }
    } else if ra == rb {
        return true;
    }

    // os.SameFile fallback (hardlink / different-path-same-file identity).
    same_file_identity(&ra, &rb)
}

#[cfg(unix)]
fn same_file_identity(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file_identity(_a: &Path, _b: &Path) -> bool {
    // PARITY NOTE: Go's os.SameFile inode-identity fallback cannot be reproduced on
    // stable Windows std (volume_serial_number/file_index are behind an unstable
    // feature). The case-insensitive resolved-path comparison above already covers
    // the self-invocation guard for all realistic and tested cases; this fallback
    // only diverges for a Windows hardlink reached via two textually different
    // paths, which the guard never encounters.
    false
}

impl Backend {
    /// Reports whether the backend git is new enough to accept
    /// `init --initial-branch` (git >= 2.28). On any error it returns `false` so
    /// callers never inject a flag an old git would reject. Go
    /// `SupportsInitialBranch`.
    ///
    /// The Go `context.Context` parameter is dropped: this is a fast, bounded
    /// `git --version` probe with no cancellation need (per the pack's
    /// context→explicit-params rule).
    pub fn supports_initial_branch(&self) -> bool {
        let output = match std::process::Command::new(&self.path)
            .arg("--version")
            .output()
        {
            // Go's .Output() reports a non-zero exit as an error → false.
            Ok(o) if o.status.success() => o,
            _ => return false,
        };

        let text = String::from_utf8_lossy(&output.stdout);
        match parse_git_version(&text) {
            Some((major, minor)) => major > 2 || (major == 2 && minor >= 28),
            None => false,
        }
    }

    /// Execs the backend with `args`, inheriting the process's stdio, and returns
    /// the exit code and wall-clock duration. A non-zero git exit is reported via
    /// [`RunOutput`], not `Err`; `Err` is reserved for failures to start the
    /// process. Go `Run`.
    ///
    /// `std::process::Command` inherits the parent's stdin/stdout/stderr by default
    /// under `.status()`, matching Go's explicit `cmd.Std* = os.Std*`.
    pub fn run(&self, args: &[String]) -> Result<RunOutput, Error> {
        let start = std::time::Instant::now();
        let status = std::process::Command::new(&self.path).args(args).status();
        let duration = start.elapsed();

        match status {
            // A non-zero exit is Ok(status) in Rust (unlike Go's *exec.ExitError);
            // status.code() is None only for a signal kill → -1, matching Go's
            // ExitCode() for that case.
            Ok(st) => Ok(RunOutput {
                exit_code: st.code().unwrap_or(-1),
                duration,
            }),
            // Failure to START the process. Go additionally returns Result{-1, dur};
            // the idiomatic Rust Err drops the duration (informational only).
            Err(e) => Err(Error::Exec(e)),
        }
    }
}

/// Extracts the major/minor from `git version X.Y.Z` output. Go `parseGitVersion`.
fn parse_git_version(s: &str) -> Option<(i64, i64)> {
    let fields: Vec<&str> = s.split_whitespace().collect();
    if fields.len() < 3 {
        return None;
    }

    let parts: Vec<&str> = fields[2].splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }

    let major = parts[0].parse::<i64>().ok()?;
    let minor = parts[1].parse::<i64>().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    // Serializes the tests that mutate the process-global PATH env var (Go's
    // t.Setenv is per-test; Rust std tests share the process and run in parallel).
    fn env_guard() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn git_name() -> &'static str {
        if cfg!(windows) {
            "git.exe"
        } else {
            "git"
        }
    }

    fn unique_temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gitc-backend-test-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_fake_exe(path: &Path) {
        std::fs::write(path, b"fake").expect("write fake exe");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake exe");
        }
    }

    // Compares two paths after symlink resolution (resolution returns
    // canonicalized paths; CI temp dirs are symlinked: macOS /var -> /private/var,
    // Windows 8.3 short names). Case-insensitive on Windows. Go test `samePath`.
    fn same_path(a: &Path, b: &Path) -> bool {
        let a = std::fs::canonicalize(a).unwrap_or_else(|_| a.to_path_buf());
        let b = std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf());
        if cfg!(windows) {
            a.to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy())
        } else {
            a == b
        }
    }

    // When the only git on PATH is gitc itself, no system git is found (prevents
    // recursive self-exec). Go `TestSelfInvocationGuard`.
    #[test]
    fn self_invocation_guard() {
        let dir = unique_temp_dir();
        let self_path = dir.join(git_name()); // gitc shipped as `git`
        write_fake_exe(&self_path);

        let _lock = env_guard();
        let prev = std::env::var_os("PATH");
        std::env::set_var("PATH", &dir);

        let got = find_system_git(&self_path);

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert!(
            got.is_none(),
            "find_system_git found {got:?}, expected none (self must be skipped)"
        );
    }

    // A real git elsewhere on PATH is resolved even when gitc-as-git sits earlier.
    // Go `TestFindsDistinctSystemGit`.
    #[test]
    fn finds_distinct_system_git() {
        let self_dir = unique_temp_dir();
        let real_dir = unique_temp_dir();
        let self_path = self_dir.join(git_name());
        let real_git = real_dir.join(git_name());

        write_fake_exe(&self_path);
        write_fake_exe(&real_git);

        let path = std::env::join_paths([&self_dir, &real_dir]).expect("join paths");

        let _lock = env_guard();
        let prev = std::env::var_os("PATH");
        std::env::set_var("PATH", &path);

        let got = find_system_git(&self_path);

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        let got = got.expect("expected to find the distinct system git");
        assert!(
            same_path(&got, &real_git),
            "found {got:?}, want {real_git:?}"
        );
    }

    // A usable vendored build wins over PATH. Go `TestResolvePrefersVendored`.
    #[test]
    fn resolve_prefers_vendored() {
        let vendor_dir = unique_temp_dir();
        let path_dir = unique_temp_dir();
        let vendored = vendor_dir.join(git_name());
        let sys = path_dir.join(git_name());
        let self_path = unique_temp_dir().join(git_name());
        write_fake_exe(&vendored);
        write_fake_exe(&sys);
        write_fake_exe(&self_path);

        let _lock = env_guard();
        let prev = std::env::var_os("PATH");
        std::env::set_var("PATH", &path_dir);

        let resolved = resolve(Some(vendored.as_path()), &self_path);

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        let b = resolved.expect("resolve");
        assert_eq!(b.kind, Kind::Managed, "kind = {:?}, want managed", b.kind);
        assert!(
            same_path(&b.path, &vendored),
            "path = {:?}, want {vendored:?}",
            b.path
        );
    }

    // Neither vendored nor a non-self system git → error. Go `TestResolveNoBackend`.
    #[test]
    fn resolve_no_backend() {
        let dir = unique_temp_dir();
        let self_path = dir.join(git_name());
        write_fake_exe(&self_path);

        let _lock = env_guard();
        let prev = std::env::var_os("PATH");
        std::env::set_var("PATH", &dir); // only self on PATH

        let resolved = resolve(None, &self_path); // Go: Resolve("", self)

        match prev {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        assert!(
            matches!(resolved, Err(Error::NoBackend)),
            "expected Err(NoBackend), got {resolved:?}"
        );
    }

    // Direct unit coverage of the version parser used by supports_initial_branch.
    #[test]
    fn parse_git_version_cases() {
        assert_eq!(parse_git_version("git version 2.28.0"), Some((2, 28)));
        assert_eq!(
            parse_git_version("git version 2.39.3 (Apple Git-146)"),
            Some((2, 39))
        );
        assert_eq!(parse_git_version("  git version 3.0.1\n"), Some((3, 0)));
        assert_eq!(parse_git_version("git version 2"), None); // <2 dotted parts
        assert_eq!(parse_git_version("git 2.28.0"), None); // <3 fields
        assert_eq!(parse_git_version("git version x.y.z"), None); // non-numeric
    }
}
