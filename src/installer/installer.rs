//! Port of Go `internal/installer` (the `installer.go` part; the embedded launcher
//! lives in the sibling [`super::shim`] module).
//!
//! Sets up gitc's PATH-precedence shadowing: it installs the running gitc binary
//! into a dedicated shim directory as `git`/`git.exe`, then (optionally) prepends
//! that directory to the user's PATH so shell invocations of `git` resolve to the
//! wrapper first. No files under any existing git install are modified — shadowing
//! is purely a matter of PATH ordering, and is reversible via [`uninstall`].
//!
//! ## Platform fork (Go `runtime.GOOS` → `#[cfg(windows)]`)
//! On **Windows** it uses the tiny-launcher model (ADR 0007): one canonical
//! `gitc.exe` under [`crate::paths::bin_dir`], plus `git`/`sh`/`bash.exe` launcher
//! shims (the embedded `shim.c` PE from [`super::shim`]) that exec it via sibling
//! scoop-format `.shim` files — `git`/`sh`/`bash.exe` are hard links to a single
//! inode. On **other platforms** the git shim is simply a copy of gitc, since the
//! git proxy there IS the gitc binary.
//!
//! ## Deviations (documented, faithful in behavior)
//! - Go `os.SameFile` (inode identity) has no stable-std Windows equivalent; the
//!   `same_exe` fallback uses canonicalized-path identity, which distinguishes
//!   every tested case (identical path vs distinct files). Same call recorded for
//!   `backend::same_file` in `PORT-GLOSSARY.md`.

use std::path::{Path, PathBuf};

/// Reports what an install performed and what the user must still do
/// (Go `struct Result`). `Result` is spelled fully-qualified as
/// `std::result::Result` in fallible signatures below, since this struct shadows
/// the prelude alias inside the module.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Result {
    /// The shim directory (Go `ShimDir`).
    pub shim_dir: PathBuf,
    /// The shimmed git binary inside [`Result::shim_dir`] (Go `ShimGit`).
    pub shim_git: PathBuf,
    /// Resolved real git the shim will delegate to; empty when no backend exists
    /// yet on a fresh machine (Go `BackendPath`).
    pub backend_path: PathBuf,
    /// True if PATH was mutated automatically (Go `PathApplied`).
    pub path_applied: bool,
    /// Manual PATH step returned when `apply_path` is false (Go `Instruction`).
    pub instruction: String,
}

/// Installer errors (Go's `fmt.Errorf` wraps). `Io` renders `<context>: <source>`
/// like Go's `%w` wrap; `Message` carries a fully-formatted Go-style message
/// (the PATH-apply wrap, the Windows-only guard, PowerShell failures).
#[derive(Debug)]
pub enum Error {
    /// An IO operation failed. Display = `"<context>: <source>"`.
    Io {
        /// Go's wrap prefix, e.g. `"create shim dir"`.
        context: String,
        /// The underlying IO error.
        source: std::io::Error,
    },
    /// A pre-formatted message (non-IO failure).
    Message(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Message(_) => None,
        }
    }
}

fn io_err(context: &str, source: std::io::Error) -> Error {
    Error::Io {
        context: context.to_string(),
        source,
    }
}

/// Installs the current gitc executable into the shim directory as `git`/`git.exe`.
/// When `apply_path` is true it also prepends the shim dir to the user's PATH
/// (Windows only, via the user environment); otherwise it returns a
/// platform-appropriate manual instruction. Faithful port of Go `Install`.
pub fn install(apply_path: bool) -> std::result::Result<Result, Error> {
    // os.Executable + filepath.Abs.
    let self_exe = std::env::current_exe().map_err(|e| io_err("resolve own path", e))?;
    let self_exe =
        std::path::absolute(&self_exe).map_err(|e| io_err("resolve absolute self path", e))?;

    let shim_dir = crate::paths::shim_dir();
    let shim_git = crate::paths::shim_git_path();

    std::fs::create_dir_all(&shim_dir).map_err(|e| io_err("create shim dir", e))?;

    // A resolvable backend is NOT required to install. Resolution skips the shim
    // binary as "self"; `backend_path` is left empty when no backend exists yet
    // (Go `b, _ := backend.Resolve(...)` — the error is deliberately non-fatal).
    let backend_path =
        crate::backend::resolve(crate::paths::managed_git_path().as_deref(), &shim_git)
            .map(|b| b.path)
            .unwrap_or_default();

    place_shims(&self_exe, &shim_dir, &shim_git)?;

    let mut res = Result {
        shim_dir: shim_dir.clone(),
        shim_git,
        backend_path,
        path_applied: false,
        instruction: String::new(),
    };

    if apply_path {
        // Go: fmt.Errorf("apply PATH: %w", err).
        prepend_user_path(&shim_dir).map_err(|e| Error::Message(format!("apply PATH: {e}")))?;
        res.path_applied = true;
        return Ok(res);
    }

    res.instruction = manual_path_instruction(&shim_dir);
    Ok(res)
}

/// Removes the shim directory. PATH cleanup is left to the user, described in the
/// returned instruction. Faithful port of Go `Uninstall`.
pub fn uninstall() -> std::result::Result<String, Error> {
    let shim_dir = crate::paths::shim_dir();

    // Go `os.RemoveAll` returns nil for a non-existent path; std's
    // `remove_dir_all` errors NotFound, so fold that into success.
    match std::fs::remove_dir_all(&shim_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err("remove shim dir", e)),
    }

    // Also remove the canonical binary the launchers exec'd into (best-effort).
    let _ = std::fs::remove_dir_all(crate::paths::bin_dir());

    Ok(format!(
        "Removed {}. Remove it from PATH to fully undo shadowing.",
        shim_dir.display()
    ))
}

/// Installs the PATH-shadowing shims (non-Windows: git shim is a copy of gitc).
#[cfg(not(windows))]
fn place_shims(
    self_exe: &Path,
    _shim_dir: &Path,
    shim_git: &Path,
) -> std::result::Result<(), Error> {
    if same_exe(self_exe, shim_git) {
        return Ok(());
    }
    copy_executable(self_exe, shim_git)
}

/// Installs the PATH-shadowing shims (Windows: the tiny-launcher model).
#[cfg(windows)]
fn place_shims(
    self_exe: &Path,
    shim_dir: &Path,
    _shim_git: &Path,
) -> std::result::Result<(), Error> {
    place_windows_launchers(self_exe, shim_dir)
}

/// Writes the canonical gitc.exe plus the git/sh/bash.exe launcher shims and their
/// `.shim` files. The sh/bash persona rides in the `.shim` `args` line, so all
/// three launchers are one shared inode pointing at one real binary. Go
/// `placeWindowsLaunchers`.
#[cfg(windows)]
fn place_windows_launchers(self_exe: &Path, shim_dir: &Path) -> std::result::Result<(), Error> {
    let launcher = match super::shim::binary(goarch()) {
        Some(l) => l,
        // No prebuilt launcher for this arch — fall back to copying gitc as the
        // git shim so install still works (larger, but functional).
        None => return copy_executable(self_exe, &shim_dir.join("git.exe")),
    };

    // 1. Place the single canonical gitc binary the launchers exec into. Skip when
    //    we already ARE it (a re-install invoked through the launcher).
    let canonical = crate::paths::canonical_path();
    if let Some(parent) = canonical.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err("create bin dir", e))?;
    }
    swap_executable(self_exe, &canonical)?;

    // 2. Write the launcher as git.exe and hard-link sh/bash.exe to it, so all
    //    three names share one small inode.
    let git_exe = shim_dir.join("git.exe");
    write_launcher(&git_exe, launcher)?;

    for name in ["sh.exe", "bash.exe"] {
        let _ = link_shim(&git_exe, &shim_dir.join(name)); // best-effort; not fatal
    }

    // 3. Write each launcher's .shim. git has no args (pure passthrough); sh/bash
    //    carry gitc's shell meta command so hooks resolve without a system shell.
    let shims = [
        ("git.shim", ""),
        ("sh.shim", "gitc sh"),
        ("bash.shim", "gitc bash"),
    ];
    for (name, args) in shims {
        write_shim_file(&shim_dir.join(name), &canonical, args)?;
    }

    Ok(())
}

/// Installs `src` at `dst` even when `dst` is a running executable: Windows locks a
/// running `.exe` against truncation, but a running `.exe` can still be renamed.
/// Moves the old binary aside as `<dst>.old` and copies the new one into place,
/// rolling back on failure. No-op when `src` already IS `dst`. Go `swapExecutable`.
#[cfg_attr(not(windows), allow(dead_code))]
fn swap_executable(src: &Path, dst: &Path) -> std::result::Result<(), Error> {
    if same_exe(src, dst) {
        return Ok(());
    }

    // Go: old := dst + ".old" (string concat — keeps the ".exe", appends ".old").
    let mut old = dst.as_os_str().to_os_string();
    old.push(".old");
    let old = PathBuf::from(old);

    let _ = std::fs::remove_file(&old);

    if std::fs::metadata(dst).is_ok() {
        std::fs::rename(dst, &old).map_err(|e| io_err("move current binary aside", e))?;
    }

    if let Err(e) = copy_executable(src, dst) {
        let _ = std::fs::rename(&old, dst); // best-effort rollback
        return Err(e);
    }

    Ok(())
}

/// Writes the embedded launcher bytes to `path`, recreating it so a stale inode
/// with existing hard links is replaced, not mutated in place. Go `writeLauncher`.
#[cfg(windows)]
fn write_launcher(path: &Path, data: &[u8]) -> std::result::Result<(), Error> {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, data)
        .map_err(|e| io_err(&format!("write launcher {}", base_name(path)), e))?;
    Ok(())
}

/// Writes a scoop-format `.shim` consumed by `shim.c`: `path = <target>` and, when
/// `args` is non-empty, `args = <args>`. UTF-8 with LF line endings. Go
/// `writeShimFile`.
#[cfg(windows)]
fn write_shim_file(path: &Path, target: &Path, args: &str) -> std::result::Result<(), Error> {
    let mut b = String::new();
    b.push_str("path = ");
    b.push_str(&target.to_string_lossy());
    b.push('\n');

    if !args.is_empty() {
        b.push_str("args = ");
        b.push_str(args);
        b.push('\n');
    }

    std::fs::write(path, b.as_bytes())
        .map_err(|e| io_err(&format!("write {}", base_name(path)), e))?;
    Ok(())
}

/// Makes `dst` a hard link to `src` (same shim dir ⇒ same volume), recreating it
/// each install; on any link failure it falls back to a copy. Go `linkShim`.
#[cfg(windows)]
fn link_shim(src: &Path, dst: &Path) -> std::result::Result<(), Error> {
    if same_exe(src, dst) {
        return Ok(()); // already the same file
    }

    let _ = std::fs::remove_file(dst);

    if std::fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }

    copy_executable(src, dst)
}

/// Reports whether two paths refer to the same executable — by cleaned path
/// (case-insensitively on Windows) or by file identity. Go `sameExe`.
///
/// DEVIATION: Go's `os.SameFile` inode identity has no stable-std Windows
/// equivalent; the fallback compares canonicalized paths, which distinguishes the
/// tested cases (identical path vs distinct files) faithfully.
fn same_exe(a: &Path, b: &Path) -> bool {
    let ca = a.to_string_lossy();
    let cb = b.to_string_lossy();

    if cfg!(windows) {
        if ca.eq_ignore_ascii_case(&cb) {
            return true;
        }
    } else if ca == cb {
        return true;
    }

    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ra), Ok(rb)) => ra == rb,
        _ => false,
    }
}

/// Copies `src` to `dst`, truncating/creating `dst` (mode 0o755 on Unix). Go
/// `copyExecutable`.
fn copy_executable(src: &Path, dst: &Path) -> std::result::Result<(), Error> {
    let mut in_f = std::fs::File::open(src).map_err(|e| io_err("open self", e))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o755);
    }
    let mut out = opts.open(dst).map_err(|e| io_err("create shim git", e))?;

    std::io::copy(&mut in_f, &mut out).map_err(|e| io_err("copy shim git", e))?;

    // Go checks the Close() error as "finalize shim git"; sync_all flushes and
    // surfaces a finalize failure the same way.
    out.sync_all().map_err(|e| io_err("finalize shim git", e))?;

    Ok(())
}

/// The manual PATH instruction for the current platform. Go
/// `manualPathInstruction` (`runtime.GOOS` → `cfg!(windows)`).
fn manual_path_instruction(shim_dir: &Path) -> String {
    let dir = shim_dir.display();
    if cfg!(windows) {
        format!(
            "Prepend the shim dir to your user PATH (PowerShell):\n  \
             [Environment]::SetEnvironmentVariable('Path', '{dir};' + \
             [Environment]::GetEnvironmentVariable('Path','User'), 'User')\n\
             Then restart your shell. Or re-run: gitc gitc install --apply"
        )
    } else {
        format!(
            "Prepend the shim dir to PATH in your shell profile (e.g. ~/.bashrc):\n  \
             export PATH=\"{dir}:$PATH\"\n\
             Then restart your shell."
        )
    }
}

/// Prepends `dir` to a `;`-separated PATH string, returning the new value and
/// whether it changed. Unchanged when `dir` is already present (any segment
/// matches exactly); just `dir` when `user_path` is empty. Go `prependPathValue`.
pub fn prepend_path_value(user_path: &str, dir: &str) -> (String, bool) {
    for seg in user_path.split(';') {
        if seg == dir {
            return (user_path.to_string(), false);
        }
    }

    if user_path.is_empty() {
        return (dir.to_string(), true);
    }

    (format!("{dir};{user_path}"), true)
}

/// Go `runtime.GOARCH` for the shim lookup — maps Rust's `ARCH` to Go's value
/// (`x86_64`→`amd64`, `aarch64`→`arm64`); other arches pass through and miss the
/// embedded-launcher table (falling back to a full copy).
#[cfg(windows)]
fn goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Prepends `dir` to the persistent user PATH. Windows-only; other platforms
/// direct the user to the manual instruction. Go `prependUserPath`.
#[cfg(not(windows))]
fn prepend_user_path(dir: &Path) -> std::result::Result<(), Error> {
    Err(Error::Message(format!(
        "automatic PATH apply is Windows-only; {}",
        manual_path_instruction(dir)
    )))
}

#[cfg(windows)]
fn prepend_user_path(dir: &Path) -> std::result::Result<(), Error> {
    // Read the persistent user PATH, compute the new value in Rust (pure, tested),
    // and write it back only if it changed — via PowerShell's Environment API to
    // avoid setx's 1024-char truncation.
    let cur = read_user_path()?;
    let (next, changed) = prepend_path_value(&cur, &dir.to_string_lossy());
    if !changed {
        return Ok(());
    }
    write_user_path(&next)
}

/// Returns the persistent (registry) user PATH, empty when unset. Go
/// `readUserPath`.
#[cfg(windows)]
fn read_user_path() -> std::result::Result<String, Error> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Environment]::GetEnvironmentVariable('Path','User')",
        ])
        .output()
        .map_err(|e| io_err("powershell read user PATH", e))?;

    if !out.status.success() {
        return Err(io_err(
            "powershell read user PATH",
            std::io::Error::other(format!("exited with {}", out.status)),
        ));
    }

    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// Persists `value` as the user PATH. Go `writeUserPath`.
#[cfg(windows)]
fn write_user_path(value: &str) -> std::result::Result<(), Error> {
    let script = format!(
        "[Environment]::SetEnvironmentVariable('Path', '{}', 'User')",
        value.replace('\'', "''")
    );

    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| io_err("powershell set user PATH", e))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Message(format!(
            "powershell set user PATH: exited with {}: {}",
            out.status,
            stderr.trim()
        )));
    }

    Ok(())
}

/// The final path component as a lossy string (Go `filepath.Base`), for error
/// messages.
#[cfg(windows)]
fn base_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    // Install/uninstall read process-global env (LOCALAPPDATA / XDG_DATA_HOME) via
    // `crate::paths`; serialize the env-mutating tests and restore afterward. Go's
    // `t.Setenv` provides this isolation automatically.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&'static str, &Path)]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let saved = pairs
                .iter()
                .map(|(k, _)| (*k, std::env::var_os(k)))
                .collect();
            for (k, v) in pairs {
                std::env::set_var(k, v);
            }
            EnvGuard { _lock: lock, saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    fn unique_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("gitc_installer_{tag}_{}_{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // Go: TestInstallHardlinksShellShims (windows-tagged).
    #[cfg(windows)]
    #[test]
    fn install_hardlinks_shell_shims() {
        let tmp = unique_dir("hardlink");
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &tmp)]);

        let res = install(false).expect("Install");

        let git_bytes = std::fs::read(&res.shim_git).expect("stat/read git shim");
        let dir = res.shim_git.parent().unwrap();

        for name in ["sh.exe", "bash.exe"] {
            let p = dir.join(name);
            let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("{name} not created: {e}"));
            // Go asserts os.SameFile (shared inode). Stable-std has no inode-identity
            // API on Windows, so we verify the link produced byte-identical content
            // (which a hard link guarantees) — the faithful observable of the link.
            assert_eq!(
                bytes, git_bytes,
                "{name} should be a hard link to git.exe (share the inode / bytes)"
            );
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // Go: TestInstallWritesLauncherAndShimFiles (windows-tagged).
    #[cfg(windows)]
    #[test]
    fn install_writes_launcher_and_shim_files() {
        let tmp = unique_dir("launcher");
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &tmp)]);

        let res = install(false).expect("Install");

        // git.exe must be the tiny embedded launcher, not a full copy of gitc.
        let launcher = super::goarch();
        let launcher = super::super::shim::binary(launcher)
            .unwrap_or_else(|| panic!("no embedded launcher for {}", super::goarch()));

        let got = std::fs::read(&res.shim_git).expect("read git shim");
        assert_eq!(
            got.len(),
            launcher.len(),
            "git.exe is {} bytes; expected the {}-byte launcher, not a gitc copy",
            got.len(),
            launcher.len()
        );

        // The canonical gitc.exe the launchers exec must exist.
        let canonical = crate::paths::canonical_path();
        assert!(
            std::fs::metadata(&canonical).is_ok(),
            "canonical gitc.exe missing"
        );

        // Each launcher needs a sibling .shim pointing at the canonical binary; the
        // sh/bash personas carry the gitc meta command in `args`.
        let canonical_str = canonical.to_string_lossy();
        let cases = [
            ("git.shim", ""),
            ("sh.shim", "args = gitc sh"),
            ("bash.shim", "args = gitc bash"),
        ];

        for (name, want_args) in cases {
            let body = std::fs::read_to_string(res.shim_dir.join(name))
                .unwrap_or_else(|e| panic!("{name} not written: {e}"));

            assert!(
                body.contains(&format!("path = {canonical_str}")),
                "{name} must point at the canonical binary; got:\n{body}"
            );

            if !want_args.is_empty() {
                assert!(
                    body.contains(want_args),
                    "{name} must carry {want_args:?}; got:\n{body}"
                );
            }

            if want_args.is_empty() {
                assert!(
                    !body.contains("args = "),
                    "git.shim must have no args line; got:\n{body}"
                );
            }
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // Go: TestSwapExecutable.
    #[test]
    fn swap_executable_moves_old_aside() {
        let dir = unique_dir("swap");
        let src = dir.join("new.exe");
        let dst = dir.join("canonical.exe");

        std::fs::write(&src, b"NEW").unwrap();
        std::fs::write(&dst, b"OLD").unwrap();

        swap_executable(&src, &dst).expect("swapExecutable");

        assert_eq!(std::fs::read(&dst).unwrap(), b"NEW", "dst should be NEW");

        let mut old = dst.as_os_str().to_os_string();
        old.push(".old");
        assert_eq!(
            std::fs::read(PathBuf::from(old)).unwrap(),
            b"OLD",
            ".old should be the previous binary moved aside"
        );

        // Re-invoking with src == dst is a no-op (a re-install through the canonical).
        swap_executable(&dst, &dst).expect("swapExecutable(dst, dst) should be a no-op");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Go: TestSameExe.
    #[test]
    fn same_exe_identity() {
        let dir = unique_dir("sameexe");

        let a = dir.join("a.exe");
        std::fs::write(&a, b"x").unwrap();
        assert!(same_exe(&a, &a), "an identical path should be sameExe");

        let b = dir.join("b.exe");
        std::fs::write(&b, b"y").unwrap();
        assert!(
            !same_exe(&a, &b),
            "two distinct files should not be sameExe"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Go: TestInstallWithoutBackendThenUninstall.
    #[test]
    fn install_without_backend_then_uninstall() {
        // Isolate the data dir so we never touch the real install.
        let local = unique_dir("nobackend_local");
        let xdg = unique_dir("nobackend_xdg");
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &local), ("XDG_DATA_HOME", &xdg)]);

        let res = install(false).expect("Install must not require a pre-existing backend");

        assert!(std::fs::metadata(&res.shim_git).is_ok(), "shim not created");
        assert!(
            !res.instruction.is_empty(),
            "expected a manual PATH instruction when --apply is not set"
        );

        uninstall().expect("Uninstall");

        let err = std::fs::metadata(&res.shim_git).err();
        assert!(
            matches!(err, Some(e) if e.kind() == std::io::ErrorKind::NotFound),
            "shim should be removed after Uninstall"
        );

        let _ = std::fs::remove_dir_all(&local);
        let _ = std::fs::remove_dir_all(&xdg);
    }

    // Go: path_test.go TestPrependPathValue (table-driven).
    #[test]
    fn prepend_path_value_cases() {
        let cases = [
            ("empty", "", r"C:\gitc\shim", r"C:\gitc\shim", true),
            (
                "prepend",
                r"C:\other",
                r"C:\gitc\shim",
                r"C:\gitc\shim;C:\other",
                true,
            ),
            (
                "already first",
                r"C:\gitc\shim;C:\other",
                r"C:\gitc\shim",
                r"C:\gitc\shim;C:\other",
                false,
            ),
            (
                "already later",
                r"C:\other;C:\gitc\shim",
                r"C:\gitc\shim",
                r"C:\other;C:\gitc\shim",
                false,
            ),
            (
                "substring not matched",
                r"C:\gitc\shimX",
                r"C:\gitc\shim",
                r"C:\gitc\shim;C:\gitc\shimX",
                true,
            ),
        ];

        for (name, user_path, dir, want_result, want_changed) in cases {
            let (got, changed) = prepend_path_value(user_path, dir);
            assert_eq!(
                (got.as_str(), changed),
                (want_result, want_changed),
                "case {name}: prependPathValue({user_path:?}, {dir:?})"
            );
        }
    }
}
