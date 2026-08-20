//! Port of Go `backendupdate.go` (package main) — the throttled background-update
//! machinery plus `cleanShimBackups` (Go `main.go`, co-located here so its test
//! sits beside the lock/notice tests it shipped with).
//!
//! On an ordinary git command gitc surfaces any pending update notice and lazily
//! kicks off a *single-flight, throttled* background update check without ever
//! blocking the foreground command. The detached worker (`gitc gitc
//! backend-update`) brings the managed git up to the pinned version, records
//! whether a newer gitc release exists, and GCs superseded installs.
//!
//! The **throttle + lock logic** ([`maybe_spawn_background_update`],
//! [`try_update_lock`]) is testable; the detached re-exec ([`spawn_detached`]) is
//! untested glue. Go's `context.Context` is dropped and the injected
//! [`crate::selfupdate::HttpClient`] replaces `net/http` (pack rules).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::selfupdate::HttpClient;
use crate::{paths, provision, selfupdate, settings};

/// Bounds how long an `update.lock` is honored before a crashed checker's lock is
/// reclaimed (Go `updateLockStale = time.Hour`).
const UPDATE_LOCK_STALE: Duration = Duration::from_secs(60 * 60);

fn lock_path() -> PathBuf {
    paths::data_dir().join("update.lock")
}

fn notice_path() -> PathBuf {
    paths::data_dir().join("update-notice.txt")
}

/// Best-effort removal of stale `*.old` binaries left behind by a self-update
/// swap: a running `.exe` cannot delete itself, so the swap renames the old binary
/// aside as `<name>.old`, cleared on a later startup (when it is no longer the
/// running process). Both the shim dir (launcher shims) and the bin dir (the
/// canonical `gitc.exe` that `git update` replaces) are swept. Faithful port of Go
/// `cleanShimBackups` (`main.go`).
pub fn clean_shim_backups() {
    for dir in [paths::shim_dir(), paths::bin_dir()] {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir && entry.file_name().to_string_lossy().ends_with(".old") {
                let _ = std::fs::remove_file(dir.join(entry.file_name()));
            }
        }
    }
}

/// An advisory-lock guard: dropping it removes the lockfile, mirroring Go's
/// `release()` closure driven by `defer`.
pub struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Creates an exclusive lockfile, reclaiming a stale one. Returns `None` when
/// another checker already holds a fresh lock. Faithful port of Go
/// `tryUpdateLock`: Go returned `(release, ok)`; here the release closure becomes
/// the [`LockGuard`]'s `Drop` (idiomatic `defer` → RAII), and `ok == false` → `None`.
pub fn try_update_lock(path: &Path) -> Option<LockGuard> {
    // Reclaim a stale lock (older than UPDATE_LOCK_STALE).
    if let Ok(info) = std::fs::metadata(path) {
        if let Ok(mtime) = info.modified() {
            if SystemTime::now()
                .duration_since(mtime)
                .map(|elapsed| elapsed > UPDATE_LOCK_STALE)
                .unwrap_or(false)
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    // O_CREATE | O_EXCL | O_WRONLY — fails if the file already exists.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    match opts.open(path) {
        Ok(_f) => Some(LockGuard {
            path: path.to_path_buf(),
        }),
        Err(_) => None,
    }
}

/// Lazily starts a background update check when one is due, without blocking the
/// foreground git command. Single-flight (via [`try_update_lock`]); it stamps the
/// check time optimistically so a burst of invocations spawns at most one checker
/// and the interval is respected even if the check fails. A no-op inside a
/// background child (`GITC_BACKGROUND`) or when updates are disabled / not yet due.
/// Faithful port of Go `maybeSpawnBackgroundUpdate`.
pub fn maybe_spawn_background_update() {
    if std::env::var_os("GITC_BACKGROUND").is_some() {
        return;
    }

    let sp = paths::settings_path();

    let s = match settings::load(&sp) {
        Ok(s) => s,
        Err(_) => return,
    };
    if !s.update.enabled {
        return;
    }

    let now = OffsetDateTime::now_utc();
    if !s.update.due_since(&s.update.backend_last_check, now)
        && !s.update.due_since(&s.update.gitc_last_check, now)
    {
        return;
    }

    let _guard = match try_update_lock(&lock_path()) {
        Some(g) => g,
        None => return,
    };

    // Optimistic stamp (Go `now.Format(time.RFC3339)` — seconds precision, no
    // fractional part), written under the advisory lock.
    let stamp = match now.replace_nanosecond(0).ok().and_then(|t| t.format(&Rfc3339).ok()) {
        Some(s) => s,
        None => return,
    };

    if settings::mutate(&sp, |s| {
        s.update.backend_last_check = stamp.clone();
        s.update.gitc_last_check = stamp.clone();
    })
    .is_err()
    {
        return;
    }

    let _ = spawn_detached(&["gitc".to_string(), "backend-update".to_string()]);
    // `_guard` drops here, releasing the lock — matching Go's `defer release()`.
}

/// Re-execs gitc, detached, with the given args and returns at once (the child
/// outlives this process). `GITC_BACKGROUND=1` marks the child so it never spawns
/// further checkers. Untested glue. Faithful port of Go `spawnDetached` — no
/// context by design (the child must OUTLIVE the parent).
fn spawn_detached(args: &[String]) -> std::io::Result<()> {
    let self_path = std::env::current_exe()?;

    let mut cmd = std::process::Command::new(self_path);
    cmd.args(args);
    cmd.env("GITC_BACKGROUND", "1");
    configure_detached(&mut cmd);

    // Spawn and let the Child handle drop (no wait/reap) — Go called
    // Process.Release() to disown the detached child.
    let _child = cmd.spawn()?;
    Ok(())
}

/// Windows: run as a detached, window-less background process that outlives the
/// parent (no console flash, its own process group). Go set
/// `SysProcAttr{HideWindow, CreationFlags: DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP}`;
/// the window-hide maps to `CREATE_NO_WINDOW`.
#[cfg(windows)]
fn configure_detached(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
}

/// Unix: put the background child in its own process group so it outlives the
/// parent. Go used `Setsid: true`; `process_group(0)` is the std-only equivalent
/// (a new process group; a full session-leader `setsid` would need `libc`/`pre_exec`
/// — deferred, this is untested detach glue).
#[cfg(unix)]
fn configure_detached(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

/// Prints and removes a pending background-update notice, so the user learns of a
/// new gitc release without the check ever blocking a command. Faithful port of Go
/// `printAndClearNotice`.
pub fn print_and_clear_notice() {
    let data = match std::fs::read(notice_path()) {
        Ok(d) => d,
        Err(_) => return,
    };

    eprint!("gitc: {}", String::from_utf8_lossy(&data));

    let _ = std::fs::remove_file(notice_path());
}

/// The detached worker (`gitc gitc backend-update`): brings the managed git
/// backend up to the pinned version (verified) when needed, records whether a
/// newer gitc release exists, and GCs superseded installs. Best-effort; it prints
/// nothing to the foreground. Faithful port of Go `runBackendUpdate` (ctx dropped;
/// `http` injected).
pub fn run_backend_update(http: &dyn HttpClient) -> i32 {
    let sp = paths::settings_path();

    let mut s = match settings::load_or_init(&sp) {
        Ok(s) => s,
        Err(_) => return 1,
    };

    provision::update_backend_if_stale(http, &sp, &mut s);
    record_gitc_notice(http);
    provision::gc_installs();

    0
}

/// Writes a one-line notice when a newer gitc release exists; the foreground
/// prints it once on the next invocation. Faithful port of Go `recordGitcNotice`.
fn record_gitc_notice(http: &dyn HttpClient) {
    let info = match selfupdate::check(crate::appmain::VERSION, http) {
        Ok(Some(info)) if info.has_update => info,
        _ => return,
    };

    let msg = format!(
        "a newer gitc is available: {} (run `git update --apply`)\n",
        info.latest
    );
    let _ = std::fs::write(notice_path(), msg.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-mutating tests serialize + restore around process-global state on the
    // crate-shared lock (LOCALAPPDATA/XDG_DATA_HOME is also mutated by the
    // installer/provision/paths tests, so a per-module lock would let them race).

    struct EnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    impl EnvGuard {
        fn set(pairs: &[(&'static str, &Path)]) -> Self {
            let saved = pairs
                .iter()
                .map(|(k, _)| (*k, std::env::var_os(k)))
                .collect();
            for (k, v) in pairs {
                std::env::set_var(k, v);
            }
            EnvGuard { saved }
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

    #[test]
    fn clean_shim_backups_sweeps_old_keeps_current() {
        let _lock = crate::test_env::guard();
        let base = std::env::temp_dir().join(format!("gitc_bu_clean_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &base), ("XDG_DATA_HOME", &base)]);

        let shim = paths::shim_dir();
        let bin = paths::bin_dir();
        for d in [&shim, &bin] {
            std::fs::create_dir_all(d).unwrap();
        }

        let keep = shim.join("git.exe");
        std::fs::write(&keep, b"current").unwrap();

        let stale = [
            shim.join("git.exe.old"),
            shim.join("gitc.old"),
            bin.join("gitc.exe.old"), // the update swap's leftover
        ];
        for p in &stale {
            std::fs::write(p, b"stale").unwrap();
        }

        clean_shim_backups();

        assert!(keep.exists(), "current shim must be kept");
        for p in &stale {
            assert!(!p.exists(), "{} should have been swept", p.display());
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn shell_name_matches_go() {
        // Go `TestShellName` lives in backendupdate_test.go; the function it tests
        // is `crate::shell::shell_name`.
        let cases: &[(&str, Option<&str>)] = &[
            ("sh.exe", Some("sh")),
            ("bash.exe", Some("bash")),
            ("gitc/shim/sh.exe", Some("sh")),
            ("/opt/gitc/bash", Some("bash")),
            ("BASH.EXE", Some("bash")),
            ("gitc/shim/git.exe", None),
            ("gitc", None),
        ];
        for (arg0, want) in cases {
            assert_eq!(
                crate::shell::shell_name(arg0).as_deref(),
                *want,
                "shell_name({arg0:?})"
            );
        }
    }

    #[test]
    fn try_update_lock_single_flight() {
        let dir = std::env::temp_dir().join(format!("gitc_bu_lock_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join("update.lock");
        let _ = std::fs::remove_file(&lock);

        let g = try_update_lock(&lock);
        assert!(g.is_some(), "first acquisition should succeed");

        assert!(
            try_update_lock(&lock).is_none(),
            "a second acquisition must fail while the lock is held"
        );

        drop(g); // release

        assert!(
            try_update_lock(&lock).is_some(),
            "the lock should be re-acquirable after release"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
