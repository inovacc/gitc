//! Port of Go `internal/paths` — the platform-specific locations gitc uses for its
//! audit database, downloaded git backend, and configuration.
//!
//! Windows uses `%LOCALAPPDATA%\gitc`; other platforms follow the XDG base
//! directory spec (`~/.local/share/gitc` and `~/.config/gitc`), falling back to
//! `~/.gitc` when neither is resolvable. Pure std.

use std::path::PathBuf;

const APP_NAME: &str = "gitc";

/// Go `os.UserHomeDir` — the user's home directory (`USERPROFILE` on Windows,
/// `HOME` elsewhere), or `None` when the environment doesn't provide it.
fn user_home_dir() -> Option<PathBuf> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn env_nonempty(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Go `DataDir` — the base directory for gitc's mutable state (audit DB,
/// downloaded git backend). Not created here.
pub fn data_dir() -> PathBuf {
    if cfg!(windows) {
        if let Some(base) = env_nonempty("LOCALAPPDATA") {
            return base.join(APP_NAME);
        }
    }
    if let Some(base) = env_nonempty("XDG_DATA_HOME") {
        return base.join(APP_NAME);
    }
    if let Some(home) = user_home_dir() {
        if cfg!(windows) {
            return home.join("AppData").join("Local").join(APP_NAME);
        }
        return home.join(".local").join("share").join(APP_NAME);
    }
    PathBuf::from(format!(".{APP_NAME}"))
}

/// Go `ConfigDir` — the base directory for gitc's user configuration.
pub fn config_dir() -> PathBuf {
    if cfg!(windows) {
        return data_dir();
    }
    if let Some(base) = env_nonempty("XDG_CONFIG_HOME") {
        return base.join(APP_NAME);
    }
    if let Some(home) = user_home_dir() {
        return home.join(".config").join(APP_NAME);
    }
    data_dir()
}

/// Go `AuditDBPath` — the forensic audit SQLite database.
pub fn audit_db_path() -> PathBuf {
    data_dir().join("audit").join(format!("{APP_NAME}.db"))
}

/// Go `ShimDir` — where `gitc gitc install` places a copy of itself named git.
pub fn shim_dir() -> PathBuf {
    data_dir().join("shim")
}

/// Go `ShimGitPath` — the shimmed git binary path inside [`shim_dir`].
pub fn shim_git_path() -> PathBuf {
    let name = if cfg!(windows) { "git.exe" } else { "git" };
    shim_dir().join(name)
}

/// Go `BinDir` — the directory holding the canonical gitc binary the launcher
/// shims exec into.
pub fn bin_dir() -> PathBuf {
    data_dir().join("bin")
}

/// Go `CanonicalPath` — the canonical gitc binary under [`bin_dir`].
pub fn canonical_path() -> PathBuf {
    let name = if cfg!(windows) {
        format!("{APP_NAME}.exe")
    } else {
        APP_NAME.to_string()
    };
    bin_dir().join(name)
}

/// Go `GitCacheDir` — the LEGACY directory of downloaded MinGit distributions.
pub fn git_cache_dir() -> PathBuf {
    data_dir().join("git")
}

/// Go `AppDir` — UUID-namespaced managed-git installs (`app/<uuidv7>/<version>/`).
pub fn app_dir() -> PathBuf {
    data_dir().join("app")
}

/// Go `SettingsPath` — `settings.json`, the active-backend + update-policy source.
pub fn settings_path() -> PathBuf {
    data_dir().join("settings.json")
}

/// Go `PolicyPath` — the DEPRECATED per-user `policy.json` location.
pub fn policy_path() -> PathBuf {
    data_dir().join("policy.json")
}

/// Go `MachineConfigDir` — the machine-wide (admin-owned) enforcement-policy dir,
/// deliberately NOT derived from the agent-mutable per-user dir.
pub fn machine_config_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        return base.join(APP_NAME);
    }
    PathBuf::from("/etc").join(APP_NAME)
}

/// Go `MachinePolicyPath` — the primary (machine-wide) `policy.json`.
pub fn machine_policy_path() -> PathBuf {
    machine_config_dir().join("policy.json")
}

/// Go `EnforceMarkerPath` — the machine-wide fail-closed marker file.
pub fn enforce_marker_path() -> PathBuf {
    machine_config_dir().join("ENFORCE")
}

/// Go `ManagedGitPath` — the newest downloaded MinGit `git.exe` under
/// [`git_cache_dir`], or `None` if none is cached. (Go returns "" for none.)
pub fn managed_git_path() -> Option<PathBuf> {
    let cache = git_cache_dir();
    let entries = std::fs::read_dir(&cache).ok()?;
    // Go's os.ReadDir returns entries sorted by name; sort so ties (mtime `>=`)
    // resolve to the last name, matching Go.
    let mut names: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().into())
        .collect();
    names.sort();

    let mut newest: Option<PathBuf> = None;
    let mut newest_mod: Option<std::time::SystemTime> = None;
    for name in names {
        let git_exe = cache.join(&name).join("cmd").join("git.exe");
        let Ok(meta) = std::fs::metadata(&git_exe) else {
            continue;
        };
        let Ok(m) = meta.modified() else {
            continue;
        };
        // `>=`, like Go — a later-sorted equal-mtime entry wins.
        if newest_mod.map(|prev| m >= prev).unwrap_or(true) {
            newest_mod = Some(m);
            newest = Some(git_exe);
        }
    }
    newest
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These tests mutate process-global env; serialize + restore around them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    impl EnvGuard {
        fn set(pairs: &[(&'static str, &std::path::Path)]) -> Self {
            let keys: Vec<&'static str> = pairs.iter().map(|(k, _)| *k).collect();
            let saved = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
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
    fn path_layout() {
        let base = data_dir();
        assert_eq!(app_dir(), base.join("app"));
        assert_eq!(settings_path(), base.join("settings.json"));
        assert_eq!(policy_path(), base.join("policy.json"));
        assert_eq!(git_cache_dir(), base.join("git"));
        assert_eq!(shim_dir(), base.join("shim"));
        assert_eq!(audit_db_path(), base.join("audit").join("gitc.db"));
    }

    #[test]
    fn managed_git_path_empty_when_no_cache() {
        let _lock = ENV_LOCK.lock().unwrap();
        let a = std::env::temp_dir().join(format!("gitc_paths_a_{}", std::process::id()));
        let b = std::env::temp_dir().join(format!("gitc_paths_b_{}", std::process::id()));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &a), ("XDG_DATA_HOME", &b)]);
        assert_eq!(managed_git_path(), None, "no cache -> None");
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn managed_git_path_finds_cached_install() {
        let _lock = ENV_LOCK.lock().unwrap();
        let base = std::env::temp_dir().join(format!("gitc_paths_c_{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let _g = EnvGuard::set(&[("LOCALAPPDATA", &base), ("XDG_DATA_HOME", &base)]);
        let git_exe = git_cache_dir()
            .join("v2.55.0.windows.2")
            .join("cmd")
            .join("git.exe");
        std::fs::create_dir_all(git_exe.parent().unwrap()).unwrap();
        std::fs::write(&git_exe, b"x").unwrap();
        assert_eq!(managed_git_path(), Some(git_exe));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn shim_git_path_under_shim_dir() {
        assert_eq!(shim_git_path().parent().unwrap(), shim_dir());
    }
}
