//! Port of Go `shell.go` (package main) — the sh/bash launcher.
//!
//! When gitc is invoked under the name `sh`/`bash` (via an installed shim, i.e. a
//! copy of gitc named `sh.exe`/`bash.exe`), it does not act as the git proxy —
//! instead it launches the *managed* git backend's own POSIX shell, found in the
//! backend's install tree rather than on the caller's PATH. This lets git hooks
//! run against a bundled shell even on a machine with no shell installed.
//!
//! [`shell_name`] is the pure name-detection (also exercised by the backendupdate
//! tests). [`run_shell`] is the launcher; the backend resolution + process exec is
//! untested glue, but the argument/PATH handling ([`shell_env`],
//! [`find_backend_shell`]) is characterized.

use std::path::{Path, PathBuf};

use crate::{backend, provision};

/// Returns `Some("sh")` / `Some("bash")` when the program was invoked under that
/// name (via an installed shim), else `None`. Faithful port of Go `shellName`:
/// the base name is lower-cased and a trailing `.exe` is stripped before the
/// match. Go returned `""` for "not a shell name"; here that is `None`.
pub fn shell_name(arg0: &str) -> Option<String> {
    // Go `filepath.Base` — platform separator semantics (on Windows both `/` and
    // `\` split, elsewhere only `/`); `std::path::Path::file_name` matches this.
    let base = Path::new(arg0)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let base = base.strip_suffix(".exe").unwrap_or(&base);

    match base {
        "sh" | "bash" => Some(base.to_string()),
        _ => None,
    }
}

/// Launches the managed git backend's POSIX shell — found in the backend's own
/// install tree, not the caller's PATH — with `args`, inheriting stdio and
/// propagating the exit code. Faithful port of Go `runShell`.
pub fn run_shell(name: &str, args: &[String]) -> i32 {
    let self_path = std::env::current_exe().unwrap_or_default();

    let b = match backend::resolve(provision::managed_git_path().as_deref(), &self_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gitc {name}: {e}");
            return 1;
        }
    };

    // `<version>/cmd/git.exe` -> `<version>` (dir of dir of the git binary).
    let root = b
        .path
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_default();

    let shell = match find_backend_shell(&root, name) {
        Some(s) => s,
        None => {
            eprintln!(
                "gitc {name}: no {name} in the git backend; run `git fetch-git --full`"
            );
            return 1;
        }
    };

    let mut cmd = std::process::Command::new(&shell);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in shell_env(&root) {
        cmd.env(k, v);
    }
    // Inherit stdio (the std default): stdin/stdout/stderr flow to the child.

    match cmd.status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!("gitc {name}: {e}");
            1
        }
    }
}

/// Builds the environment for a launched shell with the backend's unix tool dirs
/// (`usr/bin`, `mingw64/bin`, `bin`) prepended to `PATH`, so the shell has `ls`,
/// `grep`, `uname`, etc. even when nothing is on the caller's PATH. Faithful port
/// of Go `shellEnv` — returns the full `(key, value)` environment.
fn shell_env(root: &Path) -> Vec<(String, String)> {
    let sep = path_list_separator();
    let prefix = [
        root.join("usr").join("bin"),
        root.join("mingw64").join("bin"),
        root.join("bin"),
    ]
    .iter()
    .map(|p| p.to_string_lossy().into_owned())
    .collect::<Vec<_>>()
    .join(sep);

    let mut env: Vec<(String, String)> = std::env::vars().collect();

    for entry in env.iter_mut() {
        // Go compared the first 5 bytes case-insensitively against "PATH=".
        if entry.0.eq_ignore_ascii_case("PATH") {
            entry.1 = format!("{prefix}{sep}{}", entry.1);
            return env;
        }
    }

    env.push(("PATH".to_string(), prefix));
    env
}

/// Locates `name`'s shell in the backend install tree, trying the full/MinGit path
/// then the busybox layout (`ash` serves as `sh`). Returns `None` when absent (e.g.
/// the minimal MinGit, or bash under busybox). Faithful port of Go
/// `findBackendShell` — the `.exe` names mirror the git-for-windows tree layout
/// regardless of host OS.
fn find_backend_shell(root: &Path, name: &str) -> Option<PathBuf> {
    let mut candidates = vec![root.join("usr").join("bin").join(format!("{name}.exe"))];
    if name == "sh" {
        candidates.push(root.join("mingw64").join("bin").join("ash.exe"));
    }

    candidates.into_iter().find(|c| c.exists())
}

/// The OS path-list separator (Go `os.PathListSeparator`): `;` on Windows, `:`
/// elsewhere.
fn path_list_separator() -> &'static str {
    if cfg!(windows) {
        ";"
    } else {
        ":"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-mutating tests serialize + restore around process-global state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn shell_name_detection() {
        // Mirrors the Go `TestShellName` case map (forward-slash / bare paths so
        // `filepath.Base` behaves identically on Linux CI and Windows).
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
            let got = shell_name(arg0);
            assert_eq!(
                got.as_deref(),
                *want,
                "shell_name({arg0:?}) = {got:?}, want {want:?}"
            );
        }
    }

    #[test]
    fn run_shell_no_backend_returns_one() {
        // With a non-existent managed backend AND an empty PATH (no system git),
        // resolution fails and run_shell surfaces exit 1 — the error arg-handling
        // path, deterministic without a real backend.
        let _lock = ENV_LOCK.lock().unwrap();
        let saved_backend = std::env::var_os("GITC_GIT_BACKEND");
        let saved_path = std::env::var_os("PATH");

        let missing = std::env::temp_dir().join(format!(
            "gitc_shell_missing_{}\\git.exe",
            std::process::id()
        ));
        std::env::set_var("GITC_GIT_BACKEND", &missing);
        std::env::set_var("PATH", "");

        let code = run_shell("sh", &["-c".to_string(), "true".to_string()]);
        assert_eq!(code, 1, "no resolvable backend -> exit 1");

        match saved_backend {
            Some(v) => std::env::set_var("GITC_GIT_BACKEND", v),
            None => std::env::remove_var("GITC_GIT_BACKEND"),
        }
        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn shell_env_prepends_backend_dirs() {
        let _lock = ENV_LOCK.lock().unwrap();
        let saved_path = std::env::var_os("PATH");
        std::env::set_var("PATH", "/orig/bin");

        let root = Path::new("/backend/v1");
        let env = shell_env(root);
        let path = env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
            .map(|(_, v)| v.clone())
            .expect("PATH must be present");

        let sep = path_list_separator();
        let usr_bin = root.join("usr").join("bin");
        assert!(
            path.starts_with(&usr_bin.to_string_lossy().into_owned()),
            "backend usr/bin must be prepended: {path}"
        );
        assert!(
            path.ends_with(&format!("{sep}/orig/bin")),
            "original PATH must be preserved after the prefix: {path}"
        );

        match saved_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn find_backend_shell_absent_is_none() {
        let root = std::env::temp_dir().join(format!("gitc_shell_empty_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        assert_eq!(find_backend_shell(&root, "bash"), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
