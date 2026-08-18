//! Thin `git` subprocess wrappers used by the history-scrub engine.
//!
//! Thin wrappers over `git` subprocesses (`rev-parse`, `count-objects`,
//! `for-each-ref`, `config`, `remote`) used by the sanity check, cleanup, and the
//! pipeline. Every call takes an explicit `git_bin` so an embedding tool can pass
//! the resolved REAL git — see [`default_git_binary`].

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The git executable used when a caller supplies none (looked up on PATH). See
/// [`default_git_binary`] for the shim-avoiding resolution lensr_git actually uses.
pub const DEFAULT_GIT_BINARY: &str = "git";

/// A failed git invocation with its captured stderr, so callers get an actionable
/// message rather than a bare exit code (Go's unexported `gitError`, made public).
#[derive(Debug)]
pub struct GitError {
    pub args: Vec<String>,
    pub stderr: String,
    /// The underlying cause (spawn error or "exit status: N").
    pub cause: String,
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = self.stderr.trim();
        if msg.is_empty() {
            write!(f, "git {}: {}", self.args.join(" "), self.cause)
        } else {
            write!(f, "git {}: {}: {}", self.args.join(" "), self.cause, msg)
        }
    }
}

impl Error for GitError {}

/// The on-disk layout of a git repository, as reported by `git rev-parse`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RepoInfo {
    /// `git rev-parse --git-dir` (may be relative, e.g. `.git`).
    pub git_dir: String,
    /// Whether the repository is bare.
    pub bare: bool,
}

/// The `git count-objects -v` fields the sanity check consults.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ObjectCounts {
    /// Number of loose (unpacked) objects.
    pub count: i64,
    /// Number of packfiles in the object store.
    pub packs: i64,
}

fn resolve_bin(git_bin: &str) -> String {
    if git_bin.is_empty() {
        default_git_binary()
    } else {
        git_bin.to_string()
    }
}

fn full_args(dir: &str, args: &[&str]) -> Vec<String> {
    let mut full = vec!["-C".to_string(), dir.to_string()];
    full.extend(args.iter().map(|s| s.to_string()));
    full
}

/// Run `<git_bin> -C dir args...` and return stdout with trailing whitespace
/// trimmed. A non-zero exit is a [`GitError`] carrying stderr.
pub fn git_output(git_bin: &str, dir: &str, args: &[&str]) -> Result<String, GitError> {
    let bin = resolve_bin(git_bin);
    let full = full_args(dir, args);
    let output = Command::new(&bin)
        .args(&full)
        .output()
        .map_err(|e| GitError {
            args: full.clone(),
            stderr: String::new(),
            cause: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(GitError {
            args: full,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            cause: format!("exit status: {}", status_code_str(&output.status)),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim_end_matches(['\r', '\n', ' ', '\t']).to_string())
}

/// Run a git command purely for its exit status: `Ok(code)` (0 on success, a
/// positive code for a clean non-zero exit such as `config --get` reporting an
/// unset key), or a [`GitError`] only when the process could not be started.
pub fn git_exit_code(git_bin: &str, dir: &str, args: &[&str]) -> Result<i32, GitError> {
    let bin = resolve_bin(git_bin);
    let full = full_args(dir, args);
    match Command::new(&bin).args(&full).output() {
        Ok(o) => Ok(o.status.code().unwrap_or(-1)),
        Err(e) => Err(GitError {
            args: full,
            stderr: String::new(),
            cause: e.to_string(),
        }),
    }
}

fn status_code_str(s: &std::process::ExitStatus) -> String {
    s.code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string())
}

/// Resolve the git directory and bareness of the repository rooted at `dir`.
pub fn repo_layout(git_bin: &str, dir: &str) -> Result<RepoInfo, GitError> {
    let bare = git_output(git_bin, dir, &["rev-parse", "--is-bare-repository"])?;
    let git_dir = git_output(git_bin, dir, &["rev-parse", "--git-dir"])?;
    Ok(RepoInfo {
        git_dir,
        bare: bare == "true",
    })
}

/// Parse `git count-objects -v`, returning loose-object + packfile counts.
pub fn count_objects(git_bin: &str, dir: &str) -> Result<ObjectCounts, GitError> {
    let out = git_output(git_bin, dir, &["count-objects", "-v"])?;
    Ok(parse_object_counts(&out))
}

/// Pure parser for `count-objects -v` output (unknown lines ignored).
fn parse_object_counts(out: &str) -> ObjectCounts {
    let mut counts = ObjectCounts::default();
    for line in out.split('\n') {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let Ok(n) = val.trim().parse::<i64>() else {
            continue;
        };
        match key.trim() {
            "count" => counts.count = n,
            "packs" => counts.packs = n,
            _ => {}
        }
    }
    counts
}

/// Every ref in the repository (full refname form) via `git for-each-ref`.
pub fn list_refs(git_bin: &str, dir: &str) -> Result<Vec<String>, GitError> {
    let out = git_output(git_bin, dir, &["for-each-ref", "--format=%(refname)"])?;
    Ok(split_lines(&out))
}

/// Read a single git config value. `Ok((_, false))` (no error) when the key is
/// unset; a genuine failure is a [`GitError`].
pub fn config_value(git_bin: &str, dir: &str, key: &str) -> Result<(String, bool), GitError> {
    let code = git_exit_code(git_bin, dir, &["config", "--get", key])?;
    if code == 1 {
        // git config exits 1 when the key is absent.
        return Ok((String::new(), false));
    }
    let out = git_output(git_bin, dir, &["config", "--get", key])?;
    Ok((out, true))
}

/// The configured remote names via `git remote`.
pub fn remotes(git_bin: &str, dir: &str) -> Result<Vec<String>, GitError> {
    let out = git_output(git_bin, dir, &["remote"])?;
    Ok(split_lines(&out))
}

fn split_lines(out: &str) -> Vec<String> {
    if out.is_empty() {
        return Vec::new();
    }
    out.split('\n').map(str::to_string).collect()
}

/// Resolve the REAL git binary to subprocess — NOT the lensr_git shim (a bare
/// `git` would re-enter this process). Resolution order: `LENSR_GIT_REAL_GIT`
/// override → the first `git` on PATH that is neither this executable nor in the
/// `%LOCALAPPDATA%\Lensr\bin` shim dir → `"git"` (Go's default; may re-enter a
/// shim — documented). This is the lensr_git adaptation of Go's `DefaultGitBinary`.
pub fn default_git_binary() -> String {
    if let Ok(p) = std::env::var("LENSR_GIT_REAL_GIT") {
        let p = p.trim();
        if !p.is_empty() {
            return p.to_string();
        }
    }
    if let Some(p) = find_real_git_on_path() {
        return p;
    }
    DEFAULT_GIT_BINARY.to_string()
}

fn find_real_git_on_path() -> Option<String> {
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for name in ["git.exe", "git"] {
            let cand = dir.join(name);
            if !cand.is_file() {
                continue;
            }
            // Skip our own shim (same canonical path) and the install dir.
            if let (Ok(c), Some(s)) = (cand.canonicalize(), self_exe.as_ref()) {
                if &c == s {
                    continue;
                }
            }
            if is_in_lensr_bin(&cand) {
                continue;
            }
            return Some(cand.to_string_lossy().into_owned());
        }
    }
    None
}

/// Whether `p` resolves inside `%LOCALAPPDATA%\Lensr\bin` (the shim install dir).
fn is_in_lensr_bin(p: &Path) -> bool {
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return false;
    };
    let bin = PathBuf::from(base).join("Lensr").join("bin");
    match (bin.canonicalize(), p.canonicalize()) {
        (Ok(cbin), Ok(cp)) => cp.starts_with(&cbin),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_count_objects_output() {
        let out = "count: 12\nsize: 48\nin-pack: 0\npacks: 3\nprune-packable: 0\ngarbage: 0";
        assert_eq!(
            parse_object_counts(out),
            ObjectCounts {
                count: 12,
                packs: 3
            }
        );
        // Unknown / malformed lines are ignored; missing fields default to 0.
        assert_eq!(
            parse_object_counts("garbage line\ncount: 5"),
            ObjectCounts { count: 5, packs: 0 }
        );
        assert_eq!(parse_object_counts(""), ObjectCounts::default());
    }

    #[test]
    fn git_error_display_with_and_without_stderr() {
        let e = GitError {
            args: vec!["-C".into(), ".".into(), "status".into()],
            stderr: "  fatal: nope\n".into(),
            cause: "exit status: 128".into(),
        };
        assert_eq!(
            e.to_string(),
            "git -C . status: exit status: 128: fatal: nope"
        );
        let e2 = GitError {
            args: vec!["remote".into()],
            stderr: "   ".into(),
            cause: "not found".into(),
        };
        assert_eq!(e2.to_string(), "git remote: not found");
    }

    #[test]
    fn default_git_binary_honors_env_override() {
        // SAFETY: single-threaded test; restore after.
        let prev = std::env::var_os("LENSR_GIT_REAL_GIT");
        std::env::set_var("LENSR_GIT_REAL_GIT", "C:/custom/git.exe");
        assert_eq!(default_git_binary(), "C:/custom/git.exe");
        match prev {
            Some(v) => std::env::set_var("LENSR_GIT_REAL_GIT", v),
            None => std::env::remove_var("LENSR_GIT_REAL_GIT"),
        }
    }

    // Characterization test against a real repo (no upstream unit tests exist).
    // Skips when no usable git is resolvable. Uses only read/init verbs (no commit),
    // so it stays fast even if `git` resolves to the lensr_git shim.
    #[test]
    fn characterization_repo_layout_refs_config_remotes() {
        let git = default_git_binary();
        let dir = std::env::temp_dir().join(format!("fr-gitutils-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().into_owned();

        // init; if git is unusable here, skip like the Go test's t.Skip.
        if git_output(&git, &d, &["-c", "init.defaultBranch=main", "init", "-q"]).is_err() {
            eprintln!("skip characterization: no usable git ({git})");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let _ = git_output(&git, &d, &["config", "user.name", "Test"]);

        let layout = repo_layout(&git, &d).expect("repo_layout");
        assert!(!layout.bare, "fresh repo is not bare");
        assert!(
            layout.git_dir.contains(".git"),
            "git_dir looks like a git dir: {}",
            layout.git_dir
        );

        assert!(
            list_refs(&git, &d).expect("list_refs").is_empty(),
            "no refs before any commit"
        );
        assert!(
            remotes(&git, &d).expect("remotes").is_empty(),
            "no remotes configured"
        );

        assert_eq!(
            config_value(&git, &d, "user.name").expect("config user.name"),
            ("Test".to_string(), true)
        );
        assert_eq!(
            config_value(&git, &d, "no.such.key").expect("config missing"),
            (String::new(), false)
        );

        // count-objects parses without error on a real repo.
        assert!(
            count_objects(&git, &d).is_ok(),
            "count_objects should succeed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
