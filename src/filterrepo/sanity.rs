//! Fresh-clone safety check (Rust port of git-filter-repo's sanity_check).
//!
//! Refuses to rewrite a repository that does not resemble a fresh clone
//! (git-filter-repo's protective `sanity_check`). Retains the two load-bearing
//! guards that actually prevent data loss — the object store must be freshly
//! packed, and a non-bare worktree must be clean — and documents the upstream
//! checks intentionally omitted (see the module history).

use std::error::Error;
use std::fmt;

use super::gitutils::{self, GitError};

/// Returned when the repository does not look like a safe, fresh clone.
#[derive(Debug)]
pub struct SanityError {
    pub reason: String,
}

impl fmt::Display for SanityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing to destructively rewrite history: this does not look like a fresh clone ({}); \
             operate on a fresh clone, or pass --force to proceed anyway",
            self.reason
        )
    }
}

impl Error for SanityError {}

/// Errors from [`sanity_check`]: a fresh-clone refusal, or a wrapped git failure.
#[derive(Debug)]
pub enum SanityCheckError {
    NotFresh(SanityError),
    Git { context: String, source: GitError },
}

impl fmt::Display for SanityCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SanityCheckError::NotFresh(e) => write!(f, "{e}"),
            SanityCheckError::Git { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl Error for SanityCheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SanityCheckError::NotFresh(e) => Some(e),
            SanityCheckError::Git { source, .. } => Some(source),
        }
    }
}

fn not_fresh(reason: &str) -> SanityCheckError {
    SanityCheckError::NotFresh(SanityError {
        reason: reason.to_string(),
    })
}

fn git_ctx(context: &str, source: GitError) -> SanityCheckError {
    SanityCheckError::Git {
        context: format!("filterrepo: {context}"),
        source,
    }
}

/// Refuse (with a [`SanityCheckError::NotFresh`]) to rewrite a repository that
/// does not resemble a fresh clone. `force` skips the check entirely.
///
/// Guards: (1) the object store must be freshly packed (≤1 packfile and <100
/// loose objects, matching `transfer.unpackLimit`), so a rewrite cannot silently
/// orphan reachable objects; (2) a non-bare worktree must be clean (no staged,
/// unstaged, or untracked changes) so a later `git reset --hard` cannot destroy
/// work.
pub fn sanity_check(git_bin: &str, repo_dir: &str, force: bool) -> Result<(), SanityCheckError> {
    if force {
        return Ok(());
    }

    let layout = gitutils::repo_layout(git_bin, repo_dir)
        .map_err(|e| git_ctx("resolving repository layout", e))?;
    let counts =
        gitutils::count_objects(git_bin, repo_dir).map_err(|e| git_ctx("counting objects", e))?;

    if counts.packs > 1 || counts.count >= 100 || (counts.packs == 1 && counts.count > 0) {
        return Err(not_fresh("expected a freshly packed repo"));
    }

    if !layout.bare {
        check_clean_worktree(git_bin, repo_dir)?;
    }

    Ok(())
}

/// Report a [`SanityCheckError::NotFresh`] if the working tree has staged,
/// unstaged, or untracked changes.
fn check_clean_worktree(git_bin: &str, repo_dir: &str) -> Result<(), SanityCheckError> {
    let staged = gitutils::git_exit_code(git_bin, repo_dir, &["diff", "--staged", "--quiet"])
        .map_err(|e| git_ctx("checking staged changes", e))?;
    if staged != 0 {
        return Err(not_fresh("you have staged but uncommitted changes"));
    }

    let unstaged = gitutils::git_exit_code(git_bin, repo_dir, &["diff", "--quiet"])
        .map_err(|e| git_ctx("checking unstaged changes", e))?;
    if unstaged != 0 {
        return Err(not_fresh("you have unstaged changes"));
    }

    let untracked = gitutils::git_output(
        git_bin,
        repo_dir,
        &["ls-files", "--others", "--exclude-standard"],
    )
    .map_err(|e| git_ctx("checking untracked files", e))?;
    if !untracked.is_empty() {
        return Err(not_fresh("you have untracked changes"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_error_message() {
        let e = SanityError {
            reason: "expected a freshly packed repo".into(),
        };
        assert!(e
            .to_string()
            .contains("does not look like a fresh clone (expected a freshly packed repo)"));
        assert!(e.to_string().contains("--force"));
    }

    // Characterization against a fresh repo (no upstream unit tests). Uses only
    // init + read verbs + an untracked file (no commit) so it stays fast. Skips
    // when no usable git is resolvable.
    #[test]
    fn fresh_repo_passes_untracked_file_refused_force_skips() {
        let git = gitutils::default_git_binary();
        let dir = std::env::temp_dir().join(format!("fr-sanity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().into_owned();

        if gitutils::git_output(&git, &d, &["-c", "init.defaultBranch=main", "init", "-q"]).is_err()
        {
            eprintln!("skip sanity characterization: no usable git ({git})");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        // A freshly-initialized, empty repo is a clean, fresh clone.
        sanity_check(&git, &d, false).expect("fresh empty repo passes sanity");

        // An untracked file makes the worktree unclean → refused.
        std::fs::write(dir.join("stray.txt"), b"x").unwrap();
        match sanity_check(&git, &d, false) {
            Err(SanityCheckError::NotFresh(e)) => {
                assert!(e.reason.contains("untracked"), "reason: {}", e.reason)
            }
            other => panic!("expected NotFresh(untracked), got {other:?}"),
        }

        // ...but --force skips the whole check.
        sanity_check(&git, &d, true).expect("force skips sanity");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
