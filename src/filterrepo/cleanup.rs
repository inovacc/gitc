//! Post-rewrite maintenance (Rust port of git-filter-repo's reflog-expire + gc).
//!
//! Post-rewrite maintenance git-filter-repo runs after a successful import: for a
//! non-bare repo, hard-reset the worktree onto the rewritten HEAD, then expire all
//! reflogs and run an aggressive gc so the old, now-unreachable history is pruned
//! rather than lingering as loose objects. Any git command exiting non-zero is
//! fatal.

use std::error::Error;
use std::fmt;

use super::gitutils::{self, GitError};

/// A cleanup step that failed.
#[derive(Debug)]
pub struct CleanupError {
    pub step: String,
    pub source: GitError,
}

impl fmt::Display for CleanupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "filterrepo: cleanup step {:?} failed: {}",
            self.step, self.source
        )
    }
}

impl Error for CleanupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Run the post-rewrite maintenance. `bare` skips the worktree reset.
pub fn cleanup(git_bin: &str, repo_dir: &str, bare: bool) -> Result<(), CleanupError> {
    let mut steps: Vec<(&str, Vec<&str>)> = Vec::new();
    if !bare {
        steps.push(("reset", vec!["reset", "--quiet", "--hard"]));
    }
    steps.push((
        "reflog expire",
        vec!["reflog", "expire", "--expire=now", "--all"],
    ));
    steps.push(("gc", vec!["gc", "--quiet", "--prune=now"]));

    for (name, args) in steps {
        gitutils::git_output(git_bin, repo_dir, &args).map_err(|e| CleanupError {
            step: name.to_string(),
            source: e,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Characterization: reflog-expire + gc on a fresh repo (bare=true skips the
    // reset, which would fail on a repo with no HEAD). Skips when git is unusable.
    #[test]
    fn reflog_expire_and_gc_on_fresh_repo() {
        let git = gitutils::default_git_binary();
        let dir = std::env::temp_dir().join(format!("fr-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_string_lossy().into_owned();

        if gitutils::git_output(&git, &d, &["-c", "init.defaultBranch=main", "init", "-q"]).is_err()
        {
            eprintln!("skip cleanup characterization: no usable git ({git})");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        // bare=true → only reflog-expire + gc, both valid on an empty repo.
        cleanup(&git, &d, true).expect("reflog-expire + gc should succeed on a fresh repo");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
