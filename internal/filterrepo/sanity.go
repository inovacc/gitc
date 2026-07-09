package filterrepo

import "fmt"

// SanityError is returned by SanityCheck when the repository does not look like
// a safe, fresh clone to rewrite. Its Reason is a short human-readable cause.
type SanityError struct {
	Reason string
}

func (e *SanityError) Error() string {
	return fmt.Sprintf(
		"refusing to destructively rewrite history: this does not look like a fresh clone (%s); "+
			"operate on a fresh clone, or pass --force to proceed anyway",
		e.Reason)
}

// SanityCheck refuses (by returning a *SanityError) to rewrite a repository that
// does not resemble a fresh clone, mirroring git-filter-repo's protective
// sanity_check. When force is true the check is skipped entirely.
//
// It reproduces upstream's load-bearing guards pragmatically:
//   - the object store must be freshly packed (at most one packfile and fewer
//     than 100 loose objects, matching the transfer.unpackLimit default), so a
//     history rewrite cannot silently orphan reachable objects; and
//   - a non-bare working tree must be clean (no staged, unstaged, or untracked
//     changes) so a `git reset --hard` during cleanup cannot destroy work.
//
// Deviations from upstream (documented for parity tracking): the niche
// "loose objects are replace refs" exemption, the case-insensitive/normalizing
// filesystem ref-collision checks, the single-remote / single-reflog-entry /
// unpushed-branch / multiple-worktree checks are not performed here. The
// freshly-packed and clean-tree guards are the ones that actually prevent data
// loss and are retained.
func SanityCheck(repoDir string, force bool) error {
	return sanityCheck(DefaultGitBinary, repoDir, force)
}

func sanityCheck(gitBin, repoDir string, force bool) error {
	if force {
		return nil
	}

	layout, err := RepoLayout(gitBin, repoDir)
	if err != nil {
		return fmt.Errorf("filterrepo: resolving repository layout: %w", err)
	}

	counts, err := CountObjects(gitBin, repoDir)
	if err != nil {
		return fmt.Errorf("filterrepo: counting objects: %w", err)
	}

	if counts.Packs > 1 || counts.Count >= 100 || (counts.Packs == 1 && counts.Count > 0) {
		return &SanityError{Reason: "expected a freshly packed repo"}
	}

	if !layout.Bare {
		if err := checkCleanWorktree(gitBin, repoDir); err != nil {
			return err
		}
	}

	return nil
}

// checkCleanWorktree reports a *SanityError if the working tree has staged,
// unstaged, or untracked changes.
func checkCleanWorktree(gitBin, repoDir string) error {
	staged, err := gitExitCode(gitBin, repoDir, "diff", "--staged", "--quiet")
	if err != nil {
		return fmt.Errorf("filterrepo: checking staged changes: %w", err)
	}

	if staged != 0 {
		return &SanityError{Reason: "you have staged but uncommitted changes"}
	}

	unstaged, err := gitExitCode(gitBin, repoDir, "diff", "--quiet")
	if err != nil {
		return fmt.Errorf("filterrepo: checking unstaged changes: %w", err)
	}

	if unstaged != 0 {
		return &SanityError{Reason: "you have unstaged changes"}
	}

	untracked, err := gitOutput(gitBin, repoDir, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return fmt.Errorf("filterrepo: checking untracked files: %w", err)
	}

	if untracked != "" {
		return &SanityError{Reason: "you have untracked changes"}
	}

	return nil
}
