package filterrepo

import "fmt"

// Cleanup performs the post-rewrite repository maintenance that git-filter-repo
// runs after a successful import: for a non-bare repo it first resets the
// working tree hard onto the rewritten HEAD, then it expires all reflogs and
// runs an aggressive gc so the old, now-unreachable history is actually pruned
// rather than lingering as loose objects.
//
// Any git command exiting non-zero is fatal and returned as an error; the
// caller must treat a failed cleanup as a failed run.
func Cleanup(repoDir string, bare bool) error {
	return cleanup(DefaultGitBinary, repoDir, bare)
}

func cleanup(gitBin, repoDir string, bare bool) error {
	type step struct {
		name string
		args []string
	}
	var steps []step
	if !bare {
		steps = append(steps, step{"reset", []string{"reset", "--quiet", "--hard"}})
	}
	steps = append(steps,
		step{"reflog expire", []string{"reflog", "expire", "--expire=now", "--all"}},
		step{"gc", []string{"gc", "--quiet", "--prune=now"}},
	)

	for _, s := range steps {
		if _, err := gitOutput(gitBin, repoDir, s.args...); err != nil {
			return fmt.Errorf("filterrepo: cleanup step %q failed: %w", s.name, err)
		}
	}
	return nil
}
