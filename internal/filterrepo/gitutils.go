package filterrepo

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// DefaultGitBinary is the git executable used when a caller does not supply an
// explicit one. It is looked up on PATH by os/exec. Callers embedded inside a
// tool that ships its own `git` shim (such as gitc) should pass the resolved
// real-git path instead, to avoid re-entering the shim.
const DefaultGitBinary = "git"

// RepoInfo describes the on-disk layout of a git repository, as reported by
// `git rev-parse`.
type RepoInfo struct {
	// GitDir is the value of `git rev-parse --git-dir` (may be relative, e.g.
	// ".git" for a non-bare repo run from its worktree root).
	GitDir string
	// Bare reports whether the repository is bare.
	Bare bool
}

// ObjectCounts holds the fields of `git count-objects -v` that the sanity check
// consults: the number of loose objects and the number of packfiles.
type ObjectCounts struct {
	// Count is the number of loose (unpacked) objects.
	Count int
	// Packs is the number of packfiles in the object store.
	Packs int
}

// gitError wraps a failed git invocation with its captured stderr so callers get
// an actionable message rather than a bare exit code.
type gitError struct {
	args   []string
	stderr string
	err    error
}

func (e *gitError) Error() string {
	msg := strings.TrimSpace(e.stderr)
	if msg == "" {
		return fmt.Sprintf("git %s: %v", strings.Join(e.args, " "), e.err)
	}
	return fmt.Sprintf("git %s: %v: %s", strings.Join(e.args, " "), e.err, msg)
}

func (e *gitError) Unwrap() error { return e.err }

// gitOutput runs `<gitBin> -C dir args...` and returns its stdout with trailing
// whitespace trimmed. A non-zero exit is returned as a *gitError carrying stderr.
func gitOutput(gitBin, dir string, args ...string) (string, error) {
	if gitBin == "" {
		gitBin = DefaultGitBinary
	}
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command(gitBin, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", &gitError{args: full, stderr: stderr.String(), err: err}
	}
	return strings.TrimRight(stdout.String(), "\r\n \t"), nil
}

// gitExitCode runs a git command purely for its exit status. It returns the exit
// code (0 for success, positive for a clean non-zero exit such as `diff
// --quiet` reporting differences) and a non-nil error only when the process
// could not be started or exited abnormally.
func gitExitCode(gitBin, dir string, args ...string) (int, error) {
	if gitBin == "" {
		gitBin = DefaultGitBinary
	}
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command(gitBin, full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, &gitError{args: full, stderr: stderr.String(), err: err}
}

// RepoLayout resolves the git directory and bareness of the repository rooted at
// dir via `git rev-parse`.
func RepoLayout(gitBin, dir string) (RepoInfo, error) {
	bare, err := gitOutput(gitBin, dir, "rev-parse", "--is-bare-repository")
	if err != nil {
		return RepoInfo{}, err
	}
	gitDir, err := gitOutput(gitBin, dir, "rev-parse", "--git-dir")
	if err != nil {
		return RepoInfo{}, err
	}
	return RepoInfo{GitDir: gitDir, Bare: bare == "true"}, nil
}

// CountObjects parses `git count-objects -v`, returning the loose-object and
// packfile counts. Unknown lines are ignored.
func CountObjects(gitBin, dir string) (ObjectCounts, error) {
	out, err := gitOutput(gitBin, dir, "count-objects", "-v")
	if err != nil {
		return ObjectCounts{}, err
	}
	var counts ObjectCounts
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(val))
		if convErr != nil {
			continue
		}
		switch strings.TrimSpace(key) {
		case "count":
			counts.Count = n
		case "packs":
			counts.Packs = n
		}
	}
	return counts, nil
}

// ListRefs returns every ref in the repository (full refname form, e.g.
// "refs/heads/main") via `git for-each-ref`.
func ListRefs(gitBin, dir string) ([]string, error) {
	out, err := gitOutput(gitBin, dir, "for-each-ref", "--format=%(refname)")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// ConfigValue reads a single git config value. ok is false (with a nil error)
// when the key is unset; a genuine failure is reported through err.
func ConfigValue(gitBin, dir, key string) (val string, ok bool, err error) {
	code, cerr := gitExitCode(gitBin, dir, "config", "--get", key)
	if cerr != nil {
		return "", false, cerr
	}
	if code == 1 {
		// git config exits 1 when the key is absent.
		return "", false, nil
	}
	out, gerr := gitOutput(gitBin, dir, "config", "--get", key)
	if gerr != nil {
		return "", false, gerr
	}
	return out, true, nil
}

// Remotes returns the configured remote names via `git remote`.
func Remotes(gitBin, dir string) ([]string, error) {
	out, err := gitOutput(gitBin, dir, "remote")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}
