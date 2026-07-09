// Package backend resolves which real git binary gitc executes and runs it as
// a transparent passthrough, inheriting stdio and propagating the exit code.
//
// gitc ships as `git`/`git.exe` earlier on PATH than any real git, so the
// resolver must never re-resolve `git` from PATH and exec itself. The
// self-invocation guard compares each candidate against gitc's own absolute
// executable path.
package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Kind identifies which backend served an invocation.
type Kind string

const (
	// KindManaged is a git downloaded by gitc (MinGit from git-for-windows).
	KindManaged Kind = "managed"
	// KindSystem is a compatible git already installed on PATH.
	KindSystem Kind = "system"
)

// osWindows is runtime.GOOS on Windows, factored out for the PATH-name logic.
const osWindows = "windows"

// ErrNoBackend is returned when neither a downloaded git nor a non-self system
// git can be found.
var ErrNoBackend = errors.New("no git backend found: run `gitc gitc fetch-git` to download one, or install git on PATH")

// Backend is a resolved git executable ready to exec.
type Backend struct {
	Kind Kind
	Path string // absolute path to the git binary
}

// Resolve picks a backend, preferring the managed (downloaded) git at
// managedPath and falling back to the first non-self `git` on PATH. selfPath is
// gitc's own absolute executable path (from os.Executable); candidates
// resolving to it are skipped to prevent recursive self-invocation.
func Resolve(managedPath, selfPath string) (Backend, error) {
	if managedPath != "" {
		if abs, ok := usableBinary(managedPath, selfPath); ok {
			return Backend{Kind: KindManaged, Path: abs}, nil
		}
	}

	if p, ok := findSystemGit(selfPath); ok {
		return Backend{Kind: KindSystem, Path: p}, nil
	}

	return Backend{}, ErrNoBackend
}

// findSystemGit walks PATH in order and returns the first git executable whose
// resolved path differs from selfPath.
func findSystemGit(selfPath string) (string, bool) {
	names := []string{"git"}
	if runtime.GOOS == osWindows {
		names = []string{"git.exe", "git.cmd", "git"}
	}

	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}

		for _, name := range names {
			cand := filepath.Join(dir, name)
			if abs, ok := usableBinary(cand, selfPath); ok {
				return abs, true
			}
		}
	}

	return "", false
}

// usableBinary reports whether cand is an executable regular file that is not
// gitc itself, returning its cleaned absolute path.
func usableBinary(cand, selfPath string) (string, bool) {
	abs, err := filepath.Abs(cand)
	if err != nil {
		return "", false
	}

	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}

	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		return "", false
	}

	if sameFile(abs, selfPath) {
		return "", false
	}

	return abs, true
}

// sameFile reports whether two paths refer to gitc's own binary. It compares
// resolved absolute paths (case-insensitively on Windows) and, when possible,
// os.SameFile identity.
func sameFile(a, b string) bool {
	if b == "" {
		return false
	}

	ra, rb := a, b
	if r, err := filepath.EvalSymlinks(a); err == nil {
		ra = r
	}

	if r, err := filepath.EvalSymlinks(b); err == nil {
		rb = r
	}

	if runtime.GOOS == osWindows {
		if strings.EqualFold(ra, rb) {
			return true
		}
	} else if ra == rb {
		return true
	}

	if ia, err := os.Stat(ra); err == nil {
		if ib, err := os.Stat(rb); err == nil {
			return os.SameFile(ia, ib)
		}
	}

	return false
}

// SupportsInitialBranch reports whether the backend git is new enough to accept
// `init --initial-branch` (git >= 2.28). On any error it returns false so
// callers never inject a flag an old git would reject.
func (b Backend) SupportsInitialBranch(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, b.Path, "--version").Output()
	if err != nil {
		return false
	}

	major, minor, ok := parseGitVersion(string(out))
	if !ok {
		return false
	}

	return major > 2 || (major == 2 && minor >= 28)
}

// parseGitVersion extracts the major/minor from `git version X.Y.Z` output.
func parseGitVersion(s string) (major, minor int, ok bool) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) < 3 {
		return 0, 0, false
	}

	parts := strings.SplitN(fields[2], ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}

	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}

	return major, minor, true
}

// Result is the outcome of a passthrough exec.
type Result struct {
	ExitCode int
	Duration time.Duration
}

// Run execs the backend with args, inheriting the process's stdio, and returns
// the exit code and wall-clock duration. A non-zero git exit is reported via
// Result, not err; err is reserved for failures to start the process.
func (b Backend) Run(ctx context.Context, args []string) (Result, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, b.Path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	dur := time.Since(start)

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return Result{ExitCode: exitErr.ExitCode(), Duration: dur}, nil
	}

	if err != nil {
		return Result{ExitCode: -1, Duration: dur}, fmt.Errorf("exec git backend: %w", err)
	}

	return Result{ExitCode: 0, Duration: dur}, nil
}
