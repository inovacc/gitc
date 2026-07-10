package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/inovacc/gitc/internal/backend"
)

// shellName returns "sh" or "bash" when the program was invoked under that name
// (via an installed shim), else "". A copy of gitc named sh.exe / bash.exe thus
// acts as a launcher for the managed git backend's shell.
func shellName(arg0 string) string {
	base := strings.ToLower(filepath.Base(arg0))
	base = strings.TrimSuffix(base, ".exe")

	switch base {
	case "sh", "bash":
		return base
	default:
		return ""
	}
}

// runShell execs the managed git backend's POSIX shell — found in the backend's
// own install tree, not the caller's PATH — with args, inheriting stdio and
// propagating the exit code.
func runShell(name string, args []string) int {
	self, _ := os.Executable()

	b, err := backend.Resolve(managedGitPath(), self)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc %s: %v\n", name, err)
		return 1
	}

	root := filepath.Dir(filepath.Dir(b.Path)) // <version>/cmd/git.exe -> <version>

	shell := findBackendShell(root, name)
	if shell == "" {
		fmt.Fprintf(os.Stderr, "gitc %s: no %s in the git backend; run `git fetch-git --full`\n", name, name)
		return 1
	}

	cmd := exec.CommandContext(context.Background(), shell, args...) //nolint:gosec // resolved managed backend shell
	cmd.Env = shellEnv(root)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}

		fmt.Fprintf(os.Stderr, "gitc %s: %v\n", name, err)

		return 1
	}

	return 0
}

// shellEnv returns the environment for a launched shell with the backend's unix
// tool dirs (usr/bin, mingw64/bin, bin) prepended to PATH, so the shell has ls,
// grep, uname, etc. even when nothing is on the caller's PATH.
func shellEnv(root string) []string {
	prefix := strings.Join([]string{
		filepath.Join(root, "usr", "bin"),
		filepath.Join(root, "mingw64", "bin"),
		filepath.Join(root, "bin"),
	}, string(os.PathListSeparator))

	env := os.Environ()

	for i, kv := range env {
		if len(kv) >= 5 && strings.EqualFold(kv[:5], "PATH=") {
			env[i] = "PATH=" + prefix + string(os.PathListSeparator) + kv[5:]
			return env
		}
	}

	return append(env, "PATH="+prefix)
}

// findBackendShell locates name's shell in the backend install tree, trying the
// full/MinGit path then the busybox layout (ash serves as sh). Returns "" when
// absent (e.g. the minimal MinGit, or bash under busybox).
func findBackendShell(root, name string) string {
	candidates := []string{filepath.Join(root, "usr", "bin", name+".exe")}
	if name == "sh" {
		candidates = append(candidates, filepath.Join(root, "mingw64", "bin", "ash.exe"))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return ""
}
