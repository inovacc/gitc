package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/store"
)

// checkStatus is the outcome level of one doctor check.
type checkStatus int

const (
	statusOK checkStatus = iota
	statusWarn
	statusFail
)

func (s checkStatus) mark() string {
	switch s {
	case statusOK:
		return "[ok]  "
	case statusWarn:
		return "[warn]"
	default:
		return "[fail]"
	}
}

// runDoctor prints a health checklist of the gitc install and its backend. It
// exits non-zero if any critical (fail) check does not pass, so it is usable in
// CI or a post-install verification step.
func runDoctor(_ []string) int {
	worst := statusOK

	report := func(s checkStatus, name, detail string) {
		if s > worst {
			worst = s
		}

		fmt.Printf("%s %-22s %s\n", s.mark(), name, detail)
	}

	fmt.Println("gitc doctor:")

	report(statusOK, "gitc version", version)

	checkShim(report)
	b, ok := checkBackend(report)
	checkGitRuns(report, b, ok)
	checkShell(report, b, ok)
	checkAudit(report)

	fmt.Println()

	switch worst {
	case statusOK:
		fmt.Println("all checks passed.")
		return 0
	case statusWarn:
		fmt.Println("passed with warnings.")
		return 0
	default:
		fmt.Println("one or more checks failed.")
		return 1
	}
}

// checkShim verifies the PATH shim exists and that plain `git` resolves to it.
func checkShim(report func(checkStatus, string, string)) {
	shim := paths.ShimGitPath()

	if _, err := os.Stat(shim); err != nil {
		report(statusWarn, "shim installed", "not found; run `git install --apply`")
		return
	}

	report(statusOK, "shim installed", shim)

	resolved, err := exec.LookPath("git")
	if err != nil {
		report(statusWarn, "git on PATH", "no git resolved on PATH")
		return
	}

	if samePath(resolved, shim) {
		report(statusOK, "shim shadows git", resolved)
	} else {
		report(statusWarn, "shim shadows git", "PATH resolves git to "+resolved+" (not the shim); restart shell")
	}
}

// checkBackend resolves the git backend and reports its path and kind.
func checkBackend(report func(checkStatus, string, string)) (backend.Backend, bool) {
	self, _ := os.Executable()

	b, err := backend.Resolve(managedGitPath(), self)
	if err != nil {
		report(statusFail, "git backend", err.Error()+"; run `git fetch-git`")
		return b, false
	}

	if _, statErr := os.Stat(b.Path); statErr != nil {
		report(statusFail, "git backend", fmt.Sprintf("%s (%s) missing on disk", b.Path, b.Kind))
		return b, false
	}

	report(statusOK, "git backend", fmt.Sprintf("%s (%s)", b.Path, b.Kind))

	return b, true
}

// checkGitRuns executes `git --version` through the resolved backend.
func checkGitRuns(report func(checkStatus, string, string), b backend.Backend, ok bool) {
	if !ok {
		report(statusFail, "git executes", "no backend to run")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, b.Path, "--version").Output()
	if err != nil {
		report(statusFail, "git executes", err.Error())
		return
	}

	report(statusOK, "git executes", strings.TrimSpace(string(out)))
}

// checkShell reports whether the resolved backend can run POSIX git hooks.
// git-for-windows finds its shell in its own install tree (not the caller's
// PATH), so this is independent of whether `sh`/`bash` resolve in your shell.
func checkShell(report func(checkStatus, string, string), b backend.Backend, ok bool) {
	if runtime.GOOS != "windows" {
		report(statusOK, "shell (hooks)", "system /bin/sh")
		return
	}

	if !ok {
		report(statusWarn, "shell (hooks)", "no backend to inspect")
		return
	}

	root := filepath.Dir(filepath.Dir(b.Path)) // <version>/cmd/git.exe -> <version>
	has := func(rel ...string) bool {
		_, statErr := os.Stat(filepath.Join(root, filepath.Join(rel...)))
		return statErr == nil
	}

	bash := has("usr", "bin", "bash.exe")
	sh := has("usr", "bin", "sh.exe")
	busybox := has("mingw64", "bin", "busybox.exe") || has("mingw64", "bin", "ash.exe")

	switch {
	case bash && sh:
		report(statusOK, "shell (hooks)", "bash + sh (#!/bin/sh and #!/bin/bash)")
	case sh:
		report(statusOK, "shell (hooks)", "sh (#!/bin/sh)")
	case busybox:
		report(statusOK, "shell (hooks)", "sh via busybox (#!/bin/sh)")
	default:
		report(statusWarn, "shell (hooks)", "none — hooks won't run; run `git fetch-git --full`")
	}
}

// checkAudit verifies the audit log opens (creating it if needed).
func checkAudit(report func(checkStatus, string, string)) {
	path := auditDBPath()

	st, err := store.Open(path)
	if err != nil {
		report(statusFail, "audit log", err.Error())
		return
	}

	_ = st.Close()

	report(statusOK, "audit log", path)
}

// samePath compares two filesystem paths, resolving symlinks and case where the
// OS allows, so a shim reached via a resolved or 8.3 path still matches.
func samePath(a, b string) bool {
	if ra, err := filepath.EvalSymlinks(a); err == nil {
		a = ra
	}

	if rb, err := filepath.EvalSymlinks(b); err == nil {
		b = rb
	}

	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
