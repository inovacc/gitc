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

	"github.com/charmbracelet/lipgloss"
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

// Doctor styling (lipgloss): a violet title banner, colored status badges, and
// a subtle footer — a one-shot styled checklist. lipgloss auto-detects the
// terminal's color profile and strips ANSI when output is piped or NO_COLOR is
// set, so the same render is safe for CI and pipes.
var (
	dcTitle = lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#4C1D95")).Padding(0, 1)
	dcOK   = lipgloss.NewStyle().Foreground(lipgloss.Color("#22C55E"))
	dcWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B"))
	dcFail = lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444"))
	dcHelp = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
)

// badge renders the colored status pill for a check (fixed 6 visible columns so
// the label/detail columns stay aligned regardless of ANSI).
func (s checkStatus) badge() string {
	switch s {
	case statusOK:
		return dcOK.Render("[ ok ]")
	case statusWarn:
		return dcWarn.Render("[warn]")
	default:
		return dcFail.Render("[fail]")
	}
}

// checkResult is one collected doctor check: its outcome, a short label, and a
// detail string (which also carries any remediation hint).
type checkResult struct {
	status checkStatus
	label  string
	detail string
}

// runDoctor health-checks the gitc install and its backend and prints a one-shot
// styled checklist. It exits non-zero if any critical (fail) check does not
// pass, so it stays usable in CI or a post-install verification step.
func runDoctor(_ []string) int {
	results, worst := collectChecks()

	fmt.Println(dcTitle.Render("◆ gitc doctor "+version) + "\n")

	for _, r := range results {
		fmt.Printf("%s  %-22s %s\n", r.status.badge(), r.label, r.detail)
	}

	fmt.Println("\n" + summaryLine(worst))
	fmt.Println(dcHelp.Render("checks only — no repo data read; `git where` shows resolved paths."))

	return exitCodeFor(worst)
}

// summaryLine renders the overall verdict, colored by the worst status.
func summaryLine(worst checkStatus) string {
	switch worst {
	case statusOK:
		return dcOK.Render("all checks passed.")
	case statusWarn:
		return dcWarn.Render("passed with warnings.")
	default:
		return dcFail.Render("one or more checks failed.")
	}
}

// collectChecks runs every doctor check and returns the results plus the worst
// status seen.
func collectChecks() ([]checkResult, checkStatus) {
	var (
		results []checkResult
		worst   = statusOK
	)

	report := func(s checkStatus, name, detail string) {
		if s > worst {
			worst = s
		}

		results = append(results, checkResult{status: s, label: name, detail: detail})
	}

	report(statusOK, "gitc version", version)

	checkShim(report)
	b, ok := checkBackend(report)
	checkGitRuns(report, b, ok)
	checkShell(report, b, ok)
	checkAudit(report)

	return results, worst
}

// exitCodeFor maps the worst check status to a process exit code (fail → 1).
func exitCodeFor(worst checkStatus) int {
	if worst == statusFail {
		return 1
	}

	return 0
}

// checkShim verifies the PATH shim exists and that plain `git` resolves to it.
func checkShim(report func(checkStatus, string, string)) {
	shim := paths.ShimGitPath()

	if _, err := os.Stat(shim); err != nil {
		report(statusWarn, "shim installed", "not found; run `git install --apply`")
		return
	}

	report(statusOK, "shim installed", shim)

	// On Windows the shim is a tiny launcher that execs the canonical gitc.exe;
	// verify that target exists (its absence would break every shimmed call).
	if runtime.GOOS == osWindows {
		canonical := paths.CanonicalPath()
		if _, err := os.Stat(canonical); err == nil {
			report(statusOK, "launcher target", canonical)
		} else {
			report(statusWarn, "launcher target", "canonical gitc.exe missing; run `git install`")
		}
	}

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
	if runtime.GOOS != osWindows {
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
