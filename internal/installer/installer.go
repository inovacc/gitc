// Package installer sets up gitc's PATH-precedence shadowing: it copies the
// running gitc binary into a dedicated shim directory as git/git.exe, then
// (optionally) prepends that directory to the user's PATH so shell invocations
// of `git` resolve to the wrapper first.
//
// No files under any existing git install are modified. Shadowing is purely a
// matter of PATH ordering, and is reversible via Uninstall.
package installer

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/paths"
)

const osWindows = "windows"

// Result reports what an install performed and what the user must still do.
type Result struct {
	ShimDir     string
	ShimGit     string
	BackendPath string // resolved real git that the shim will delegate to
	PathApplied bool   // true if PATH was mutated automatically
	Instruction string // manual PATH step when not applied
}

// Install copies the current gitc executable into the shim directory as
// git/git.exe. When applyPath is true it also prepends the shim dir to the
// user's PATH (Windows only, via the user environment); otherwise it returns a
// platform-appropriate manual instruction.
func Install(applyPath bool) (Result, error) {
	self, err := os.Executable()
	if err != nil {
		return Result{}, fmt.Errorf("resolve own path: %w", err)
	}

	self, _ = filepath.Abs(self)

	shimDir := paths.ShimDir()
	shimGit := paths.ShimGitPath()

	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create shim dir: %w", err)
	}

	// A resolvable backend is NOT required to install. The shim shadows git, and
	// on first use gitc auto-provisions the pinned MinGit (Windows) or resolves a
	// system git / `git fetch-git`. Resolution skips the shim binary as "self";
	// BackendPath is left empty when no backend exists yet (a fresh machine).
	b, _ := backend.Resolve(paths.ManagedGitPath(), shimGit) //nolint:errcheck // missing backend is non-fatal here

	// Copy gitc into the shim dir — unless we are already running *as* the shim
	// (e.g. `git gitc install` where git is the installed shim). Windows cannot
	// overwrite a running executable, and no copy is needed since the shim is
	// already this exact binary; only the PATH step (if any) still applies.
	if !sameExe(self, shimGit) {
		if err := copyExecutable(self, shimGit); err != nil {
			return Result{}, err
		}
	}

	// On Windows also install sh/bash launcher shims — the same gitc binary,
	// which self-detects its name and execs the managed backend's shell, so
	// scripts and hooks that call sh/bash resolve even with no system shell.
	// These are HARD LINKS to the git shim (same dir = same volume), so all
	// three names share one inode instead of three ~15 MB copies.
	if runtime.GOOS == osWindows {
		for _, name := range []string{"sh.exe", "bash.exe"} {
			_ = linkShim(shimGit, filepath.Join(shimDir, name)) // best-effort; not fatal
		}
	}

	res := Result{
		ShimDir:     shimDir,
		ShimGit:     shimGit,
		BackendPath: b.Path,
	}

	if applyPath {
		if err := prependUserPath(shimDir); err != nil {
			return res, fmt.Errorf("apply PATH: %w", err)
		}

		res.PathApplied = true

		return res, nil
	}

	res.Instruction = manualPathInstruction(shimDir)

	return res, nil
}

// linkShim makes dst a hard link to src (same shim dir ⇒ same volume), so the
// sh/bash shims share the git shim's bytes instead of duplicating them. dst is
// recreated each install so it tracks the freshly-written git shim; on any link
// failure (e.g. a filesystem without hard links) it falls back to a copy.
func linkShim(src, dst string) error {
	if sameExe(src, dst) {
		return nil // already the same file
	}

	_ = os.Remove(dst)

	if err := os.Link(src, dst); err == nil {
		return nil
	}

	return copyExecutable(src, dst)
}

// sameExe reports whether two paths refer to the same executable — by cleaned
// path (case-insensitively on Windows) or by file identity.
func sameExe(a, b string) bool {
	if runtime.GOOS == osWindows {
		if strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
			return true
		}
	} else if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}

	ia, e1 := os.Stat(a)

	ib, e2 := os.Stat(b)

	return e1 == nil && e2 == nil && os.SameFile(ia, ib)
}

// Uninstall removes the shim directory. PATH cleanup is left to the user (or a
// future automated step) and described in the returned instruction.
func Uninstall() (string, error) {
	shimDir := paths.ShimDir()
	if err := os.RemoveAll(shimDir); err != nil {
		return "", fmt.Errorf("remove shim dir: %w", err)
	}

	return fmt.Sprintf("Removed %s. Remove it from PATH to fully undo shadowing.", shimDir), nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open self: %w", err)
	}

	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create shim git: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy shim git: %w", err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("finalize shim git: %w", err)
	}

	return nil
}

func manualPathInstruction(shimDir string) string {
	if runtime.GOOS == osWindows {
		return fmt.Sprintf(
			"Prepend the shim dir to your user PATH (PowerShell):\n"+
				"  [Environment]::SetEnvironmentVariable('Path', '%s;' + "+
				"[Environment]::GetEnvironmentVariable('Path','User'), 'User')\n"+
				"Then restart your shell. Or re-run: gitc gitc install --apply",
			shimDir)
	}

	return fmt.Sprintf(
		"Prepend the shim dir to PATH in your shell profile (e.g. ~/.bashrc):\n"+
			"  export PATH=\"%s:$PATH\"\n"+
			"Then restart your shell.", shimDir)
}

// prependUserPath prepends dir to the persistent user PATH. Implemented for
// Windows via the user environment (non-truncating, unlike setx); other
// platforms return an error directing the user to the manual instruction,
// since editing shell rc files automatically is intentionally out of scope.
func prependUserPath(dir string) error {
	if runtime.GOOS != osWindows {
		return fmt.Errorf("automatic PATH apply is Windows-only; %s", manualPathInstruction(dir))
	}
	// Read the current user PATH, prepend dir if absent, write it back — all
	// via PowerShell's Environment API to avoid setx's 1024-char truncation.
	script := fmt.Sprintf(
		"$d='%s';"+
			"$p=[Environment]::GetEnvironmentVariable('Path','User');"+
			"if(-not $p){$p=''};"+
			"if(($p -split ';') -notcontains $d){"+
			"[Environment]::SetEnvironmentVariable('Path', $d + ';' + $p, 'User')}",
		strings.ReplaceAll(dir, "'", "''"))
	cmd := exec.CommandContext(context.Background(), "powershell", "-NoProfile", "-NonInteractive", "-Command", script)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell set user PATH: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
