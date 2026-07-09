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

	// Guard: a real git must be resolvable once the shim shadows git, or we'd
	// break git entirely. Resolution skips the shim binary as "self".
	b, err := backend.Resolve(paths.VendoredGitPath(), shimGit)
	if err != nil {
		return Result{}, fmt.Errorf("refusing to install: %w", err)
	}

	if err := copyExecutable(self, shimGit); err != nil {
		return Result{}, err
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
	if runtime.GOOS == "windows" {
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
	if runtime.GOOS != "windows" {
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
