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
	"github.com/inovacc/gitc/internal/installer/shim"
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

	if err := placeShims(self, shimDir, shimGit); err != nil {
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

// placeShims installs the PATH-shadowing shims. On Windows it uses the tiny
// launcher model (ADR 0007): one canonical gitc.exe under BinDir, and
// git/sh/bash.exe launcher shims (embedded shim.c) that exec it via sibling
// .shim files. On other platforms the git shim is simply a copy of gitc, since
// the git proxy there IS the gitc binary.
func placeShims(self, shimDir, shimGit string) error {
	if runtime.GOOS != osWindows {
		if sameExe(self, shimGit) {
			return nil
		}

		return copyExecutable(self, shimGit)
	}

	return placeWindowsLaunchers(self, shimDir)
}

// placeWindowsLaunchers writes the canonical gitc.exe plus the git/sh/bash.exe
// launcher shims and their .shim files. The persona for sh/bash rides in the
// .shim `args` line via gitc's own meta commands (`git gitc sh|bash`), so all
// three launchers are one shared inode pointing at one real binary.
func placeWindowsLaunchers(self, shimDir string) error {
	launcher := shim.Binary(runtime.GOARCH)
	if launcher == nil {
		// No prebuilt launcher for this arch — fall back to copying gitc as the
		// git shim so install still works (larger, but functional).
		return copyExecutable(self, filepath.Join(shimDir, "git.exe"))
	}

	// 1. Place the single canonical gitc binary the launchers exec into. Skip
	//    when we already ARE it (a re-install invoked through the launcher):
	//    Windows cannot overwrite a running exe, and no copy is needed.
	canonical := paths.CanonicalPath()
	if err := os.MkdirAll(filepath.Dir(canonical), 0o755); err != nil {
		return fmt.Errorf("create bin dir: %w", err)
	}

	if err := swapExecutable(self, canonical); err != nil {
		return err
	}

	// 2. Write the launcher as git.exe and hard-link sh/bash.exe to it, so all
	//    three names share one small inode.
	gitExe := filepath.Join(shimDir, "git.exe")
	if err := writeLauncher(gitExe, launcher); err != nil {
		return err
	}

	for _, name := range []string{"sh.exe", "bash.exe"} {
		_ = linkShim(gitExe, filepath.Join(shimDir, name)) // best-effort; not fatal
	}

	// 3. Write each launcher's .shim. git has no args (pure passthrough); sh/bash
	//    carry gitc's shell meta command so hooks resolve without a system shell.
	shims := map[string]string{
		"git.shim":  "",
		"sh.shim":   "gitc sh",
		"bash.shim": "gitc bash",
	}
	for name, args := range shims {
		if err := writeShimFile(filepath.Join(shimDir, name), canonical, args); err != nil {
			return err
		}
	}

	return nil
}

// swapExecutable installs src at dst even when dst is a running executable —
// Windows locks a running .exe against truncation, but a running .exe can still
// be renamed. It moves the old binary aside as <dst>.old (swept on a later
// startup) and copies the new one into place, rolling back on failure. A no-op
// when src already IS dst (a re-install invoked through the canonical itself).
func swapExecutable(src, dst string) error {
	if sameExe(src, dst) {
		return nil
	}

	old := dst + ".old"
	_ = os.Remove(old)

	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			return fmt.Errorf("move current binary aside: %w", err)
		}
	}

	if err := copyExecutable(src, dst); err != nil {
		_ = os.Rename(old, dst) // best-effort rollback
		return err
	}

	return nil
}

// writeLauncher writes the embedded launcher bytes to path (recreating it so a
// stale inode with existing hard links is replaced, not mutated in place).
func writeLauncher(path string, data []byte) error {
	_ = os.Remove(path)

	if err := os.WriteFile(path, data, 0o755); err != nil {
		return fmt.Errorf("write launcher %s: %w", filepath.Base(path), err)
	}

	return nil
}

// writeShimFile writes a scoop-format .shim consumed by shim.c: `path = <target>`
// and, when args is non-empty, `args = <args>`. UTF-8 with LF line endings.
func writeShimFile(path, target, args string) error {
	var b strings.Builder

	b.WriteString("path = ")
	b.WriteString(target)
	b.WriteString("\n")

	if args != "" {
		b.WriteString("args = ")
		b.WriteString(args)
		b.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}

	return nil
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

	// Also remove the canonical binary the launchers exec'd into. Best-effort:
	// on Windows a re-install via the launcher runs the canonical itself, which
	// cannot delete its own running image — the leftover is swept on next start.
	_ = os.RemoveAll(paths.BinDir())

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
