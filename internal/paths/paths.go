// Package paths resolves the platform-specific locations gitc uses for its
// audit database, downloaded git backend, and configuration.
//
// Windows uses %LOCALAPPDATA%\gitc; other platforms follow the XDG base
// directory spec (~/.local/share/gitc and ~/.config/gitc), falling back to
// ~/.gitc when neither is resolvable.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	appName   = "gitc"
	osWindows = "windows"
)

// DataDir returns the base directory for gitc's mutable state (audit DB,
// downloaded git backend). The directory is not created here; callers create it
// with the permissions they need.
func DataDir() string {
	if runtime.GOOS == osWindows {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, appName)
		}
	}

	if base := os.Getenv("XDG_DATA_HOME"); base != "" {
		return filepath.Join(base, appName)
	}

	if home, err := os.UserHomeDir(); err == nil {
		if runtime.GOOS == osWindows {
			return filepath.Join(home, "AppData", "Local", appName)
		}

		return filepath.Join(home, ".local", "share", appName)
	}

	return filepath.Join(".", "."+appName)
}

// ConfigDir returns the base directory for gitc's user configuration.
func ConfigDir() string {
	if runtime.GOOS == osWindows {
		return DataDir()
	}

	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, appName)
	}

	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", appName)
	}

	return DataDir()
}

// AuditDBPath returns the absolute path to the forensic audit SQLite database.
func AuditDBPath() string {
	return filepath.Join(DataDir(), "audit", appName+".db")
}

// ShimDir returns the directory where `gitc gitc install` places a copy of
// itself named git/git.exe. Placing this directory earlier on PATH than the
// real git shadows it (PATH-precedence, no file overwrite).
func ShimDir() string {
	return filepath.Join(DataDir(), "shim")
}

// ShimGitPath returns the shimmed git binary path inside ShimDir.
func ShimGitPath() string {
	name := "git"
	if runtime.GOOS == osWindows {
		name = "git.exe"
	}

	return filepath.Join(ShimDir(), name)
}

// BinDir returns the directory holding the canonical gitc binary that the
// installed launcher shims (git/sh/bash.exe) exec into. Keeping one real binary
// here — rather than a full copy per shim name — is what lets the shims be tiny
// launchers (vendored shim.c) instead of ~15 MB copies.
func BinDir() string {
	return filepath.Join(DataDir(), "bin")
}

// CanonicalPath returns the path to the canonical gitc binary under BinDir —
// the target the launcher shims' `.shim` files point at, and the binary that
// `git update` replaces in place.
func CanonicalPath() string {
	name := appName
	if runtime.GOOS == osWindows {
		name = appName + ".exe"
	}

	return filepath.Join(BinDir(), name)
}

// GitCacheDir returns the LEGACY directory where downloaded MinGit
// distributions were unpacked, one subdirectory per release tag. New installs
// use AppDir (ADR 0005); this remains for resolving and migrating older installs.
func GitCacheDir() string {
	return filepath.Join(DataDir(), "git")
}

// AppDir returns the directory holding UUID-namespaced managed-git installs,
// one per download: app/<uuidv7>/<version>/ (ADR 0005). Naming each install
// with a fresh UUID means a new download never touches the in-use install, and
// settings.json's backend pointer selects the active one.
func AppDir() string {
	return filepath.Join(DataDir(), "app")
}

// SettingsPath returns the path to settings.json, gitc's on-disk source of
// truth for the active backend pointer and the update policy (ADR 0005).
func SettingsPath() string {
	return filepath.Join(DataDir(), "settings.json")
}

// PolicyPath returns the DEPRECATED per-user policy.json location. It is derived
// from the agent-mutable LOCALAPPDATA/XDG_DATA_HOME, so enforcement policy should
// live at MachinePolicyPath instead; this remains a fallback for migration.
func PolicyPath() string {
	return filepath.Join(DataDir(), "policy.json")
}

// MachineConfigDir returns the machine-wide (admin-owned) config directory for
// gitc's enforcement policy. It is deliberately NOT derived from the per-user,
// agent-mutable LOCALAPPDATA/XDG_DATA_HOME, so a compromised agent cannot
// relocate the policy to an empty dir to disable the gate. Windows uses
// %ProgramData%\gitc (falling back to C:\ProgramData); other platforms /etc/gitc.
func MachineConfigDir() string {
	if runtime.GOOS == osWindows {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}

		return filepath.Join(base, appName)
	}

	return filepath.Join("/etc", appName)
}

// MachinePolicyPath is the primary (machine-wide) policy.json location.
func MachinePolicyPath() string {
	return filepath.Join(MachineConfigDir(), "policy.json")
}

// EnforceMarkerPath is a machine-wide marker file: when present, a missing or
// unreadable policy fails CLOSED (blocks) rather than defaulting to no
// enforcement — so relocating the user dir to an empty path cannot disable the
// gate on a host where enforcement was provisioned.
func EnforceMarkerPath() string {
	return filepath.Join(MachineConfigDir(), "ENFORCE")
}

// ManagedGitPath returns the path to the newest downloaded MinGit git binary
// (fetched by `gitc gitc fetch-git`), or "" if none is cached. Override the
// backend explicitly with GITC_GIT_BACKEND.
func ManagedGitPath() string {
	entries, err := os.ReadDir(GitCacheDir())
	if err != nil {
		return ""
	}

	var (
		newest    string
		newestMod int64
	)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		gitExe := filepath.Join(GitCacheDir(), e.Name(), "cmd", "git.exe")

		info, err := os.Stat(gitExe)
		if err != nil {
			continue
		}

		if m := info.ModTime().UnixNano(); m >= newestMod {
			newestMod = m
			newest = gitExe
		}
	}

	return newest
}
