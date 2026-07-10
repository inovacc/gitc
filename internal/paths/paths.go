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

// PolicyPath returns the path to policy.json, the machine/org enforcement
// policy (secret gate, remote allowlist). Absent means no enforcement.
func PolicyPath() string {
	return filepath.Join(DataDir(), "policy.json")
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
