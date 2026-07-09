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

const appName = "gitc"

// DataDir returns the base directory for gitc's mutable state (audit DB,
// vendored git build). The directory is not created here; callers create it
// with the permissions they need.
func DataDir() string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, appName)
		}
	}
	if base := os.Getenv("XDG_DATA_HOME"); base != "" {
		return filepath.Join(base, appName)
	}
	if home, err := os.UserHomeDir(); err == nil {
		if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Local", appName)
		}
		return filepath.Join(home, ".local", "share", appName)
	}
	return filepath.Join(".", "."+appName)
}

// ConfigDir returns the base directory for gitc's user configuration.
func ConfigDir() string {
	if runtime.GOOS == "windows" {
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
	if runtime.GOOS == "windows" {
		name = "git.exe"
	}
	return filepath.Join(ShimDir(), name)
}

// GitCacheDir returns the directory where downloaded MinGit distributions are
// unpacked, one subdirectory per release tag.
func GitCacheDir() string {
	return filepath.Join(DataDir(), "git")
}

// ManagedGitPath returns the path to the newest downloaded MinGit git binary
// (fetched by `gitc gitc fetch-git`), or "" if none is cached. Override the
// backend explicitly with GITC_GIT_BACKEND.
func ManagedGitPath() string {
	entries, err := os.ReadDir(GitCacheDir())
	if err != nil {
		return ""
	}
	var newest string
	var newestMod int64
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
