// Package paths resolves the platform-specific locations gitc uses for its
// audit database, vendored git build, and configuration.
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

// VendoredGitPath returns the default path to the git binary built from the
// third_party/git submodule by `task git:build`. It resolves relative to
// gitc's own executable (the install directory ships gitc alongside its
// vendor-build tree), falling back to the data dir when the executable path is
// unavailable. Override with GITC_GIT_BACKEND.
func VendoredGitPath() string {
	name := "git"
	if runtime.GOOS == "windows" {
		name = "git.exe"
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "vendor-build", "git", "bin", name)
	}
	return filepath.Join(DataDir(), "vendor-build", "git", "bin", name)
}
