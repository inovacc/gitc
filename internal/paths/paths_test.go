package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathLayout(t *testing.T) {
	base := DataDir()

	checks := []struct {
		got, want string
	}{
		{AppDir(), filepath.Join(base, "app")},
		{SettingsPath(), filepath.Join(base, "settings.json")},
		{PolicyPath(), filepath.Join(base, "policy.json")},
		{GitCacheDir(), filepath.Join(base, "git")},
		{ShimDir(), filepath.Join(base, "shim")},
		{AuditDBPath(), filepath.Join(base, "audit", "gitc.db")},
	}

	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("path = %q, want %q", c.got, c.want)
		}
	}
}

func TestManagedGitPathEmptyWhenNoCache(t *testing.T) {
	// Point the data dir at fresh, empty temp dirs (both Windows and XDG vars)
	// so there is no cached MinGit to find.
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	if got := ManagedGitPath(); got != "" {
		t.Errorf("expected empty managed path with no cache, got %q", got)
	}
}

func TestManagedGitPathFindsCachedInstall(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_DATA_HOME", base)

	gitExe := filepath.Join(GitCacheDir(), "v2.55.0.windows.2", "cmd", "git.exe")
	if err := os.MkdirAll(filepath.Dir(gitExe), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(gitExe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := ManagedGitPath(); got != gitExe {
		t.Errorf("ManagedGitPath() = %q, want %q", got, gitExe)
	}
}

func TestShimGitPathUnderShimDir(t *testing.T) {
	if dir := filepath.Dir(ShimGitPath()); dir != ShimDir() {
		t.Errorf("shim git %q not under shim dir %q", ShimGitPath(), ShimDir())
	}
}
