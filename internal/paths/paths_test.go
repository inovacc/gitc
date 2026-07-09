package paths

import (
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

func TestShimGitPathUnderShimDir(t *testing.T) {
	if dir := filepath.Dir(ShimGitPath()); dir != ShimDir() {
		t.Errorf("shim git %q not under shim dir %q", ShimGitPath(), ShimDir())
	}
}
