package provision

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/settings"
)

func TestPinnedAvailableMatchesPlatform(t *testing.T) {
	// The in-code pinned MinGit manifest ships Windows builds only, so
	// auto-provision is gated to Windows; other platforms rely on a system git.
	if got := pinnedAvailable(); got != (runtime.GOOS == "windows") {
		t.Errorf("pinnedAvailable() = %v on GOOS=%s", got, runtime.GOOS)
	}
}

func TestManifestForFlavor(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"":        "Git-full", // default
		"full":    "Git-full",
		"busybox": "MinGit-busybox",
		"minimal": "MinGit",
		"unknown": "MinGit",
	}

	for flavor, wantFlavor := range cases {
		if got := manifestForFlavor(flavor).Flavor; got != wantFlavor {
			t.Errorf("manifestForFlavor(%q).Flavor = %q, want %q", flavor, got, wantFlavor)
		}
	}
}

func TestAppUUID(t *testing.T) {
	if appUUID("app/abc/v1") != "abc" {
		t.Error("app install uuid should be the second path segment")
	}

	if appUUID("git/v1") != "" {
		t.Error("a legacy install has no app uuid")
	}

	if appUUID("") != "" {
		t.Error("empty path has no uuid")
	}
}

func TestActiveKeepSet(t *testing.T) {
	var s settings.Settings

	s.Backend.Active = "app/aaa/v1"
	s.Backend.Previous = "app/bbb/v0"

	keep := ActiveKeepSet(s)
	if len(keep) != 2 || !keep["aaa"] || !keep["bbb"] {
		t.Errorf("keep set = %v, want {aaa, bbb}", keep)
	}
}

func TestGcInstalls(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_DATA_HOME", base)

	app := paths.AppDir()
	for _, id := range []string{"keep", "drop1", "drop2"} {
		if err := os.MkdirAll(filepath.Join(app, id, "v"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	GcInstalls(map[string]bool{"keep": true})

	if _, err := os.Stat(filepath.Join(app, "keep")); err != nil {
		t.Errorf("kept install was removed: %v", err)
	}

	for _, gone := range []string{"drop1", "drop2"} {
		if _, err := os.Stat(filepath.Join(app, gone)); !os.IsNotExist(err) {
			t.Errorf("install %q should have been GC'd", gone)
		}
	}
}
