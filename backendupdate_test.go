package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/settings"
)

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

	keep := activeKeepSet(s)
	if len(keep) != 2 || !keep["aaa"] || !keep["bbb"] {
		t.Errorf("keep set = %v, want {aaa, bbb}", keep)
	}
}

func TestTryUpdateLock(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "update.lock")

	release, ok := tryUpdateLock(lock)
	if !ok {
		t.Fatal("first acquisition should succeed")
	}

	if _, held := tryUpdateLock(lock); held {
		t.Error("a second acquisition must fail while the lock is held")
	}

	release()

	if _, again := tryUpdateLock(lock); !again {
		t.Error("the lock should be re-acquirable after release")
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

	gcInstalls(map[string]bool{"keep": true})

	if _, err := os.Stat(filepath.Join(app, "keep")); err != nil {
		t.Errorf("kept install was removed: %v", err)
	}

	for _, gone := range []string{"drop1", "drop2"} {
		if _, err := os.Stat(filepath.Join(app, gone)); !os.IsNotExist(err) {
			t.Errorf("install %q should have been GC'd", gone)
		}
	}
}
