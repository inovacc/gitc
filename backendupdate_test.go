package main

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

func TestCleanShimBackups(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_DATA_HOME", base)

	shim := paths.ShimDir()
	if err := os.MkdirAll(shim, 0o755); err != nil {
		t.Fatal(err)
	}

	keep := filepath.Join(shim, "git.exe")
	if err := os.WriteFile(keep, []byte("current"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, old := range []string{"git.exe.old", "gitc.old"} {
		if err := os.WriteFile(filepath.Join(shim, old), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cleanShimBackups()

	if _, err := os.Stat(keep); err != nil {
		t.Errorf("current shim must be kept: %v", err)
	}

	for _, old := range []string{"git.exe.old", "gitc.old"} {
		if _, err := os.Stat(filepath.Join(shim, old)); !os.IsNotExist(err) {
			t.Errorf("%s should have been swept", old)
		}
	}
}

func TestShellName(t *testing.T) {
	t.Parallel()

	// Use forward-slash / bare paths so filepath.Base behaves the same on the
	// Linux CI and Windows (backslash is a separator only on Windows).
	cases := map[string]string{
		"sh.exe":            "sh",
		"bash.exe":          "bash",
		"gitc/shim/sh.exe":  "sh",
		"/opt/gitc/bash":    "bash",
		"BASH.EXE":          "bash",
		"gitc/shim/git.exe": "",
		"gitc":              "",
	}

	for arg0, want := range cases {
		if got := shellName(arg0); got != want {
			t.Errorf("shellName(%q) = %q, want %q", arg0, got, want)
		}
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
