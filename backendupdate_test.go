package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/gitc/internal/paths"
)

func TestCleanShimBackups(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_DATA_HOME", base)

	// Both the shim dir (launcher shims) and the bin dir (canonical gitc.exe) are
	// swept, since a self-update swap leaves <name>.old in whichever dir it ran.
	shim := paths.ShimDir()
	bin := paths.BinDir()

	for _, d := range []string{shim, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	keep := filepath.Join(shim, "git.exe")
	if err := os.WriteFile(keep, []byte("current"), 0o644); err != nil {
		t.Fatal(err)
	}

	stale := map[string]string{
		filepath.Join(shim, "git.exe.old"): "stale",
		filepath.Join(shim, "gitc.old"):    "stale",
		filepath.Join(bin, "gitc.exe.old"): "stale", // the update swap's leftover
	}
	for p := range stale {
		if err := os.WriteFile(p, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cleanShimBackups()

	if _, err := os.Stat(keep); err != nil {
		t.Errorf("current shim must be kept: %v", err)
	}

	for p := range stale {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s should have been swept", p)
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
