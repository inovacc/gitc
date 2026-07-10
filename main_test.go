package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestHasHelpFlag(t *testing.T) {
	if !hasHelpFlag([]string{"-h"}) {
		t.Error("-h should be detected")
	}

	if !hasHelpFlag([]string{"x", "--help"}) {
		t.Error("--help should be detected")
	}

	if hasHelpFlag([]string{"status", "-w"}) {
		t.Error("no help flag present")
	}
}

func TestRunMetaVersion(t *testing.T) {
	if code := runMeta(context.Background(), []string{"version"}, nil); code != 0 {
		t.Errorf("version exit = %d, want 0", code)
	}
}

func TestRunMetaBareAndHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}} {
		if code := runMeta(context.Background(), args, nil); code != 0 {
			t.Errorf("runMeta(%v) = %d, want 0", args, code)
		}
	}
}

func TestRunMetaUnknownCommand(t *testing.T) {
	if code := runMeta(context.Background(), []string{"definitely-not-a-command"}, nil); code != 2 {
		t.Errorf("unknown meta command exit = %d, want 2", code)
	}
}

func TestRunMetaHelpFlagShowsUsage(t *testing.T) {
	// `git scan --help` renders the cmdtree usage rather than running scan (which
	// would need a backend), so it is safe to exercise with a nil store.
	if code := runMeta(context.Background(), []string{"scan", "--help"}, nil); code != 0 {
		t.Errorf("scan --help exit = %d, want 0", code)
	}
}

func TestRunUpdateUnknownFlag(t *testing.T) {
	// The flag parse rejects an unknown flag (exit 2) before any network call.
	if code := runUpdate(context.Background(), []string{"--nope"}); code != 2 {
		t.Errorf("update --nope exit = %d, want 2", code)
	}
}

func TestRunRoutesMetaCommand(t *testing.T) {
	// Route a `git gitc version` through run(): it opens the audit store, sees a
	// Meta decision, and dispatches to runMeta — no backend required.
	t.Setenv("GITC_AUDIT_DB", filepath.Join(t.TempDir(), "audit.db"))
	t.Setenv("GITC_BACKGROUND", "1") // suppress the background update spawn

	if code := run(context.Background(), []string{"gitc", "version"}); code != 0 {
		t.Errorf("run(gitc version) = %d, want 0", code)
	}
}

func TestPrintSelfInfoAndHelpDoNotPanic(t *testing.T) {
	// Redirect stdout/stderr to a temp file so the checks run quietly; we only
	// assert the printers don't panic (they exercise backend resolution).
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f

	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

	printSelfInfo()
	printMetaHelp()
}
