package scancmd

import (
	"testing"
)

func TestRunUnknownFlag(t *testing.T) {
	if code := Run([]string{"--nope"}); code != 2 {
		t.Errorf("unknown flag exit = %d, want 2", code)
	}
}

func TestRunCleanDir(t *testing.T) {
	// An empty directory has no secrets: exit 0.
	dir := t.TempDir()
	if code := Run([]string{dir}); code != 0 {
		t.Errorf("clean scan of empty dir exit = %d, want 0", code)
	}
}
