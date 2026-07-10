package installer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSameExe(t *testing.T) {
	dir := t.TempDir()

	a := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(a, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !sameExe(a, a) {
		t.Error("an identical path should be sameExe")
	}

	b := filepath.Join(dir, "b.exe")
	if err := os.WriteFile(b, []byte("y"), 0o755); err != nil {
		t.Fatal(err)
	}

	if sameExe(a, b) {
		t.Error("two distinct files should not be sameExe")
	}
}

func TestInstallWithoutBackendThenUninstall(t *testing.T) {
	// Isolate the data dir so we never touch the real install.
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	res, err := Install(false)
	if err != nil {
		t.Fatalf("Install must not require a pre-existing backend: %v", err)
	}

	if _, err := os.Stat(res.ShimGit); err != nil {
		t.Fatalf("shim not created: %v", err)
	}

	if res.Instruction == "" {
		t.Error("expected a manual PATH instruction when --apply is not set")
	}

	if _, err := Uninstall(); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	if _, err := os.Stat(res.ShimGit); !os.IsNotExist(err) {
		t.Error("shim should be removed after Uninstall")
	}
}
