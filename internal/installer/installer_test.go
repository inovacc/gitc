package installer

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/inovacc/gitc/internal/installer/shim"
	"github.com/inovacc/gitc/internal/paths"
)

func TestInstallHardlinksShellShims(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("sh/bash launcher shims are Windows-only")
	}

	t.Setenv("LOCALAPPDATA", t.TempDir())

	res, err := Install(false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	gi, err := os.Stat(res.ShimGit)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"sh.exe", "bash.exe"} {
		si, err := os.Stat(filepath.Join(filepath.Dir(res.ShimGit), name))
		if err != nil {
			t.Fatalf("%s not created: %v", name, err)
		}

		if !os.SameFile(gi, si) {
			t.Errorf("%s should be a hard link to git.exe (share the inode)", name)
		}
	}
}

func TestInstallWritesLauncherAndShimFiles(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the launcher model is Windows-only")
	}

	t.Setenv("LOCALAPPDATA", t.TempDir())

	res, err := Install(false)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	// git.exe must be the tiny embedded launcher, not a full copy of gitc.
	launcher := shim.Binary(runtime.GOARCH)
	if launcher == nil {
		t.Fatalf("no embedded launcher for %s", runtime.GOARCH)
	}

	got, err := os.ReadFile(res.ShimGit)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != len(launcher) {
		t.Errorf("git.exe is %d bytes; expected the %d-byte launcher, not a gitc copy", len(got), len(launcher))
	}

	// The canonical gitc.exe the launchers exec must exist.
	if _, err := os.Stat(paths.CanonicalPath()); err != nil {
		t.Errorf("canonical gitc.exe missing: %v", err)
	}

	// Each launcher needs a sibling .shim pointing at the canonical binary; the
	// sh/bash personas carry the gitc meta command in `args`.
	canonical := paths.CanonicalPath()

	cases := map[string]string{
		"git.shim":  "",
		"sh.shim":   "args = gitc sh",
		"bash.shim": "args = gitc bash",
	}

	for name, wantArgs := range cases {
		body, err := os.ReadFile(filepath.Join(res.ShimDir, name))
		if err != nil {
			t.Fatalf("%s not written: %v", name, err)
		}

		text := string(body)
		if !strings.Contains(text, "path = "+canonical) {
			t.Errorf("%s must point at the canonical binary; got:\n%s", name, text)
		}

		if wantArgs != "" && !strings.Contains(text, wantArgs) {
			t.Errorf("%s must carry %q; got:\n%s", name, wantArgs, text)
		}

		if wantArgs == "" && strings.Contains(text, "args = ") {
			t.Errorf("git.shim must have no args line; got:\n%s", text)
		}
	}
}

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
