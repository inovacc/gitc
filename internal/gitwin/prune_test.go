package gitwin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPruneRedundant(t *testing.T) {
	dest := t.TempDir()

	// Lay out a full-git-like tree: the dirs gitc uses plus the redundant ones.
	keep := []string{
		filepath.Join("cmd", "git.exe"),
		filepath.Join("usr", "bin", "sh.exe"),
		filepath.Join("mingw64", "bin", "git.exe"),
	}
	drop := []string{
		filepath.Join("bin", "git.exe"),
		filepath.Join("tmp", "placeholder"),
		filepath.Join("dev", "null"),
	}

	for _, rel := range append(append([]string{}, keep...), drop...) {
		p := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	pruneRedundant(dest)

	for _, rel := range keep {
		if _, err := os.Stat(filepath.Join(dest, rel)); err != nil {
			t.Errorf("%s must be kept: %v", rel, err)
		}
	}

	for _, dir := range []string{"bin", "tmp", "dev"} {
		if _, err := os.Stat(filepath.Join(dest, dir)); !os.IsNotExist(err) {
			t.Errorf("%s/ should have been pruned", dir)
		}
	}
}

func TestPruneRedundantIgnoresAbsentDirs(t *testing.T) {
	// A leaner MinGit tree has no bin/tmp/dev — pruning must not error.
	dest := t.TempDir()
	pruneRedundant(dest) // must be a no-op, no panic
}
