package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func gitName() string {
	if runtime.GOOS == "windows" {
		return "git.exe"
	}
	return "git"
}

func writeFakeExe(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("fake"), 0o755); err != nil {
		t.Fatalf("write fake exe: %v", err)
	}
}

// TestSelfInvocationGuard: when the only git on PATH is gitc itself, no system
// git is found (prevents recursive self-exec).
func TestSelfInvocationGuard(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, gitName()) // gitc shipped as `git`
	writeFakeExe(t, self)

	t.Setenv("PATH", dir)

	if got, ok := findSystemGit(self); ok {
		t.Fatalf("findSystemGit found %q, expected none (self must be skipped)", got)
	}
}

// TestFindsDistinctSystemGit: a real git elsewhere on PATH is resolved even
// when gitc-as-git sits earlier.
func TestFindsDistinctSystemGit(t *testing.T) {
	selfDir := t.TempDir()
	realDir := t.TempDir()
	self := filepath.Join(selfDir, gitName())
	real := filepath.Join(realDir, gitName())
	writeFakeExe(t, self)
	writeFakeExe(t, real)

	t.Setenv("PATH", selfDir+string(os.PathListSeparator)+realDir)

	got, ok := findSystemGit(self)
	if !ok {
		t.Fatal("expected to find the distinct system git")
	}
	if !samePath(got, real) {
		t.Fatalf("found %q, want %q", got, real)
	}
}

// samePath compares two paths after symlink resolution (Resolve returns
// EvalSymlinks-resolved paths; CI temp dirs are symlinked: macOS /var ->
// /private/var, Windows 8.3 short names). Case-insensitive on Windows.
func samePath(a, b string) bool {
	if r, err := filepath.EvalSymlinks(a); err == nil {
		a = r
	}
	if r, err := filepath.EvalSymlinks(b); err == nil {
		b = r
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// TestResolvePrefersVendored: a usable vendored build wins over PATH.
func TestResolvePrefersVendored(t *testing.T) {
	vendorDir := t.TempDir()
	pathDir := t.TempDir()
	vendored := filepath.Join(vendorDir, gitName())
	sys := filepath.Join(pathDir, gitName())
	self := filepath.Join(t.TempDir(), gitName())
	writeFakeExe(t, vendored)
	writeFakeExe(t, sys)
	writeFakeExe(t, self)

	t.Setenv("PATH", pathDir)

	b, err := Resolve(vendored, self)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if b.Kind != KindManaged {
		t.Fatalf("Kind = %v, want managed", b.Kind)
	}
	if !samePath(b.Path, vendored) {
		t.Fatalf("Path = %q, want %q", b.Path, vendored)
	}
}

// TestResolveNoBackend: neither vendored nor a non-self system git → error.
func TestResolveNoBackend(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, gitName())
	writeFakeExe(t, self)
	t.Setenv("PATH", dir) // only self on PATH

	if _, err := Resolve("", self); err == nil {
		t.Fatal("expected ErrNoBackend, got nil")
	}
}
