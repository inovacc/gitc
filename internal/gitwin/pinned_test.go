package gitwin

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchTag(t *testing.T) {
	t.Parallel()

	cases := map[string]string{"amd64": "64-bit", "386": "32-bit", "arm64": "arm64"}
	for goarch, want := range cases {
		got, err := archTag(goarch)
		if err != nil || got != want {
			t.Errorf("archTag(%q) = %q, %v; want %q", goarch, got, err, want)
		}
	}

	if _, err := archTag("mips"); err == nil {
		t.Error("archTag should reject an unknown architecture")
	}
}

func TestVersionDir(t *testing.T) {
	t.Parallel()

	if VersionDir(pinnedVersion) != pinnedVersion {
		t.Error("a clean version should pass through unchanged")
	}

	if got := VersionDir("a/b:c"); got != "a-b-c" {
		t.Errorf("VersionDir should sanitize separators, got %q", got)
	}
}

func TestPinnedManifestComplete(t *testing.T) {
	t.Parallel()

	m := Pinned()
	if m.Version == "" {
		t.Fatal("pinned version is empty")
	}

	for _, arch := range []string{"amd64", "386", "arm64"} {
		a, ok := m.For("windows", arch)
		if !ok || a.SHA256 == "" || a.URL == "" || a.Name == "" {
			t.Errorf("pinned windows/%s missing or incomplete: %+v", arch, a)
		}
	}
}

func TestPinnedBusyboxComplete(t *testing.T) {
	t.Parallel()

	m := PinnedBusybox()
	if m.Version != pinnedVersion || m.Flavor != "MinGit-busybox" {
		t.Fatalf("busybox manifest metadata: %+v", m)
	}

	// git-for-windows builds busybox for 64/32-bit only (no arm64).
	for _, arch := range []string{"amd64", "386"} {
		a, ok := m.For("windows", arch)
		if !ok || a.SHA256 == "" || a.URL == "" {
			t.Errorf("busybox windows/%s missing/incomplete: %+v", arch, a)
		}
	}

	if _, ok := m.For("windows", "arm64"); ok {
		t.Error("there is no arm64 busybox build; For should miss")
	}
}

func TestPinnedFullComplete(t *testing.T) {
	t.Parallel()

	m := PinnedFull()
	if m.Version != pinnedVersion || m.Flavor != "Git-full" {
		t.Fatalf("full manifest metadata: %+v", m)
	}

	// git-for-windows ships the full tarball for 64-bit and arm64 only.
	for _, arch := range []string{"amd64", "arm64"} {
		a, ok := m.For("windows", arch)
		if !ok || a.SHA256 == "" || !strings.HasSuffix(a.Name, ".tar.bz2") {
			t.Errorf("full windows/%s missing/incomplete: %+v", arch, a)
		}
	}

	if _, ok := m.For("windows", "386"); ok {
		t.Error("there is no 32-bit full tarball; For should miss")
	}
}

func TestParseManifestAndFor(t *testing.T) {
	t.Parallel()

	js := `{"version":"v1","assets":{"windows/amd64":{"name":"g.zip","url":"http://x","sha256":"abc","size":1}}}`

	m, err := ParseManifest([]byte(js))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}

	if a, ok := m.For("windows", "amd64"); !ok || a.Name != "g.zip" {
		t.Errorf("For(windows/amd64) = %+v, %v", a, ok)
	}

	if _, ok := m.For("linux", "amd64"); ok {
		t.Error("For should miss on an absent platform")
	}
}

func TestVerifySHA256(t *testing.T) {
	t.Parallel()

	f := filepath.Join(t.TempDir(), "blob")
	data := []byte("hello gitc")

	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(data)
	if err := verifySHA256(f, hex.EncodeToString(sum[:])); err != nil {
		t.Errorf("verifySHA256 on a valid digest: %v", err)
	}

	if err := verifySHA256(f, "deadbeef"); err == nil {
		t.Error("verifySHA256 must reject a wrong digest")
	}
}

func TestUnzipHappyAndZipSlip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	good := filepath.Join(dir, "good.zip")
	writeZip(t, good, map[string]string{"cmd/git.exe": "binary", "README": "hi"})

	dest := filepath.Join(dir, "out")
	if err := Unzip(good, dest); err != nil {
		t.Fatalf("Unzip good: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "cmd", "git.exe")); err != nil {
		t.Errorf("expected extracted file: %v", err)
	}

	evil := filepath.Join(dir, "evil.zip")
	writeZip(t, evil, map[string]string{"../escape.txt": "pwned"})

	if err := Unzip(evil, filepath.Join(dir, "out2")); err == nil {
		t.Error("Unzip must reject a zip-slip path")
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)

	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
