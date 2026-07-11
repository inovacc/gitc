package gitwin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// buildMinGitZip returns a zip archive shaped like a MinGit distribution: the
// cmd/git.exe gitc runs, a top-level bin/ that pruneRedundant should remove, and
// a usr/bin/sh.exe it must keep.
func buildMinGitZip(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer

	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"cmd/git.exe":    "GITBINARY",
		"bin/git.exe":    "launcher-to-prune",
		"usr/bin/sh.exe": "sh",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func serveBytes(t *testing.T, data []byte) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
}

func TestEnsurePinnedDownloadsVerifiesExtracts(t *testing.T) {
	zipBytes := buildMinGitZip(t)
	sum := sha256.Sum256(zipBytes)

	srv := serveBytes(t, zipBytes)
	defer srv.Close()

	m := Manifest{Version: "v9.9.9", Flavor: "MinGit", Assets: map[string]ManifestAsset{
		"test/test": {
			Name:   "MinGit.zip",
			URL:    srv.URL + "/MinGit.zip",
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(zipBytes)),
		},
	}}

	asset, ok := m.For("test", "test")
	if !ok {
		t.Fatal("asset lookup failed")
	}

	base := t.TempDir()

	gitExe, err := m.EnsurePinned(context.Background(), asset, base)
	if err != nil {
		t.Fatalf("EnsurePinned: %v", err)
	}

	if _, err := os.Stat(gitExe); err != nil {
		t.Errorf("git.exe not extracted at %s: %v", gitExe, err)
	}

	root := filepath.Dir(filepath.Dir(gitExe)) // <version>/cmd/git.exe -> <version>

	if _, err := os.Stat(filepath.Join(root, "bin")); !os.IsNotExist(err) {
		t.Error("top-level bin/ should have been pruned")
	}

	if _, err := os.Stat(filepath.Join(root, "usr", "bin", "sh.exe")); err != nil {
		t.Errorf("usr/bin/sh.exe should be kept: %v", err)
	}

	// A second call short-circuits on the already-present git.exe (no download).
	srv.Close()

	if _, err := m.EnsurePinned(context.Background(), asset, base); err != nil {
		t.Errorf("second EnsurePinned should short-circuit without downloading: %v", err)
	}
}

func TestEnsurePinnedRejectsShaMismatch(t *testing.T) {
	zipBytes := buildMinGitZip(t)

	srv := serveBytes(t, zipBytes)
	defer srv.Close()

	m := Manifest{Version: "v9.9.9", Assets: map[string]ManifestAsset{
		"test/test": {
			Name:   "MinGit.zip",
			URL:    srv.URL + "/MinGit.zip",
			SHA256: "00deadbeef00", // wrong
			Size:   int64(len(zipBytes)),
		},
	}}

	asset, _ := m.For("test", "test")

	if _, err := m.EnsurePinned(context.Background(), asset, t.TempDir()); err == nil {
		t.Error("a sha256 mismatch must refuse (never install an unverified backend)")
	}
}
