package gitwin

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// tarEntry is one entry to write into a test tar.
type tarEntry struct {
	name     string
	typeflag byte
	body     string
	linkname string
}

// buildTar builds an in-memory tar (the bzip2 layer is transparent, so testing
// the tar-extraction + zip-slip logic against a plain tar is equivalent).
func buildTar(t *testing.T, entries []tarEntry) *tar.Reader {
	t.Helper()

	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o644, Linkname: e.linkname}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}

		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}

		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return tar.NewReader(&buf)
}

func TestExtractTarNormalFile(t *testing.T) {
	dest := t.TempDir()

	tr := buildTar(t, []tarEntry{{name: "cmd/git.exe", typeflag: tar.TypeReg, body: "binary"}})
	if err := extractTar(tr, dest); err != nil {
		t.Fatalf("extractTar: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "cmd", "git.exe"))
	if err != nil || string(got) != "binary" {
		t.Errorf("extracted file = %q err=%v", got, err)
	}
}

func TestExtractTarRejectsTraversal(t *testing.T) {
	dest := t.TempDir()

	tr := buildTar(t, []tarEntry{{name: "../escape.txt", typeflag: tar.TypeReg, body: "pwned"}})
	if err := extractTar(tr, dest); err == nil {
		t.Fatal("a ../ traversal entry must be rejected")
	}

	// Nothing must be written outside dest.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); !os.IsNotExist(err) {
		t.Error("traversal wrote a file outside the destination")
	}
}

func TestExtractTarRejectsAbsolute(t *testing.T) {
	dest := t.TempDir()

	// An absolute-looking entry must not escape the destination.
	tr := buildTar(t, []tarEntry{{name: "/etc/pwned", typeflag: tar.TypeReg, body: "x"}})
	if err := extractTar(tr, dest); err == nil {
		if _, statErr := os.Stat("/etc/pwned"); statErr == nil {
			t.Fatal("absolute path escaped the destination")
		}
	}
}

func TestExtractTarDerefsHardlink(t *testing.T) {
	dest := t.TempDir()

	tr := buildTar(t, []tarEntry{
		{name: "usr/bin/bash.exe", typeflag: tar.TypeReg, body: "shell"},
		{name: "usr/bin/sh.exe", typeflag: tar.TypeLink, linkname: "usr/bin/bash.exe"},
	})
	if err := extractTar(tr, dest); err != nil {
		t.Fatalf("extractTar: %v", err)
	}

	// The link must be materialized as a real copy of its target.
	got, err := os.ReadFile(filepath.Join(dest, "usr", "bin", "sh.exe"))
	if err != nil || string(got) != "shell" {
		t.Errorf("dereferenced link = %q err=%v, want a copy of bash.exe", got, err)
	}
}

func TestSafeJoin(t *testing.T) {
	dest := filepath.Clean(t.TempDir())

	if _, err := safeJoin(dest, "cmd/git.exe"); err != nil {
		t.Errorf("a normal path must be accepted: %v", err)
	}

	for _, bad := range []string{"../escape", "../../x", filepath.Join("a", "..", "..", "b")} {
		if _, err := safeJoin(dest, bad); err == nil {
			t.Errorf("safeJoin must reject escaping path %q", bad)
		}
	}
}
