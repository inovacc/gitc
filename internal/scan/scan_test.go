package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanStringDetectsGitLabPAT(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A clearly-fake, high-entropy GitLab personal access token (glpat- + 20).
	sample := "gitlab_token = glpat-R8xK2mQ7vL9nP4wZ1tY6"

	findings := s.ScanString(sample)
	if len(findings) == 0 {
		t.Fatalf("expected >=1 finding for fake GitLab PAT, got 0")
	}
}

func TestScanStringDetectsGenericSecret(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A clearly-fake, high-entropy secret in an assignment the ruleset flags.
	sample := `password = "R8xK2mQ7vL9nP4wZ1tY6bC3d"`

	findings := s.ScanString(sample)
	if len(findings) == 0 {
		t.Fatalf("expected >=1 finding for fake generic secret, got 0")
	}
}

func TestScanDirFindsSecretsAndReportsNoSkips(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "config.env"),
		[]byte("gitlab_token = glpat-R8xK2mQ7vL9nP4wZ1tY6\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("nothing to see here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := s.ScanDir(dir)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	if len(res.Findings) == 0 {
		t.Errorf("expected >=1 finding across the tree, got 0")
	}

	if len(res.Skipped) != 0 {
		t.Errorf("expected no skipped files on a readable tree, got %+v", res.Skipped)
	}
}

func TestScanDirSkipsVendoredDirs(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("gitlab_token = glpat-R8xK2mQ7vL9nP4wZ1tY6\n")

	// Same secret in a vendored dir (skipped) and at the top level (found).
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "leak.env"), secret, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "app.env"), secret, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := s.ScanDir(dir)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	if len(res.Findings) != 1 {
		t.Errorf("expected exactly 1 finding (top-level only; node_modules skipped), got %d", len(res.Findings))
	}
}

func TestScanDirNonexistentRootErrors(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := s.ScanDir(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("ScanDir on a missing root should return an error, not a silent empty result")
	}
}

func TestScanStringCleanIsEmpty(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	findings := s.ScanString("the quick brown fox jumps over the lazy dog\nhello = world\n")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for clean text, got %d: %+v", len(findings), findings)
	}
}
