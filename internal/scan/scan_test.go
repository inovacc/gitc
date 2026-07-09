package scan

import "testing"

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
