package enrich

import (
	"context"
	"testing"
)

func TestParseStatus(t *testing.T) {
	// Representative `git status --porcelain=v2 --branch` output:
	// - branch main, 2 ahead / 1 behind
	// - one fully-staged add (A.), one staged+unstaged modify (MM),
	//   one unstaged modify (.M), one untracked, one conflict.
	out := "" +
		"# branch.oid abc123\n" +
		"# branch.head main\n" +
		"# branch.ab +2 -1\n" +
		"1 A. N... 100644 100644 100644 0000 1111 added.go\n" +
		"1 MM N... 100644 100644 100644 2222 3333 both.go\n" +
		"1 .M N... 100644 100644 100644 4444 4444 work.go\n" +
		"u UU N... 100644 100644 100644 100644 5555 6666 7777 conflict.go\n" +
		"? untracked.go\n"

	st := parseStatus(out)

	if st.Branch != "main" {
		t.Errorf("Branch = %q, want main", st.Branch)
	}

	if st.OID != "abc123" {
		t.Errorf("OID = %q, want abc123", st.OID)
	}

	if st.Ahead != 2 || st.Behind != 1 {
		t.Errorf("ahead/behind = %d/%d, want 2/1", st.Ahead, st.Behind)
	}

	if st.Staged != 2 { // A. and MM
		t.Errorf("Staged = %d, want 2", st.Staged)
	}

	if st.Unstaged != 2 { // MM and .M
		t.Errorf("Unstaged = %d, want 2", st.Unstaged)
	}

	if st.Untracked != 1 {
		t.Errorf("Untracked = %d, want 1", st.Untracked)
	}

	if st.Conflicts != 1 {
		t.Errorf("Conflicts = %d, want 1", st.Conflicts)
	}
}

func TestParseStatusClean(t *testing.T) {
	out := "" +
		"# branch.oid deadbeef\n" +
		"# branch.head release\n" +
		"# branch.ab +0 -0\n"

	st := parseStatus(out)
	if st.Staged+st.Unstaged+st.Untracked+st.Conflicts != 0 {
		t.Errorf("expected clean tree, got %+v", st)
	}

	if st.Branch != "release" {
		t.Errorf("Branch = %q, want release", st.Branch)
	}
}

func TestNewExecEmptyPathIsNoop(t *testing.T) {
	if _, ok := NewExec("").(noop); !ok {
		t.Fatal("NewExec(\"\") should return a no-op enricher")
	}
}

// TestEnrichDegradesOnCancelledContext verifies enrichment never surfaces an
// error (or blocks) when the exec cannot run — here because the context is
// already cancelled. This also exercises the bounded-context path added for H-04.
func TestEnrichDegradesOnCancelledContext(t *testing.T) {
	t.Parallel()

	e := &execEnricher{gitPath: "git"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	blob, err := e.Enrich(ctx, "")
	if err != nil {
		t.Fatalf("Enrich must never return an error, got %v", err)
	}

	if blob != nil {
		t.Fatalf("Enrich on a cancelled context should yield nil blob, got %s", blob)
	}
}
