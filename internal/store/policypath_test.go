package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestInsertRecordsPolicyPath(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = st.Close() }()

	want := `C:\ProgramData\gitc\policy.json`
	rec := Record{
		TS:         time.Now(),
		OSUser:     "dev",
		Cwd:        ".",
		Argv:       []string{"push", "origin", "main"},
		Backend:    "system",
		Mode:       "passthrough",
		PolicyPath: want,
	}

	if err := st.Insert(rec); err != nil {
		t.Fatal(err)
	}

	rows, err := st.Records(1)
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	if rows[0].PolicyPath != want {
		t.Errorf("PolicyPath round-trip = %q, want %q", rows[0].PolicyPath, want)
	}
}

func TestInsertEmptyPolicyPath(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = st.Close() }()

	// No policy in effect: the column persists as empty, not a literal "".
	if err := st.Insert(Record{TS: time.Now(), OSUser: "dev", Argv: []string{"status"}, Mode: "passthrough"}); err != nil {
		t.Fatal(err)
	}

	rows, err := st.Records(1)
	if err != nil {
		t.Fatal(err)
	}

	if len(rows) != 1 || rows[0].PolicyPath != "" {
		t.Errorf("empty PolicyPath expected, got %q", rows[0].PolicyPath)
	}
}
