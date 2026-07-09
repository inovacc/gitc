package store

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenInsertAndTail(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit", "gitc.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	rec := Record{
		TS:          time.Now(),
		OSUser:      "alice",
		Identity:    "Alice Example",
		Cwd:         "/repo",
		Argv:        []string{"commit", "-m", "hello"},
		EnvSubset:   map[string]string{"GIT_AUTHOR_NAME": "alice", "PATH": "/usr/bin"},
		Backend:     "system",
		BackendPath: "/usr/bin/git",
		Mode:        "passthrough",
		ExitCode:    0,
		Duration:    42 * time.Millisecond,
		Enrichment:  json.RawMessage(`{"files":3}`),
	}
	if err := s.Insert(rec); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	// Second row to confirm append-only accumulation and ordering.
	rec2 := rec
	rec2.Argv = []string{"push"}
	rec2.ExitCode = 1
	if err := s.Insert(rec2); err != nil {
		t.Fatalf("Insert 2: %v", err)
	}

	var buf bytes.Buffer
	if err := s.Tail(10, &buf); err != nil {
		t.Fatalf("Tail: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "alice") {
		t.Errorf("tail missing user: %q", out)
	}
	if !strings.Contains(out, "commit") || !strings.Contains(out, "push") {
		t.Errorf("tail missing argv rows: %q", out)
	}
	// Oldest-first ordering: commit (row 1) before push (row 2).
	if strings.Index(out, "commit") > strings.Index(out, "push") {
		t.Errorf("tail not oldest-first: %q", out)
	}
}

func TestInsertNilOptionalFields(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gitc.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// No identity, no shortcut, no enrichment — should insert cleanly as NULLs.
	rec := Record{
		TS:          time.Now(),
		OSUser:      "bob",
		Cwd:         ".",
		Argv:        []string{"status"},
		EnvSubset:   map[string]string{},
		Backend:     "vendored",
		BackendPath: "/opt/git",
		Mode:        "passthrough",
		ExitCode:    0,
		Duration:    time.Millisecond,
	}
	if err := s.Insert(rec); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}
