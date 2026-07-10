package store

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestWALEnabled asserts the DSN actually put the DB in WAL mode — the property
// that lets concurrent processes read while one writes.
func TestWALEnabled(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = s.Close() }()

	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q, want wal", mode)
	}

	var busy int
	if err := s.db.QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatal(err)
	}

	if busy != busyTimeoutMS {
		t.Errorf("busy_timeout = %d, want %d", busy, busyTimeoutMS)
	}
}

// TestConcurrentWritersNoLock simulates many gitc processes writing the same
// audit DB at once (each an independent Store handle to one file) and asserts no
// write fails with "database is locked / busy". This reproduces the reported
// contention and pins the WAL + IMMEDIATE fix.
func TestConcurrentWritersNoLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")

	// Initialize the DB once (WAL + schema), as the first-ever gitc run would;
	// the reported failure is many *later* processes writing this WAL DB at once.
	init, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	_ = init.Close()

	const (
		writers   = 8
		perWriter = 30
	)

	var wg sync.WaitGroup

	errCh := make(chan error, writers*perWriter)

	for w := range writers {
		wg.Add(1)

		go func(id int) {
			defer wg.Done()

			s, err := Open(path) // an independent handle, like a separate process
			if err != nil {
				errCh <- err
				return
			}

			defer func() { _ = s.Close() }()

			for i := range perWriter {
				if err := s.Insert(sampleRecord(id, i)); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent insert failed (database locked/busy?): %v", err)
	}

	// Every row must have landed and the hash chain must remain intact.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = s.Close() }()

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if want := writers * perWriter; count != want {
		t.Errorf("row count = %d, want %d (writes were dropped)", count, want)
	}

	res, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}

	if !res.Intact {
		t.Errorf("hash chain broken after concurrent writes: %+v", res)
	}
}

func sampleRecord(writer, seq int) Record {
	return Record{
		TS:          time.Now().UTC(),
		OSUser:      "tester",
		Cwd:         "/repo",
		Argv:        []string{"status", strconv.Itoa(writer), strconv.Itoa(seq)},
		EnvSubset:   map[string]string{},
		Backend:     "vendored",
		BackendPath: "/git",
		Mode:        "passthrough",
		ExitCode:    0,
		Duration:    time.Millisecond,
	}
}
