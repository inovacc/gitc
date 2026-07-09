// Package store owns the forensic audit database: schema migrations, the
// append-only Record model, and connection setup with owner-only file
// permissions.
package store

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Record is one forensic audit entry: everything gitc knows about a single
// git invocation. Values are stored raw and unredacted by design.
type Record struct {
	TS          time.Time         // invocation start (stored as RFC3339 UTC)
	OSUser      string            // OS username
	Identity    string            // resolved identity, if any
	Cwd         string            // working directory
	Argv        []string          // raw argv passed to the backend
	EnvSubset   map[string]string // captured git-relevant env vars, raw values
	Backend     string            // "vendored" | "system"
	BackendPath string            // resolved absolute backend binary path
	Mode        string            // "passthrough" | "shortcut"
	Shortcut    string            // shortcut name when Mode == "shortcut"
	ExitCode    int               // backend exit code
	Duration    time.Duration     // wall-clock exec duration
	Enrichment  json.RawMessage   // optional libgit2 blob, nil if unavailable
}

// Store is the append-only audit log backing store.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the audit database at path, ensures its
// parent directory and the file itself are owner-only, and applies the
// embedded schema migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	// Pre-create the file with restrictive permissions so the DB is never
	// briefly world-readable. Best-effort on Windows, where mode bits map to
	// the read-only attribute only; ACL hardening is left to the installer.
	if f, err := os.OpenFile(path, os.O_CREATE, 0o600); err == nil {
		_ = f.Close()
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping audit db: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		sqlBytes, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.db.Exec(string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return nil
}

// Insert appends one record to the audit log. It never updates or deletes.
func (s *Store) Insert(r Record) error {
	argv, err := json.Marshal(r.Argv)
	if err != nil {
		return fmt.Errorf("marshal argv: %w", err)
	}
	env, err := json.Marshal(r.EnvSubset)
	if err != nil {
		return fmt.Errorf("marshal env: %w", err)
	}
	var enrichment any
	if len(r.Enrichment) > 0 {
		enrichment = string(r.Enrichment)
	}
	var identity, shortcut any
	if r.Identity != "" {
		identity = r.Identity
	}
	if r.Shortcut != "" {
		shortcut = r.Shortcut
	}

	const q = `INSERT INTO audit_log
        (ts, os_user, identity, cwd, argv, env_subset, backend, backend_path,
         mode, shortcut, exit_code, duration_ms, enrichment)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.Exec(q,
		r.TS.UTC().Format(time.RFC3339Nano),
		r.OSUser, identity, r.Cwd, string(argv), string(env),
		r.Backend, r.BackendPath, r.Mode, shortcut,
		r.ExitCode, r.Duration.Milliseconds(), enrichment,
	)
	if err != nil {
		return fmt.Errorf("insert audit row: %w", err)
	}
	return nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
