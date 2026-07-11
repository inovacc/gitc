// Package store owns the forensic audit database: schema migrations, the
// append-only Record model, and connection setup with owner-only file
// permissions.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// openTimeout bounds the initial connectivity check so a stalled database file
// (e.g. on a slow or hung network share) fails fast instead of blocking git
// startup; the caller then runs without an audit log rather than hanging.
const openTimeout = 3 * time.Second

// busyTimeoutMS is how long SQLite waits for a held lock before returning
// SQLITE_BUSY, so concurrent gitc processes serialize their audit writes
// instead of silently dropping them.
const busyTimeoutMS = 5000

// dataSourceName builds the modernc sqlite DSN. The pragmas are baked into the
// connection string so every physical connection gets them:
//
//   - journal_mode=WAL: multiple gitc processes can read while one writes,
//     without the whole-database EXCLUSIVE lock of the default rollback journal
//     — the core fix for "database is locked" under concurrent invocations.
//   - _txlock=immediate: Insert reads the hash-chain head and then appends in
//     one transaction; taking the write lock up front (BEGIN IMMEDIATE) means two
//     concurrent writers queue on the busy timeout instead of both grabbing a
//     shared lock and deadlocking on the upgrade (which a busy timeout can't fix).
//   - busy_timeout: wait for a held write lock instead of erroring immediately.
//   - synchronous=NORMAL: durable under WAL and far fewer fsyncs than FULL.
func dataSourceName(path string) string {
	return path +
		"?_txlock=immediate" +
		"&_pragma=busy_timeout(" + strconv.Itoa(busyTimeoutMS) + ")" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)"
}

// Record is one forensic audit entry: everything gitc knows about a single
// git invocation. Values are stored raw and unredacted by design.
type Record struct {
	TS          time.Time         // invocation start (stored as RFC3339 UTC)
	OSUser      string            // OS username
	Identity    string            // resolved identity, if any
	Cwd         string            // working directory
	Argv        []string          // argv passed to the backend (URL/auth credentials masked)
	EnvSubset   map[string]string // captured git-relevant env vars, credential-masked
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

	db, err := sql.Open("sqlite", dataSourceName(path))
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}

	// Serialize this process on one durable connection: WAL + the busy timeout
	// handle cross-process concurrency, and a single long-lived connection keeps
	// the per-connection pragmas in effect for the process lifetime rather than
	// racing to SQLITE_BUSY within the process.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()

	if err := pingWithRetry(ctx, db); err != nil {
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

// pingWithRetry verifies connectivity, tolerating the transient SQLITE_BUSY that
// a concurrent cold-start storm can produce while WAL is first being established
// (once WAL exists, opens no longer switch journal mode and never hit this). The
// per-connection busy timeout handles steady-state contention; this only covers
// the brief first-init window so a startup race never drops auditing.
func pingWithRetry(ctx context.Context, db *sql.DB) error {
	var err error

	for attempt := range 5 {
		if err = db.PingContext(ctx); err == nil {
			return nil
		}

		if !isBusy(err) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 20 * time.Millisecond):
		}
	}

	return err
}

// isBusy reports whether err is a SQLite lock/busy condition worth retrying.
func isBusy(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()

	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "SQLITE_BUSY") ||
		strings.Contains(msg, "(5)")
}

func (s *Store) migrate() error { //nolint:funcorder // grouped with the other setup logic
	ctx, cancel := opContext()
	defer cancel()

	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

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
		var applied int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}

		if applied > 0 {
			continue
		}

		sqlBytes, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if _, err := s.db.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}

		// OR IGNORE: two processes racing a cold-start init may both apply an
		// IF-NOT-EXISTS migration; recording it must not fail the second one.
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO schema_migrations (name) VALUES (?)`, name); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}

	return nil
}

// Insert appends one record to the audit log. It never updates or deletes.
// opTimeout bounds a single audit DB operation so a wedged database (a stuck
// lock, a hung fsync) can never hang the git command driving it. Audit is
// best-effort: a timeout surfaces as an error the caller warns on, not a freeze.
const opTimeout = 5 * time.Second

// opContext returns a context bounded by opTimeout for one DB operation.
func opContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

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

	enrStr := ""
	if len(r.Enrichment) > 0 {
		enrStr = string(r.Enrichment)
	}

	ts := r.TS.UTC().Format(time.RFC3339Nano)

	ctx, cancel := opContext()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit tx: %w", err)
	}

	defer func() { _ = tx.Rollback() }()

	var prev string
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(row_hash, '') FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read chain head: %w", err)
	}

	v := rowValues{
		ts: ts, osUser: r.OSUser, identity: r.Identity, cwd: r.Cwd,
		argv: string(argv), env: string(env), backend: r.Backend,
		backendPath: r.BackendPath, mode: r.Mode, shortcut: r.Shortcut,
		enrichment: enrStr, exit: r.ExitCode, durMs: r.Duration.Milliseconds(),
	}
	rowHash := chainHash(prev, v)

	const q = `INSERT INTO audit_log
        (ts, os_user, identity, cwd, argv, env_subset, backend, backend_path,
         mode, shortcut, exit_code, duration_ms, enrichment, prev_hash, row_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if _, err := tx.ExecContext(ctx, q,
		ts, r.OSUser, identity, r.Cwd, string(argv), string(env),
		r.Backend, r.BackendPath, r.Mode, shortcut,
		r.ExitCode, r.Duration.Milliseconds(), enrichment, prev, rowHash,
	); err != nil {
		return fmt.Errorf("insert audit row: %w", err)
	}

	return tx.Commit()
}

// rowValues holds the audited field values in a fixed order for the tamper-
// evident hash chain, so Insert and Verify compute identical hashes.
type rowValues struct {
	ts, osUser, identity, cwd, argv, env string
	backend, backendPath, mode, shortcut string
	enrichment                           string
	exit                                 int
	durMs                                int64
}

func (v rowValues) fields() []string {
	return []string{
		v.ts, v.osUser, v.identity, v.cwd, v.argv, v.env,
		v.backend, v.backendPath, v.mode, v.shortcut,
		strconv.Itoa(v.exit), strconv.FormatInt(v.durMs, 10), v.enrichment,
	}
}

// chainHash is sha256(prev_hash | 0x1f-separated field values); each row's hash
// folds in the previous row's hash, so any deletion or edit breaks the chain.
func chainHash(prev string, v rowValues) string {
	h := sha256.New()
	_, _ = h.Write([]byte(prev))

	for _, f := range v.fields() {
		_, _ = h.Write([]byte{0x1f})
		_, _ = h.Write([]byte(f))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}

	return s.db.Close()
}
