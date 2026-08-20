//! Port of Go `internal/store` (store.go + query.go) — the forensic audit
//! database: schema migrations, the append-only [`Record`] model, connection
//! setup with owner-only file permissions, and the tamper-evident hash chain.
//!
//! ## Faithfulness (security-critical)
//!
//! - **Hash chain (byte-for-byte with Go).** Each row's `row_hash` =
//!   `sha256(prev_hash ‖ 0x1f field ‖ 0x1f field ‖ …)` over the field values in
//!   the EXACT Go order (see [`chain_hash`] / [`RowValues`]):
//!   `ts, os_user, identity, cwd, argv, env, backend, backend_path, mode,
//!   shortcut, exit(decimal), duration_ms(decimal), enrichment`. `prev_hash` is
//!   the previous row's `row_hash` (empty string for the first row). Any
//!   deletion/edit breaks the chain, which [`Store::verify`] detects. This
//!   reproduces Go's `chainHash` preimage precisely so a chain written by either
//!   implementation validates.
//! - **Migrations** run in sorted name order on [`open`], guarded by a
//!   `schema_migrations` bookkeeping table, `INSERT OR IGNORE` for the cold-start
//!   race — exactly as Go's `migrate()`. The three `.sql` files are embedded
//!   byte-identical via `include_str!`.
//! - **PRAGMAs** match Go's DSN: `busy_timeout=5000`, `journal_mode=WAL`,
//!   `synchronous=NORMAL`; every write transaction is `BEGIN IMMEDIATE`
//!   (Go's `_txlock=immediate`) so concurrent writers serialize on the busy
//!   timeout instead of dead-locking on a lock upgrade.
//!
//! ## Preserved quirks / documented deviations
//!
//! - Go marshals a `nil` slice/map to JSON `null` and an empty one to `[]`/`{}`.
//!   [`Record::env_subset`] is `Option<BTreeMap<..>>` to reproduce this exactly
//!   (`None`→`null`, `Some(empty)`→`{}`, `Some(map)`→sorted-key object like Go).
//!   [`Record::argv`] is a plain `Vec<String>`; an empty argv serializes to `[]`
//!   (Go's nil would be `null`), but every call site supplies a non-empty argv.
//! - Timestamps use the `time` crate's RFC 3339 (std has none). Go uses
//!   `RFC3339Nano`; the stored value is re-hashed from storage on verify, so the
//!   chain is internally consistent regardless of any subsecond-formatting
//!   nuance between the two RFC 3339 encoders.
//! - `Store::close` is an explicit close (Go `Close() error`); [`Drop`] is the
//!   RAII safety net. Queries after close return [`Error::Closed`].

#[cfg(feature = "app")]
use std::cell::RefCell;
#[cfg(feature = "app")]
use std::collections::BTreeMap;
#[cfg(feature = "app")]
use std::fmt;
#[cfg(feature = "app")]
use std::fs::{self, OpenOptions};
#[cfg(feature = "app")]
use std::io::{self, Write};
#[cfg(feature = "app")]
use std::path::Path;
#[cfg(feature = "app")]
use std::time::Duration;

#[cfg(feature = "app")]
use rusqlite::{params, Connection, TransactionBehavior};
#[cfg(feature = "app")]
use sha2::{Digest, Sha256};
#[cfg(feature = "app")]
use time::format_description::well_known::Rfc3339;
#[cfg(feature = "app")]
use time::{OffsetDateTime, UtcOffset};

/// How long SQLite waits for a held lock before returning `SQLITE_BUSY`, so
/// concurrent gitc processes serialize their audit writes. Go `busyTimeoutMS`.
#[cfg(feature = "app")]
const BUSY_TIMEOUT_MS: i64 = 5000;

/// The embedded schema migrations, in sorted (apply) order. Go embeds
/// `migrations/*.sql` and sorts by name; the order is fixed here to match.
#[cfg(feature = "app")]
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_audit.sql",
        include_str!("store_migrations/0001_audit.sql"),
    ),
    (
        "0002_audit_chain.sql",
        include_str!("store_migrations/0002_audit_chain.sql"),
    ),
    (
        "0003_resolved_policy_path.sql",
        include_str!("store_migrations/0003_resolved_policy_path.sql"),
    ),
];

/// One forensic audit entry: everything gitc knows about a single git
/// invocation. Values are stored raw and unredacted by design. Go `Record`.
#[cfg(feature = "app")]
#[derive(Debug, Clone)]
pub struct Record {
    /// Invocation start (stored as RFC 3339 UTC). Go `TS time.Time`.
    pub ts: OffsetDateTime,
    /// OS username. Go `OSUser`.
    pub os_user: String,
    /// Resolved identity, if any (`""` = none → stored NULL). Go `Identity`.
    pub identity: String,
    /// Working directory. Go `Cwd`.
    pub cwd: String,
    /// argv passed to the backend (URL/auth credentials masked). Go `Argv`.
    pub argv: Vec<String>,
    /// Captured git-relevant env vars, credential-masked. Go `EnvSubset`
    /// (`map[string]string`): `None` marshals to `null`, `Some` to a
    /// sorted-key JSON object, exactly like Go.
    pub env_subset: Option<BTreeMap<String, String>>,
    /// `"vendored"` | `"system"`. Go `Backend`.
    pub backend: String,
    /// Resolved absolute backend binary path. Go `BackendPath`.
    pub backend_path: String,
    /// `"passthrough"` | `"shortcut"` | `"blocked"`. Go `Mode`.
    pub mode: String,
    /// Shortcut name when `mode == "shortcut"` (`""` → stored NULL). Go `Shortcut`.
    pub shortcut: String,
    /// Backend exit code. Go `ExitCode`.
    pub exit_code: i32,
    /// Wall-clock exec duration. Go `Duration`.
    pub duration: Duration,
    /// Optional libgit2 JSON blob, `None`/empty if unavailable (→ stored NULL).
    /// Go `Enrichment json.RawMessage`.
    pub enrichment: Option<String>,
    /// Resolved enforcement policy path in effect (`""` = none → stored NULL).
    /// Go `PolicyPath`.
    pub policy_path: String,
}

#[cfg(feature = "app")]
impl Default for Record {
    fn default() -> Self {
        Record {
            ts: OffsetDateTime::UNIX_EPOCH,
            os_user: String::new(),
            identity: String::new(),
            cwd: String::new(),
            argv: Vec::new(),
            env_subset: None,
            backend: String::new(),
            backend_path: String::new(),
            mode: String::new(),
            shortcut: String::new(),
            exit_code: 0,
            duration: Duration::ZERO,
            enrichment: None,
            policy_path: String::new(),
        }
    }
}

/// The append-only audit log backing store. Go `Store`.
///
/// Holds a single long-lived SQLite connection (Go pins `SetMaxOpenConns(1)`),
/// behind `RefCell` for interior mutability; [`close`](Store::close) takes and
/// drops the connection so later queries surface [`Error::Closed`].
#[cfg(feature = "app")]
pub struct Store {
    conn: RefCell<Option<Connection>>,
}

#[cfg(feature = "app")]
impl Store {
    fn migrate(&self) -> Result<(), Error> {
        let guard = self.conn.borrow();
        let conn = guard.as_ref().ok_or(Error::Closed)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)",
            [],
        )?;

        for &(name, sql) in MIGRATIONS {
            let applied: i64 = conn.query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE name = ?1",
                [name],
                |row| row.get(0),
            )?;

            if applied > 0 {
                continue;
            }

            conn.execute_batch(sql)?;

            // OR IGNORE: two processes racing a cold-start init may both apply an
            // IF-NOT-EXISTS migration; recording it must not fail the second one.
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (name) VALUES (?1)",
                [name],
            )?;
        }

        Ok(())
    }

    /// Append one record to the audit log. It never updates or deletes.
    ///
    /// Reads the hash-chain head and appends in one `BEGIN IMMEDIATE`
    /// transaction so concurrent writers serialize on the busy timeout. Go
    /// `Insert`.
    pub fn insert(&self, r: &Record) -> Result<(), Error> {
        let argv = serde_json::to_string(&r.argv)?;
        let env = serde_json::to_string(&r.env_subset)?;

        let has_enr = r.enrichment.as_ref().is_some_and(|e| !e.is_empty());
        let enr_str: &str = if has_enr {
            r.enrichment.as_deref().unwrap_or("")
        } else {
            ""
        };

        let ts = r.ts.to_offset(UtcOffset::UTC).format(&Rfc3339)?;
        let dur_ms = r.duration.as_millis() as i64;

        let mut guard = self.conn.borrow_mut();
        let conn = guard.as_mut().ok_or(Error::Closed)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let prev: String = match tx.query_row(
            "SELECT COALESCE(row_hash, '') FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        ) {
            Ok(p) => p,
            Err(rusqlite::Error::QueryReturnedNoRows) => String::new(),
            Err(e) => return Err(Error::Sqlite(e)),
        };

        let v = RowValues {
            ts: ts.clone(),
            os_user: r.os_user.clone(),
            identity: r.identity.clone(),
            cwd: r.cwd.clone(),
            argv: argv.clone(),
            env: env.clone(),
            backend: r.backend.clone(),
            backend_path: r.backend_path.clone(),
            mode: r.mode.clone(),
            shortcut: r.shortcut.clone(),
            enrichment: enr_str.to_string(),
            exit: r.exit_code as i64,
            dur_ms,
        };
        let row_hash = chain_hash(&prev, &v);

        // NULL-able columns: an empty string persists as NULL (COALESCE'd back to
        // "" on read), while the hash folds in the raw "" — identical to Go.
        let identity_p: Option<&str> = opt(&r.identity);
        let shortcut_p: Option<&str> = opt(&r.shortcut);
        let enrichment_p: Option<&str> = if has_enr { Some(enr_str) } else { None };
        let policy_p: Option<&str> = opt(&r.policy_path);

        tx.execute(
            "INSERT INTO audit_log
                (ts, os_user, identity, cwd, argv, env_subset, backend, backend_path,
                 mode, shortcut, exit_code, duration_ms, enrichment, prev_hash, row_hash,
                 resolved_policy_path)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                ts,
                r.os_user,
                identity_p,
                r.cwd,
                argv,
                env,
                r.backend,
                r.backend_path,
                r.mode,
                shortcut_p,
                r.exit_code,
                dur_ms,
                enrichment_p,
                prev,
                row_hash,
                policy_p,
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Return the most recent `n` audit rows (newest first) as structured data
    /// for the interactive viewer. Read-only. `n <= 0` defaults to 200. Go
    /// `Records`.
    pub fn records(&self, n: i64) -> Result<Vec<AuditRow>, Error> {
        let n = if n <= 0 { 200 } else { n };

        let guard = self.conn.borrow();
        let conn = guard.as_ref().ok_or(Error::Closed)?;

        let mut stmt = conn.prepare(
            "SELECT id, ts, os_user, COALESCE(identity,''), cwd, argv, env_subset,
                backend, backend_path, mode, COALESCE(shortcut,''), exit_code, duration_ms,
                COALESCE(enrichment,''), COALESCE(resolved_policy_path,'')
                FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([n], |row| {
            Ok(AuditRow {
                id: row.get(0)?,
                ts: row.get(1)?,
                os_user: row.get(2)?,
                identity: row.get(3)?,
                cwd: row.get(4)?,
                argv: row.get(5)?,
                env: row.get(6)?,
                backend: row.get(7)?,
                backend_path: row.get(8)?,
                mode: row.get(9)?,
                shortcut: row.get(10)?,
                exit: row.get(11)?,
                duration_ms: row.get(12)?,
                enrichment: row.get(13)?,
                policy_path: row.get(14)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Write the most recent `n` audit rows to `w`, oldest first. Compact
    /// one-line summary unless `wide`. Read-only. `n <= 0` defaults to 20. Go
    /// `Tail`.
    pub fn tail(&self, n: i64, wide: bool, w: &mut dyn Write) -> Result<(), Error> {
        let n = if n <= 0 { 20 } else { n };

        let guard = self.conn.borrow();
        let conn = guard.as_ref().ok_or(Error::Closed)?;

        let mut stmt = conn.prepare(
            "SELECT ts, os_user, mode, COALESCE(shortcut, ''), exit_code, backend, argv,
                COALESCE(enrichment, '')
                FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([n], |row| {
            Ok(AuditLine {
                ts: row.get(0)?,
                user: row.get(1)?,
                mode: row.get(2)?,
                shortcut: row.get(3)?,
                exit: row.get(4)?,
                backend: row.get(5)?,
                argv: row.get(6)?,
                enrichment: row.get(7)?,
            })
        })?;

        let mut lines = Vec::new();
        for r in rows {
            lines.push(r?);
        }

        for l in lines.iter().rev() {
            if wide {
                render_wide(w, l);
            } else {
                render_compact(w, l);
            }
        }

        Ok(())
    }

    /// Walk the audit hash chain oldest-first and report the first row whose
    /// stored hash or previous-link does not recompute — evidence of a deleted
    /// or edited row. Legacy (pre-AUD-2) rows carry no hash and are counted, not
    /// verified. Go `Verify`.
    pub fn verify(&self) -> Result<VerifyResult, Error> {
        let guard = self.conn.borrow();
        let conn = guard.as_ref().ok_or(Error::Closed)?;

        let mut stmt = conn.prepare(
            "SELECT id, ts, os_user, COALESCE(identity,''), cwd, argv, env_subset,
                backend, backend_path, mode, COALESCE(shortcut,''), exit_code, duration_ms,
                COALESCE(enrichment,''), COALESCE(prev_hash,''), COALESCE(row_hash,'')
                FROM audit_log ORDER BY id ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                RowValues {
                    ts: row.get(1)?,
                    os_user: row.get(2)?,
                    identity: row.get(3)?,
                    cwd: row.get(4)?,
                    argv: row.get(5)?,
                    env: row.get(6)?,
                    backend: row.get(7)?,
                    backend_path: row.get(8)?,
                    mode: row.get(9)?,
                    shortcut: row.get(10)?,
                    exit: row.get(11)?,
                    dur_ms: row.get(12)?,
                    enrichment: row.get(13)?,
                },
                row.get::<_, String>(14)?,
                row.get::<_, String>(15)?,
            ))
        })?;

        let mut res = VerifyResult {
            checked: 0,
            legacy: 0,
            intact: true,
            broken_id: 0,
        };
        let mut prev = String::new();

        for row in rows {
            let (id, v, prev_hash, row_hash) = row?;

            if row_hash.is_empty() {
                res.legacy += 1;
                continue;
            }

            if prev_hash != prev || row_hash != chain_hash(&prev, &v) {
                res.intact = false;
                res.broken_id = id;
                break;
            }

            res.checked += 1;
            prev = row_hash;
        }

        Ok(res)
    }

    /// Return every row's id, argv, and env_subset, oldest first — for scanning
    /// the audit log itself for secrets. Go `RawRows`.
    pub fn raw_rows(&self) -> Result<Vec<RawRow>, Error> {
        let guard = self.conn.borrow();
        let conn = guard.as_ref().ok_or(Error::Closed)?;

        let mut stmt =
            conn.prepare("SELECT id, argv, env_subset FROM audit_log ORDER BY id ASC")?;

        let rows = stmt.query_map([], |row| {
            Ok(RawRow {
                id: row.get(0)?,
                argv: row.get(1)?,
                env: row.get(2)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Release the database handle. Idempotent; later queries return
    /// [`Error::Closed`]. Go `Close`.
    pub fn close(&self) -> Result<(), Error> {
        // Dropping the connection closes it (RAII); mirrors Go's db.Close().
        self.conn.borrow_mut().take();
        Ok(())
    }
}

/// Open (creating if needed) the audit database at `path`, ensure its parent
/// directory and the file are owner-only, apply pragmas, and run the embedded
/// migrations. Go `Open`.
#[cfg(feature = "app")]
pub fn open(path: impl AsRef<Path>) -> Result<Store, Error> {
    let path = path.as_ref();

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
            harden_dir(parent);
        }
    }

    // Pre-create the file with restrictive permissions so the DB is never briefly
    // world-readable. Best-effort; skipped when it already exists so a concurrent
    // reopen never contends the in-use file. On Windows mode bits are a near
    // no-op (ACL hardening is the installer's job), as in Go.
    pre_create(path);

    let conn = Connection::open(path)?;

    // Bake in Go's DSN pragmas on this connection. busy_timeout first so the WAL
    // switch (which needs a brief lock) waits under contention instead of erroring.
    conn.execute_batch(&format!(
        "PRAGMA busy_timeout={BUSY_TIMEOUT_MS};\nPRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;"
    ))?;

    let store = Store {
        conn: RefCell::new(Some(conn)),
    };
    store.migrate()?;

    Ok(store)
}

#[cfg(feature = "app")]
impl Drop for Store {
    fn drop(&mut self) {
        self.conn.borrow_mut().take();
    }
}

#[cfg(all(feature = "app", unix))]
fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
}

#[cfg(all(feature = "app", not(unix)))]
fn harden_dir(_dir: &Path) {}

#[cfg(all(feature = "app", unix))]
fn pre_create(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt;
    if !path.exists() {
        let _ = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(path);
    }
}

#[cfg(all(feature = "app", not(unix)))]
fn pre_create(path: &Path) {
    if !path.exists() {
        let _ = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path);
    }
}

/// `""` → `None` (stored SQL NULL), any other string → `Some`.
#[cfg(feature = "app")]
fn opt(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ── the tamper-evident hash chain ───────────────────────────────────────────

/// The audited field values in a fixed order for the hash chain, so `insert`
/// and `verify` compute identical hashes. Go `rowValues`.
#[cfg(feature = "app")]
struct RowValues {
    ts: String,
    os_user: String,
    identity: String,
    cwd: String,
    argv: String,
    env: String,
    backend: String,
    backend_path: String,
    mode: String,
    shortcut: String,
    enrichment: String,
    exit: i64,
    dur_ms: i64,
}

/// `sha256(prev_hash ‖ 0x1f-separated field values)` as lowercase hex. Each
/// row's hash folds in the previous row's hash, so any deletion or edit breaks
/// the chain. Field order and the `0x1f` (US) separator match Go `chainHash`
/// byte-for-byte:
///
/// `prev ‖ 0x1f ts ‖ 0x1f os_user ‖ 0x1f identity ‖ 0x1f cwd ‖ 0x1f argv ‖
///  0x1f env ‖ 0x1f backend ‖ 0x1f backend_path ‖ 0x1f mode ‖ 0x1f shortcut ‖
///  0x1f exit(decimal) ‖ 0x1f duration_ms(decimal) ‖ 0x1f enrichment`.
#[cfg(feature = "app")]
fn chain_hash(prev: &str, v: &RowValues) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());

    // The exact Go fields() order: 10 string fields, then exit, duration_ms
    // (as decimal strings), then enrichment last.
    for f in [
        &v.ts,
        &v.os_user,
        &v.identity,
        &v.cwd,
        &v.argv,
        &v.env,
        &v.backend,
        &v.backend_path,
        &v.mode,
        &v.shortcut,
    ] {
        h.update([0x1f]);
        h.update(f.as_bytes());
    }

    h.update([0x1f]);
    h.update(v.exit.to_string().as_bytes());
    h.update([0x1f]);
    h.update(v.dur_ms.to_string().as_bytes());
    h.update([0x1f]);
    h.update(v.enrichment.as_bytes());

    to_hex(h.finalize().as_slice())
}

/// Lowercase hex encoding (Go `encoding/hex`). std has no hex; this is a
/// small self-contained slice, not worth a dependency.
#[cfg(feature = "app")]
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ── query.go: structured/rendered read views ────────────────────────────────

/// One audit record exposed for structured/interactive consumption (the audit
/// TUI). `argv`/`env` are the stored JSON blobs; [`command`](AuditRow::command)
/// decodes argv. Go `AuditRow`.
#[cfg(feature = "app")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: i64,
    pub ts: String,
    pub os_user: String,
    pub identity: String,
    pub cwd: String,
    /// JSON array (credential-masked).
    pub argv: String,
    /// JSON object.
    pub env: String,
    pub backend: String,
    pub backend_path: String,
    pub mode: String,
    pub shortcut: String,
    pub exit: i32,
    pub duration_ms: i64,
    pub enrichment: String,
    /// Resolved enforcement policy path in effect (`""` = none).
    pub policy_path: String,
}

#[cfg(feature = "app")]
impl AuditRow {
    /// Decode the stored argv JSON into a readable space-joined command; on a
    /// decode error, return the raw argv string. Go `Command`.
    pub fn command(&self) -> String {
        match serde_json::from_str::<Vec<String>>(&self.argv) {
            Ok(argv) => argv.join(" "),
            Err(_) => self.argv.clone(),
        }
    }

    /// Report whether this row is a policy-refused (never-executed) command. Go
    /// `Blocked`.
    pub fn blocked(&self) -> bool {
        self.mode == "blocked"
    }
}

/// The outcome of an audit hash-chain check. Go `VerifyResult`.
#[cfg(feature = "app")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResult {
    /// Hashed rows verified in-chain.
    pub checked: i64,
    /// Pre-AUD-2 rows without a hash (unverifiable).
    pub legacy: i64,
    /// Every hashed row links correctly.
    pub intact: bool,
    /// Id of the first failing row (0 when intact).
    pub broken_id: i64,
}

/// A stored invocation's raw argv + captured env, for scanning the audit log
/// itself for secrets (`git scan --audit`). Go `RawRow`.
#[cfg(feature = "app")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRow {
    pub id: i64,
    pub argv: String,
    pub env: String,
}

/// One decoded audit row for rendering. Go `auditLine`.
#[cfg(feature = "app")]
struct AuditLine {
    ts: String,
    user: String,
    mode: String,
    shortcut: String,
    backend: String,
    argv: String,
    enrichment: String,
    exit: i32,
}

/// Print the full audit record. Go `renderWide`.
#[cfg(feature = "app")]
fn render_wide(w: &mut dyn Write, l: &AuditLine) {
    let tag = if l.shortcut.is_empty() {
        l.mode.clone()
    } else {
        format!("{}:{}", l.mode, l.shortcut)
    };

    let _ = writeln!(
        w,
        "{}  {:<12}  exit={:<3}  {:<8}  [{}]  {}{}",
        l.ts,
        l.user,
        l.exit,
        l.backend,
        tag,
        l.argv,
        format_enrichment(&l.enrichment)
    );
}

/// Print a short one-line summary: time, status, branch, command. A
/// policy-refused row shows BLOCKED rather than an exit code. Go `renderCompact`.
#[cfg(feature = "app")]
fn render_compact(w: &mut dyn Write, l: &AuditLine) {
    let status = if l.mode == "blocked" {
        "BLOCKED".to_string()
    } else {
        format!("exit={:<2}", l.exit)
    };

    let _ = writeln!(
        w,
        "{}  {:<8}  {:<22}  {}",
        short_time(&l.ts),
        status,
        short_branch(&l.enrichment),
        short_argv(&l.argv, 64)
    );
}

/// Extract `HH:MM:SS` from an RFC 3339 timestamp. Go `shortTime`.
#[cfg(feature = "app")]
fn short_time(ts: &str) -> String {
    let bytes = ts.as_bytes();
    if let Some(i) = bytes.iter().position(|&b| b == b'T') {
        if bytes.len() >= i + 9 {
            return ts[i + 1..i + 9].to_string();
        }
    }
    ts.to_string()
}

/// Decode the stored argv JSON into a space-joined command, truncated to
/// `max_len`. Go `shortArgv`.
#[cfg(feature = "app")]
fn short_argv(argv_json: &str, max_len: usize) -> String {
    match serde_json::from_str::<Vec<String>>(argv_json) {
        Ok(argv) => truncate(&argv.join(" "), max_len),
        Err(_) => truncate(argv_json, max_len),
    }
}

/// Byte-bounded truncation with a `…` ellipsis, matching Go `truncate` (which
/// slices bytes). Uses lossy UTF-8 recovery so a cut inside a multibyte rune
/// never panics (Go would emit the raw partial bytes).
#[cfg(feature = "app")]
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    if max_len <= 1 {
        return String::from_utf8_lossy(&s.as_bytes()[..max_len]).into_owned();
    }
    let head = String::from_utf8_lossy(&s.as_bytes()[..max_len - 1]);
    format!("{head}…")
}

/// Pull the branch name from the enrichment JSON, or `-` if absent. Go
/// `shortBranch`.
#[cfg(feature = "app")]
fn short_branch(enrichment: &str) -> String {
    if enrichment.is_empty() {
        return "-".to_string();
    }
    match serde_json::from_str::<BranchOnly>(enrichment) {
        Ok(s) if !s.branch.is_empty() => s.branch,
        _ => "-".to_string(),
    }
}

/// Render the stored enrichment JSON into a compact suffix. Schema-tolerant: any
/// parseable object is summarized; anything else is dropped. Go `formatEnrichment`.
#[cfg(feature = "app")]
fn format_enrichment(blob: &str) -> String {
    if blob.is_empty() {
        return String::new();
    }
    match serde_json::from_str::<Enrichment>(blob) {
        Ok(s) => format!(
            "  {{{} +{}/-{} staged={} unstaged={} untracked={} conflicts={}}}",
            s.branch, s.ahead, s.behind, s.staged, s.unstaged, s.untracked, s.conflicts
        ),
        Err(_) => String::new(),
    }
}

#[cfg(feature = "app")]
#[derive(serde::Deserialize)]
struct BranchOnly {
    #[serde(default)]
    branch: String,
}

#[cfg(feature = "app")]
#[derive(serde::Deserialize)]
struct Enrichment {
    #[serde(default)]
    branch: String,
    #[serde(default)]
    ahead: i64,
    #[serde(default)]
    behind: i64,
    #[serde(default)]
    staged: i64,
    #[serde(default)]
    unstaged: i64,
    #[serde(default)]
    untracked: i64,
    #[serde(default)]
    conflicts: i64,
}

// ── error type ──────────────────────────────────────────────────────────────

/// Errors from the audit store. Go returns wrapped `error` values; here they map
/// to a per-module enum (glossary convention).
#[cfg(feature = "app")]
#[derive(Debug)]
pub enum Error {
    /// Filesystem error creating the audit dir / file.
    Io(io::Error),
    /// A SQLite error (open, migrate, query, transaction).
    Sqlite(rusqlite::Error),
    /// JSON (de)serialization of argv/env/enrichment.
    Json(serde_json::Error),
    /// RFC 3339 formatting of the timestamp.
    TimeFormat(time::error::Format),
    /// An operation was attempted after [`Store::close`].
    Closed,
}

#[cfg(feature = "app")]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "audit store io: {e}"),
            Error::Sqlite(e) => write!(f, "audit store sqlite: {e}"),
            Error::Json(e) => write!(f, "audit store json: {e}"),
            Error::TimeFormat(e) => write!(f, "audit store timestamp: {e}"),
            Error::Closed => write!(f, "audit store is closed"),
        }
    }
}

#[cfg(feature = "app")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Sqlite(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::TimeFormat(e) => Some(e),
            Error::Closed => None,
        }
    }
}

#[cfg(feature = "app")]
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(feature = "app")]
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}

#[cfg(feature = "app")]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

#[cfg(feature = "app")]
impl From<time::error::Format> for Error {
    fn from(e: time::error::Format) -> Self {
        Error::TimeFormat(e)
    }
}

// ── tests (ported from store_test.go, errpath_test.go, policypath_test.go,
//    concurrency_test.go) ──────────────────────────────────────────────────
#[cfg(all(test, feature = "app"))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use time::OffsetDateTime;

    /// Minimal std-only temp dir (no `tempfile` dependency); Go `t.TempDir()`.
    struct TmpDir {
        path: PathBuf,
    }

    impl TmpDir {
        fn new() -> TmpDir {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "gitc-store-test-{}-{}-{}",
                std::process::id(),
                nanos,
                n
            ));
            fs::create_dir_all(&path).unwrap();
            TmpDir { path }
        }

        fn join(&self, s: &str) -> PathBuf {
            self.path.join(s)
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn env_map(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), (*v).to_string());
        }
        Some(m)
    }

    fn pragma_i64(s: &Store, q: &str) -> i64 {
        let guard = s.conn.borrow();
        let conn = guard.as_ref().unwrap();
        conn.query_row(q, [], |r| r.get::<_, i64>(0)).unwrap()
    }

    fn count_rows(s: &Store) -> i64 {
        let guard = s.conn.borrow();
        let conn = guard.as_ref().unwrap();
        conn.query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap()
    }

    // TestOpenInsertAndTail
    #[test]
    fn open_insert_and_tail() {
        let tmp = TmpDir::new();
        let db_path = tmp.path().join("audit").join("gitc.db");

        let s = open(&db_path).expect("Open");

        let rec = Record {
            ts: OffsetDateTime::now_utc(),
            os_user: "alice".into(),
            identity: "Alice Example".into(),
            cwd: "/repo".into(),
            argv: vec!["commit".into(), "-m".into(), "hello".into()],
            env_subset: env_map(&[("GIT_AUTHOR_NAME", "alice"), ("PATH", "/usr/bin")]),
            backend: "system".into(),
            backend_path: "/usr/bin/git".into(),
            mode: "passthrough".into(),
            exit_code: 0,
            duration: Duration::from_millis(42),
            enrichment: Some(r#"{"files":3}"#.into()),
            ..Default::default()
        };
        s.insert(&rec).expect("Insert");

        // Second row to confirm append-only accumulation and ordering.
        let mut rec2 = rec.clone();
        rec2.argv = vec!["push".into()];
        rec2.exit_code = 1;
        s.insert(&rec2).expect("Insert 2");

        let mut buf: Vec<u8> = Vec::new();
        s.tail(10, true, &mut buf).expect("Tail");

        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("alice"), "tail missing user: {out:?}");
        assert!(
            out.contains("commit") && out.contains("push"),
            "tail missing argv rows: {out:?}"
        );
        // Oldest-first ordering: commit (row 1) before push (row 2).
        assert!(
            out.find("commit").unwrap() < out.find("push").unwrap(),
            "tail not oldest-first: {out:?}"
        );
    }

    // TestOpenAppliesBusyTimeout
    #[test]
    fn open_applies_busy_timeout() {
        let tmp = TmpDir::new();
        let s = open(tmp.join("gitc.db")).expect("Open");
        let got = pragma_i64(&s, "PRAGMA busy_timeout");
        assert_eq!(got, BUSY_TIMEOUT_MS, "busy_timeout mismatch");
    }

    // TestVerifyDetectsTamper
    #[test]
    fn verify_detects_tamper() {
        let tmp = TmpDir::new();
        let s = open(tmp.join("gitc.db")).expect("Open");

        for _ in 0..3 {
            let rec = Record {
                ts: OffsetDateTime::now_utc(),
                os_user: "u".into(),
                cwd: ".".into(),
                argv: vec!["status".into()],
                env_subset: Some(BTreeMap::new()),
                backend: "system".into(),
                backend_path: "/git".into(),
                mode: "passthrough".into(),
                exit_code: 0,
                duration: Duration::from_millis(1),
                ..Default::default()
            };
            s.insert(&rec).expect("Insert");
        }

        let res = s.verify().expect("Verify");
        assert!(
            res.intact && res.checked == 3,
            "expected intact chain of 3, got {res:?}"
        );

        // Tamper: edit row 2's argv directly, bypassing Insert.
        {
            let guard = s.conn.borrow();
            let conn = guard.as_ref().unwrap();
            conn.execute(r#"UPDATE audit_log SET argv = '["evil"]' WHERE id = 2"#, [])
                .unwrap();
        }

        let res = s.verify().expect("Verify after tamper");
        assert!(
            !res.intact && res.broken_id == 2,
            "expected chain broken at id 2, got {res:?}"
        );
    }

    // TestInsertNilOptionalFields
    #[test]
    fn insert_nil_optional_fields() {
        let tmp = TmpDir::new();
        let s = open(tmp.join("gitc.db")).expect("Open");

        // No identity, no shortcut, no enrichment — should insert cleanly as NULLs.
        let rec = Record {
            ts: OffsetDateTime::now_utc(),
            os_user: "bob".into(),
            cwd: ".".into(),
            argv: vec!["status".into()],
            env_subset: Some(BTreeMap::new()),
            backend: "vendored".into(),
            backend_path: "/opt/git".into(),
            mode: "passthrough".into(),
            exit_code: 0,
            duration: Duration::from_millis(1),
            ..Default::default()
        };
        s.insert(&rec).expect("Insert");
    }

    // TestOpenOnDirectoryFails
    #[test]
    fn open_on_directory_fails() {
        // Opening a directory as the SQLite file must error, not panic.
        let tmp = TmpDir::new();
        let r = open(tmp.path());
        assert!(r.is_err(), "Open on a directory path should fail");
    }

    // TestQueriesAfterCloseError
    #[test]
    fn queries_after_close_error() {
        let tmp = TmpDir::new();
        let s = open(tmp.join("audit.db")).expect("Open");

        s.close().expect("Close");

        assert!(s.records(1).is_err(), "Records after Close should error");
        assert!(s.raw_rows().is_err(), "RawRows after Close should error");
        assert!(s.verify().is_err(), "Verify after Close should error");
    }

    // TestInsertRecordsPolicyPath
    #[test]
    fn insert_records_policy_path() {
        let tmp = TmpDir::new();
        let s = open(tmp.join("audit.db")).expect("Open");

        let want = r"C:\ProgramData\gitc\policy.json";
        let rec = Record {
            ts: OffsetDateTime::now_utc(),
            os_user: "dev".into(),
            cwd: ".".into(),
            argv: vec!["push".into(), "origin".into(), "main".into()],
            backend: "system".into(),
            mode: "passthrough".into(),
            policy_path: want.into(),
            ..Default::default()
        };
        s.insert(&rec).expect("Insert");

        let rows = s.records(1).expect("Records");
        assert_eq!(rows.len(), 1, "want 1 row");
        assert_eq!(rows[0].policy_path, want, "PolicyPath round-trip");
    }

    // TestInsertEmptyPolicyPath
    #[test]
    fn insert_empty_policy_path() {
        let tmp = TmpDir::new();
        let s = open(tmp.join("audit.db")).expect("Open");

        // No policy in effect: the column persists as empty, not a literal "".
        let rec = Record {
            ts: OffsetDateTime::now_utc(),
            os_user: "dev".into(),
            argv: vec!["status".into()],
            mode: "passthrough".into(),
            ..Default::default()
        };
        s.insert(&rec).expect("Insert");

        let rows = s.records(1).expect("Records");
        assert!(
            rows.len() == 1 && rows[0].policy_path.is_empty(),
            "empty PolicyPath expected, got {:?}",
            rows.first().map(|r| &r.policy_path)
        );
    }

    // TestWALEnabled
    #[test]
    fn wal_enabled() {
        let tmp = TmpDir::new();
        let s = open(tmp.join("audit.db")).expect("Open");

        let mode: String = {
            let guard = s.conn.borrow();
            let conn = guard.as_ref().unwrap();
            conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap()
        };
        assert!(
            mode.eq_ignore_ascii_case("wal"),
            "journal_mode = {mode:?}, want wal"
        );

        let busy = pragma_i64(&s, "PRAGMA busy_timeout");
        assert_eq!(busy, BUSY_TIMEOUT_MS, "busy_timeout mismatch");
    }

    fn sample_record(writer: usize, seq: usize) -> Record {
        Record {
            ts: OffsetDateTime::now_utc(),
            os_user: "tester".into(),
            cwd: "/repo".into(),
            argv: vec!["status".into(), writer.to_string(), seq.to_string()],
            env_subset: Some(BTreeMap::new()),
            backend: "vendored".into(),
            backend_path: "/git".into(),
            mode: "passthrough".into(),
            exit_code: 0,
            duration: Duration::from_millis(1),
            ..Default::default()
        }
    }

    // TestConcurrentWritersNoLock
    #[test]
    fn concurrent_writers_no_lock() {
        let tmp = TmpDir::new();
        let path = tmp.join("audit.db");

        // Initialize the DB once (WAL + schema), as the first-ever gitc run would.
        let init = open(&path).expect("init open");
        init.close().expect("init close");
        drop(init);

        const WRITERS: usize = 8;
        const PER_WRITER: usize = 30;

        let mut handles = Vec::new();
        for w in 0..WRITERS {
            let path = path.clone();
            handles.push(thread::spawn(move || -> Result<(), String> {
                let s = open(&path).map_err(|e| e.to_string())?; // independent handle
                for i in 0..PER_WRITER {
                    s.insert(&sample_record(w, i)).map_err(|e| e.to_string())?;
                }
                Ok(())
            }));
        }

        for h in handles {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => panic!("concurrent insert failed (database locked/busy?): {e}"),
                Err(_) => panic!("writer thread panicked"),
            }
        }

        // Every row must have landed and the hash chain must remain intact.
        let s = open(&path).expect("final open");
        let count = count_rows(&s);
        assert_eq!(
            count,
            (WRITERS * PER_WRITER) as i64,
            "row count mismatch (writes were dropped)"
        );

        let res = s.verify().expect("Verify");
        assert!(
            res.intact,
            "hash chain broken after concurrent writes: {res:?}"
        );
    }
}
