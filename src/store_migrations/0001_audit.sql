-- gitc forensic audit log schema.
--
-- Append-only: gitc issues INSERTs only. No UPDATE/DELETE path exists in the
-- CLI itself, preserving forensic integrity. Fields are logged raw and
-- unredacted by explicit design decision; protect the DB file with
-- owner-only filesystem permissions.

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,           -- RFC3339 UTC invocation start
    os_user      TEXT    NOT NULL,           -- OS username
    identity     TEXT,                       -- resolved identity, if available
    cwd          TEXT    NOT NULL,           -- working directory
    argv         TEXT    NOT NULL,           -- JSON array of raw argv (unredacted)
    env_subset   TEXT    NOT NULL,           -- JSON object of captured env vars (raw values)
    backend      TEXT    NOT NULL,           -- 'vendored' | 'system'
    backend_path TEXT    NOT NULL,           -- resolved absolute backend binary path
    mode         TEXT    NOT NULL,           -- 'passthrough' | 'shortcut'
    shortcut     TEXT,                       -- shortcut name when mode='shortcut'
    exit_code    INTEGER NOT NULL,
    duration_ms  INTEGER NOT NULL,           -- wall-clock exec duration
    enrichment   TEXT                        -- optional libgit2 JSON blob, NULL if unavailable
);

CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log (ts);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log (os_user);
CREATE INDEX IF NOT EXISTS idx_audit_mode ON audit_log (mode);
