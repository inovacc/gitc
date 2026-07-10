package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// auditLine is one decoded audit row for rendering.
type auditLine struct {
	ts, user, mode, shortcut, backend, argv, enrichment string
	exit                                                int
}

// Tail writes the most recent n audit rows to w, oldest first. When wide is
// false it prints a compact one-line summary (time, exit, branch, short
// command); when true it prints the full record (user, backend, raw argv, repo
// state). Read-only: it never mutates the append-only log.
func (s *Store) Tail(n int, wide bool, w io.Writer) error {
	if n <= 0 {
		n = 20
	}

	const q = `SELECT ts, os_user, mode, COALESCE(shortcut, ''), exit_code, backend, argv,
        COALESCE(enrichment, '')
        FROM audit_log ORDER BY id DESC LIMIT ?`

	rows, err := s.db.QueryContext(context.Background(), q, n)
	if err != nil {
		return fmt.Errorf("query audit log: %w", err)
	}

	defer func() { _ = rows.Close() }()

	var lines []auditLine

	for rows.Next() {
		var l auditLine
		if err := rows.Scan(&l.ts, &l.user, &l.mode, &l.shortcut, &l.exit, &l.backend, &l.argv, &l.enrichment); err != nil {
			return fmt.Errorf("scan audit row: %w", err)
		}

		lines = append(lines, l)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate audit rows: %w", err)
	}

	for i := len(lines) - 1; i >= 0; i-- {
		if wide {
			renderWide(w, lines[i])
		} else {
			renderCompact(w, lines[i])
		}
	}

	return nil
}

// VerifyResult reports the outcome of an audit hash-chain check.
type VerifyResult struct {
	Checked  int   // hashed rows verified in-chain
	Legacy   int   // pre-AUD-2 rows without a hash (unverifiable)
	Intact   bool  // every hashed row links correctly
	BrokenID int64 // id of the first failing row (0 when intact)
}

// Verify walks the audit hash chain oldest-first and reports the first row whose
// stored hash or previous-link does not recompute — evidence of a deleted or
// edited row. Rows written before AUD-2 carry no hash and are counted, not
// verified.
func (s *Store) Verify() (VerifyResult, error) {
	const q = `SELECT id, ts, os_user, COALESCE(identity,''), cwd, argv, env_subset,
        backend, backend_path, mode, COALESCE(shortcut,''), exit_code, duration_ms,
        COALESCE(enrichment,''), COALESCE(prev_hash,''), COALESCE(row_hash,'')
        FROM audit_log ORDER BY id ASC`

	rows, err := s.db.QueryContext(context.Background(), q)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("query audit log: %w", err)
	}

	defer func() { _ = rows.Close() }()

	res := VerifyResult{Intact: true}
	prev := ""

	for rows.Next() {
		var (
			id                int64
			v                 rowValues
			prevHash, rowHash string
		)

		if err := rows.Scan(&id, &v.ts, &v.osUser, &v.identity, &v.cwd, &v.argv, &v.env,
			&v.backend, &v.backendPath, &v.mode, &v.shortcut, &v.exit, &v.durMs,
			&v.enrichment, &prevHash, &rowHash); err != nil {
			return VerifyResult{}, fmt.Errorf("scan audit row: %w", err)
		}

		if rowHash == "" {
			res.Legacy++
			continue
		}

		if prevHash != prev || rowHash != chainHash(prev, v) {
			res.Intact = false
			res.BrokenID = id

			break
		}

		res.Checked++
		prev = rowHash
	}

	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("iterate audit rows: %w", err)
	}

	return res, nil
}

// RawRow is a stored invocation's raw argv + captured env, for scanning the
// audit log itself for secrets (git scan --audit).
type RawRow struct {
	ID   int64
	Argv string
	Env  string
}

// RawRows returns every row's id, argv, and env_subset.
func (s *Store) RawRows() ([]RawRow, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT id, argv, env_subset FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query audit rows: %w", err)
	}

	defer func() { _ = rows.Close() }()

	var out []RawRow

	for rows.Next() {
		var r RawRow
		if err := rows.Scan(&r.ID, &r.Argv, &r.Env); err != nil {
			return nil, fmt.Errorf("scan audit row: %w", err)
		}

		out = append(out, r)
	}

	return out, rows.Err()
}

// renderWide prints the full audit record.
func renderWide(w io.Writer, l auditLine) {
	tag := l.mode
	if l.shortcut != "" {
		tag = l.mode + ":" + l.shortcut
	}

	fmt.Fprintf(w, "%s  %-12s  exit=%-3d  %-8s  [%s]  %s%s\n",
		l.ts, l.user, l.exit, l.backend, tag, l.argv, formatEnrichment(l.enrichment))
}

// renderCompact prints a short one-line summary: time, status, branch, command.
// A policy-refused row shows BLOCKED rather than an exit code so a blocked
// attempt is not mistaken for a git-level failure.
func renderCompact(w io.Writer, l auditLine) {
	status := fmt.Sprintf("exit=%-2d", l.exit)
	if l.mode == "blocked" {
		status = "BLOCKED"
	}

	fmt.Fprintf(w, "%s  %-8s  %-22s  %s\n",
		shortTime(l.ts), status, shortBranch(l.enrichment), shortArgv(l.argv, 64))
}

// shortTime extracts HH:MM:SS from an RFC3339 timestamp.
func shortTime(ts string) string {
	if i := strings.IndexByte(ts, 'T'); i >= 0 && len(ts) >= i+9 {
		return ts[i+1 : i+9]
	}

	return ts
}

// shortArgv decodes the stored argv JSON into a space-joined command, truncated
// to maxLen runes-ish (byte-bounded) for the compact view.
func shortArgv(argvJSON string, maxLen int) string {
	var argv []string
	if err := json.Unmarshal([]byte(argvJSON), &argv); err != nil {
		return truncate(argvJSON, maxLen)
	}

	return truncate(strings.Join(argv, " "), maxLen)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	if maxLen <= 1 {
		return s[:maxLen]
	}

	return s[:maxLen-1] + "…"
}

// shortBranch pulls the branch name from the enrichment JSON, or "-" if absent.
func shortBranch(enrichment string) string {
	if enrichment == "" {
		return "-"
	}

	var s struct {
		Branch string `json:"branch"`
	}
	if err := json.Unmarshal([]byte(enrichment), &s); err != nil || s.Branch == "" {
		return "-"
	}

	return s.Branch
}

// formatEnrichment renders the stored enrichment JSON into a compact suffix.
// It stays schema-tolerant: any parseable object is summarized; anything else
// is dropped so the audit view never breaks on an unexpected blob.
func formatEnrichment(blob string) string {
	if blob == "" {
		return ""
	}

	var s struct {
		Branch    string `json:"branch"`
		Ahead     int    `json:"ahead"`
		Behind    int    `json:"behind"`
		Staged    int    `json:"staged"`
		Unstaged  int    `json:"unstaged"`
		Untracked int    `json:"untracked"`
		Conflicts int    `json:"conflicts"`
	}
	if err := json.Unmarshal([]byte(blob), &s); err != nil {
		return ""
	}

	return fmt.Sprintf("  {%s +%d/-%d staged=%d unstaged=%d untracked=%d conflicts=%d}",
		s.Branch, s.Ahead, s.Behind, s.Staged, s.Unstaged, s.Untracked, s.Conflicts)
}
