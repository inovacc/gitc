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

// renderWide prints the full audit record.
func renderWide(w io.Writer, l auditLine) {
	tag := l.mode
	if l.shortcut != "" {
		tag = l.mode + ":" + l.shortcut
	}

	fmt.Fprintf(w, "%s  %-12s  exit=%-3d  %-8s  [%s]  %s%s\n",
		l.ts, l.user, l.exit, l.backend, tag, l.argv, formatEnrichment(l.enrichment))
}

// renderCompact prints a short one-line summary: time, exit, branch, command.
func renderCompact(w io.Writer, l auditLine) {
	fmt.Fprintf(w, "%s  exit=%-2d  %-22s  %s\n",
		shortTime(l.ts), l.exit, shortBranch(l.enrichment), shortArgv(l.argv, 64))
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
