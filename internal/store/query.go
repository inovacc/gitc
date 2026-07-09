package store

import (
	"encoding/json"
	"fmt"
	"io"
)

// Tail writes the most recent n audit rows to w, oldest first, in a compact
// one-line-per-invocation format. This is a read-only convenience for the
// `gitc gitc audit` meta command; it does not mutate the append-only log.
func (s *Store) Tail(n int, w io.Writer) error {
	if n <= 0 {
		n = 20
	}
	const q = `SELECT ts, os_user, mode, COALESCE(shortcut, ''), exit_code, backend, argv,
        COALESCE(enrichment, '')
        FROM audit_log ORDER BY id DESC LIMIT ?`
	rows, err := s.db.Query(q, n)
	if err != nil {
		return fmt.Errorf("query audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type line struct {
		ts, user, mode, shortcut, backend, argv, enrichment string
		exit                                                int
	}
	var lines []line
	for rows.Next() {
		var l line
		if err := rows.Scan(&l.ts, &l.user, &l.mode, &l.shortcut, &l.exit, &l.backend, &l.argv, &l.enrichment); err != nil {
			return fmt.Errorf("scan audit row: %w", err)
		}
		lines = append(lines, l)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate audit rows: %w", err)
	}

	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		tag := l.mode
		if l.shortcut != "" {
			tag = l.mode + ":" + l.shortcut
		}
		fmt.Fprintf(w, "%s  %-12s  exit=%-3d  %-8s  [%s]  %s%s\n",
			l.ts, l.user, l.exit, l.backend, tag, l.argv, formatEnrichment(l.enrichment))
	}
	return nil
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
