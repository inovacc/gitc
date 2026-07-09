package store

import (
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
	const q = `SELECT ts, os_user, mode, COALESCE(shortcut, ''), exit_code, backend, argv
        FROM audit_log ORDER BY id DESC LIMIT ?`
	rows, err := s.db.Query(q, n)
	if err != nil {
		return fmt.Errorf("query audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type line struct {
		ts, user, mode, shortcut, backend, argv string
		exit                                    int
	}
	var lines []line
	for rows.Next() {
		var l line
		if err := rows.Scan(&l.ts, &l.user, &l.mode, &l.shortcut, &l.exit, &l.backend, &l.argv); err != nil {
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
		fmt.Fprintf(w, "%s  %-12s  exit=%-3d  %-8s  [%s]  %s\n",
			l.ts, l.user, l.exit, l.backend, tag, l.argv)
	}
	return nil
}
