// Package auditcmd implements `git audit`: rendering the forensic audit log as a
// compact or wide text table, verifying the tamper-evident hash chain, or
// browsing it interactively (the bubbletea TUI in tui.go). Keeping it out of
// package main leaves the command layer as thin dispatch.
package auditcmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/inovacc/gitc/internal/store"
)

// Run renders the audit log: a compact one-line summary by default, or the full
// record with --wide/-w. An optional numeric argument limits the row count.
func Run(args []string, st *store.Store) int {
	if st == nil {
		fmt.Fprintln(os.Stderr, "gitc: audit log unavailable")
		return 1
	}

	n := 0
	wide := false
	verify := false
	plain := false

	for _, a := range args {
		switch a {
		case "--wide", "-w":
			wide = true
		case "--verify":
			verify = true
		case "--plain":
			plain = true
		default:
			if v, err := strconv.Atoi(a); err == nil {
				n = v
			}
		}
	}

	if verify {
		return runAuditVerify(st)
	}

	// On a terminal, browse interactively; a pipe/redirect, --plain, or --wide
	// gets the scriptable text render. The TUI loads the most recent rows
	// (default 500) so a big log stays responsive.
	if !wide && !plain && stdoutIsTTY() {
		return runAuditTUI(st, auditLimit(n, 500))
	}

	if err := st.Tail(auditLimit(n, 20), wide, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	return 0
}

// auditLimit returns n when the user gave a positive count, else the default.
func auditLimit(n, def int) int {
	if n > 0 {
		return n
	}

	return def
}

// stdoutIsTTY reports whether stdout is an interactive terminal (not a pipe or
// file), using only the standard library so no isatty dependency is pulled in.
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// runAuditVerify checks the tamper-evident hash chain and reports whether the
// audit log is intact.
func runAuditVerify(st *store.Store) int {
	res, err := st.Verify()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	if res.Intact {
		fmt.Printf("audit chain intact: %d row(s) verified", res.Checked)

		if res.Legacy > 0 {
			fmt.Printf(", %d legacy (pre-hash) row(s)", res.Legacy)
		}

		fmt.Println()

		return 0
	}

	fmt.Fprintf(os.Stderr,
		"audit chain BROKEN at row id %d (%d verified before the break): a row was deleted or edited\n",
		res.BrokenID, res.Checked)

	return 1
}
