// Package scancmd implements `git scan`: a detection-only secret scan of the
// working tree (or, with --audit, of the captured argv/env in the audit DB)
// using the embedded gitleaks ruleset. Keeping it out of package main leaves the
// command layer as thin dispatch.
package scancmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/inovacc/gitc/internal/provision"
	"github.com/inovacc/gitc/internal/scan"
	"github.com/inovacc/gitc/internal/store"
)

// Run implements `git scan [path]`: a detection-only secret scan of the working
// tree using the gitleaks embedded ruleset. It never mutates the repository. It
// prints one redacted line per finding and a summary, exiting 1 if any secrets
// are found (so it is usable as a CI gate) and 0 when clean.
func Run(args []string) int {
	path := "."
	strict := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--audit":
			return runScanAudit()
		case a == "--strict":
			strict = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "git scan: unknown flag %q\n", a)
			return 2
		default:
			path = a
		}
	}

	sc, err := scan.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan: %v\n", err)
		return 1
	}

	res, err := sc.ScanDir(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan: %v\n", err)
		return 1
	}

	for _, f := range res.Findings {
		loc := f.File
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
		}

		fmt.Printf("%s\t%s\t%s\n", f.RuleID, loc, scan.Mask(f.Secret))
	}

	reportSkipped(res.Skipped)

	switch {
	case len(res.Findings) > 0:
		fmt.Printf("scan: %d potential secret(s) found in %s\n", len(res.Findings), path)
		return 1
	case strict && len(res.Skipped) > 0:
		fmt.Printf("scan: no secrets found, but %d file(s) could not be read (--strict) in %s\n", len(res.Skipped), path)
		return 1
	default:
		fmt.Printf("scan clean: no secrets found in %s (%d file(s) skipped)\n", path, len(res.Skipped))
		return 0
	}
}

// reportSkipped warns (to stderr) about files the scan could not read, so a
// clean result is never mistaken for a complete one. The list is capped to keep
// output readable.
func reportSkipped(skipped []scan.Skip) {
	if len(skipped) == 0 {
		return
	}

	const maxList = 10

	fmt.Fprintf(os.Stderr, "git scan: %d file(s) could not be read:\n", len(skipped))

	for i, sk := range skipped {
		if i == maxList {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(skipped)-maxList)
			break
		}

		fmt.Fprintf(os.Stderr, "  %s: %s\n", sk.Path, sk.Reason)
	}
}

// runScanAudit implements `git scan --audit`: it scans the captured argv and env
// of every audit-log row for secrets that slipped past write-time redaction,
// printing the row id per finding. Exit 1 if any are found (CI-usable).
func runScanAudit() int {
	st, err := store.Open(provision.AuditDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan --audit: %v\n", err)
		return 1
	}

	defer func() { _ = st.Close() }()

	rows, err := st.RawRows()
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan --audit: %v\n", err)
		return 1
	}

	sc, err := scan.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan --audit: %v\n", err)
		return 1
	}

	found := 0

	for _, row := range rows {
		for _, f := range sc.ScanString(row.Argv + "\n" + row.Env) {
			found++

			fmt.Printf("row %d\t%s\t%s\n", row.ID, f.RuleID, scan.Mask(f.Secret))
		}
	}

	if found == 0 {
		fmt.Printf("scan --audit clean: no secrets in %d audited row(s)\n", len(rows))
		return 0
	}

	fmt.Printf("scan --audit: %d potential secret(s) across %d audited row(s)\n", found, len(rows))

	return 1
}
