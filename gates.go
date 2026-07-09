package main

import (
	"fmt"
	"os"

	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/policy"
	"github.com/inovacc/gitc/internal/scan"
)

// enforceGates applies the machine/org policy (policy.json) to a passthrough
// command: it blocks push/fetch/clone to a remote host not on the allowlist, and
// blocks a commit/push when a working-tree secret scan finds anything. It
// returns (exitCode, true) to refuse the command; (0, false) to allow it. A
// broken policy file fails closed.
func enforceGates(args []string) (int, bool) {
	pol, err := policy.LoadPolicy(paths.PolicyPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: policy: %v\n", err)
		return 1, true
	}

	if code, blocked := enforceRemoteAllowlist(pol, args); blocked {
		return code, true
	}

	return enforceSecretGate(pol, args)
}

// enforceRemoteAllowlist blocks a remote-facing command whose URL host/owner is
// not on the approved list.
func enforceRemoteAllowlist(pol policy.Policy, args []string) (int, bool) {
	for _, u := range pol.RemoteURLsToCheck(args) {
		if !pol.RemoteAllowed(u) {
			fmt.Fprintf(os.Stderr, "gitc: BLOCKED by policy: remote %q is not on the allowed list\n", u)
			return 1, true
		}
	}

	return 0, false
}

// enforceSecretGate runs a working-tree secret scan before a gated command
// (commit/push) and refuses when anything is found.
func enforceSecretGate(pol policy.Policy, args []string) (int, bool) {
	if !pol.SecretGateApplies(args) {
		return 0, false
	}

	sc, err := scan.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: secret gate: %v\n", err)
		return 1, true
	}

	res, err := sc.ScanDir(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: secret gate: %v\n", err)
		return 1, true
	}

	if len(res.Findings) == 0 {
		return 0, false
	}

	fmt.Fprintf(os.Stderr, "gitc: BLOCKED by secret gate: %d secret(s) in the working tree:\n", len(res.Findings))

	for _, f := range res.Findings {
		loc := f.File
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
		}

		fmt.Fprintf(os.Stderr, "  %s\t%s\t%s\n", f.RuleID, loc, maskSecret(f.Secret))
	}

	fmt.Fprintln(os.Stderr, "refusing to proceed. Remove or scrub the secret(s), then retry.")

	return 1, true
}
