package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/policy"
	"github.com/inovacc/gitc/internal/scan"
)

// gitQueryTimeout bounds the read-only git queries the allowlist runs to resolve
// named remotes before a command executes.
const gitQueryTimeout = 5 * time.Second

// enforceGates applies the machine/org policy (policy.json) to a passthrough
// command: it blocks push/fetch/clone to a remote host not on the allowlist
// (resolving named remotes via gitPath), and blocks a commit/push when a
// working-tree secret scan finds anything (unless the gate is in warn mode). It
// returns (exitCode, true) to refuse; (0, false) to allow. A broken policy file
// fails closed.
func enforceGates(args []string, gitPath string) (int, bool) {
	pol, err := policy.LoadPolicy(paths.PolicyPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: policy: %v\n", err)
		return 1, true
	}

	if code, blocked := enforceRemoteAllowlist(pol, args, gitPath); blocked {
		return code, true
	}

	return enforceSecretGate(pol, args)
}

// enforceRemoteAllowlist resolves the effective remote URL(s) of a remote-facing
// command — URL args, configured remote names, and the implicit default remote —
// and blocks any whose host/owner is not on the approved list.
func enforceRemoteAllowlist(pol policy.Policy, args []string, gitPath string) (int, bool) {
	refs, usesDefault := pol.RemoteRefs(args)

	var urls []string

	for _, ref := range refs {
		if policy.IsRemoteURL(ref) {
			urls = append(urls, ref)
		} else if u, ok := resolveRemoteURL(gitPath, ref); ok {
			urls = append(urls, u)
		}
		// An unresolvable name is an unknown remote; git itself will error.
	}

	if usesDefault {
		if u, ok := resolveDefaultRemote(gitPath); ok {
			urls = append(urls, u)
		}
	}

	for _, u := range urls {
		if !pol.RemoteAllowed(u) {
			fmt.Fprintf(os.Stderr, "gitc: BLOCKED by policy: remote %q is not on the allowed list\n", u)
			return 1, true
		}
	}

	return 0, false
}

// enforceSecretGate runs a working-tree secret scan before a gated command
// (commit/push) and refuses when anything is found — or, in warn mode, reports
// and proceeds.
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

	fmt.Fprintf(os.Stderr, "gitc: secret gate: %d secret(s) in the working tree:\n", len(res.Findings))

	for _, f := range res.Findings {
		loc := f.File
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
		}

		fmt.Fprintf(os.Stderr, "  %s\t%s\t%s\n", f.RuleID, loc, maskSecret(f.Secret))
	}

	if !pol.SecretGate.Blocks() {
		fmt.Fprintln(os.Stderr, "gitc: secret gate (warn mode): proceeding despite findings.")
		return 0, false
	}

	fmt.Fprintln(os.Stderr, "gitc: BLOCKED — remove or scrub the secret(s), then retry.")

	return 1, true
}

// resolveRemoteURL runs `git remote get-url <name>` and returns the URL.
func resolveRemoteURL(gitPath, name string) (string, bool) {
	return gitQuery(gitPath, "remote", "get-url", name)
}

// resolveDefaultRemote resolves the current branch's push remote to a URL,
// falling back to origin.
func resolveDefaultRemote(gitPath string) (string, bool) {
	ref, ok := gitQuery(gitPath, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{push}")
	if !ok {
		return resolveRemoteURL(gitPath, "origin")
	}

	name := ref
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		name = ref[:i]
	}

	return resolveRemoteURL(gitPath, name)
}

// gitQuery runs a read-only git command against gitPath and returns trimmed
// stdout with a success flag.
func gitQuery(gitPath string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), gitQueryTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, gitPath, args...).Output()
	if err != nil {
		return "", false
	}

	return strings.TrimSpace(string(out)), true
}
