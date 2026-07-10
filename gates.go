package main

import (
	"context"
	"errors"
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
	pol, _, err := loadEnforcementPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: policy: %v\n", err)
		return 1, true
	}

	if code, blocked := enforceRemoteAllowlist(pol, args, gitPath); blocked {
		return code, true
	}

	return enforceSecretGate(pol, args)
}

// loadEnforcementPolicy resolves the machine/org policy, defending against an
// agent relocating it via its user environment (SEC-2/H-27). It reads the
// machine-wide policy first — a location the agent's LOCALAPPDATA/XDG_DATA_HOME
// cannot repoint — then the deprecated per-user path. It returns the resolved
// path for the audit record.
func loadEnforcementPolicy() (policy.Policy, string, error) {
	return resolvePolicy(paths.MachinePolicyPath(), paths.PolicyPath(), paths.EnforceMarkerPath())
}

// resolvePolicy is loadEnforcementPolicy's path-injected core (testable without
// touching the real machine dirs). Order: machine policy, then the deprecated
// per-user policy. If neither exists and the ENFORCE marker is present, it fails
// CLOSED (returns an error) so a missing policy blocks rather than silently
// disabling enforcement.
func resolvePolicy(machinePath, userPath, markerPath string) (policy.Policy, string, error) {
	if fileExists(machinePath) {
		pol, err := policy.LoadPolicy(machinePath)
		return pol, machinePath, err
	}

	if fileExists(userPath) {
		fmt.Fprintf(os.Stderr,
			"gitc: warning: per-user policy.json is deprecated (removal 2026-09-01); move it to %s\n", machinePath)

		pol, err := policy.LoadPolicy(userPath)

		return pol, userPath, err
	}

	if fileExists(markerPath) {
		return policy.Policy{}, "", fmt.Errorf(
			"enforcement required (%s present) but no policy.json found at %s", markerPath, machinePath)
	}

	return policy.Policy{}, "", nil
}

// fileExists reports whether path is an existing regular file.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// enforceRemoteAllowlist resolves the effective remote URL(s) of a remote-facing
// command — URL args, configured remote names, and the implicit default remote —
// and blocks any whose host/owner is not on the approved list.
//
// It fails CLOSED: if a remote that the command WILL contact cannot be resolved
// to a URL because git could not be run to a verdict (timeout, git missing, a
// killed process), the command is blocked rather than allowed unverified. Only a
// git-level rejection (a genuinely unknown remote name, which git itself will
// reject) is allowed to fall through.
func enforceRemoteAllowlist(pol policy.Policy, args []string, gitPath string) (int, bool) {
	refs, usesDefault := pol.RemoteRefs(args)

	var urls []string

	for _, ref := range refs {
		if policy.IsRemoteURL(ref) {
			urls = append(urls, ref)
			continue
		}

		u, err := resolveRemoteURL(gitPath, ref)
		switch {
		case err == nil:
			urls = append(urls, u)
		case isExecFailure(err):
			return blockUnverifiable(fmt.Sprintf("remote %q", ref), err)
		}
		// else: git-level rejection (unknown remote) — git itself will error.
	}

	if usesDefault {
		u, err := resolveDefaultRemote(gitPath)
		switch {
		case err == nil:
			urls = append(urls, u)
		case isExecFailure(err):
			return blockUnverifiable("the default remote", err)
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

// blockUnverifiable reports a fail-closed block for a remote the allowlist could
// not resolve to a URL, and returns the block result.
func blockUnverifiable(what string, err error) (int, bool) {
	fmt.Fprintf(os.Stderr, "gitc: BLOCKED by policy: cannot verify %s against the allowlist: %v\n", what, err)
	return 1, true
}

// isExecFailure reports whether err means git could not be run to a clean verdict
// — a timeout/cancellation, a missing binary, or a killed process — as opposed to
// git running fine and exiting non-zero (e.g. an unknown remote, which is a real
// git verdict). The allowlist fails closed on an exec failure but lets a
// git-level rejection fall through to git.
func isExecFailure(err error) bool {
	if err == nil {
		return false
	}

	var exit *exec.ExitError

	return !errors.As(err, &exit)
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

// resolveRemoteURL runs `git remote get-url <name>` and returns the URL, or an
// error (an unknown name yields a git-level *exec.ExitError; a failed exec yields
// something else — see isExecFailure).
func resolveRemoteURL(gitPath, name string) (string, error) {
	return gitQuery(gitPath, "remote", "get-url", name)
}

// resolveDefaultRemote resolves the current branch's push remote to a URL,
// falling back to origin. An exec failure while probing @{push} propagates (so
// the caller fails closed); a git-level "no upstream" falls back to origin.
func resolveDefaultRemote(gitPath string) (string, error) {
	ref, err := gitQuery(gitPath, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{push}")
	if err != nil {
		if isExecFailure(err) {
			return "", err
		}

		return resolveRemoteURL(gitPath, "origin")
	}

	name := ref
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		name = ref[:i]
	}

	return resolveRemoteURL(gitPath, name)
}

// gitQuery runs a read-only git command against gitPath and returns trimmed
// stdout. It is a package var so tests can stub git resolution. A context
// timeout is surfaced as the context error (not the killed-process ExitError) so
// isExecFailure classifies it as an exec failure and the allowlist fails closed.
var gitQuery = func(gitPath string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitQueryTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, gitPath, args...).Output()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}
