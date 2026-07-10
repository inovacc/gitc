package main

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/inovacc/gitc/internal/policy"
)

// allowlistPolicy builds a policy whose remote allowlist permits only hosts.
func allowlistPolicy(hosts ...string) policy.Policy {
	return policy.Policy{RemoteAllow: policy.RemoteAllowlist{Enabled: true, Hosts: hosts}}
}

// stubGitQuery replaces the package gitQuery seam for the duration of a test.
func stubGitQuery(t *testing.T, f func(gitPath string, args ...string) (string, error)) {
	t.Helper()

	orig := gitQuery
	gitQuery = f

	t.Cleanup(func() { gitQuery = orig })
}

// exitError returns a genuine *exec.ExitError: git ran and exited non-zero (as
// it would for an unknown remote), distinct from an exec/timeout failure.
func exitError(t *testing.T) error {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperExit1") //nolint:gosec // fixed test binary

	cmd.Env = append(os.Environ(), "GITC_HELPER_EXIT1=1")

	err := cmd.Run()
	if err == nil {
		t.Fatal("helper process unexpectedly succeeded; expected a non-zero exit")
	}

	return err
}

// TestHelperExit1 is the subprocess spawned by exitError; it exits non-zero only
// when the sentinel env var is set, so the normal test run is unaffected.
func TestHelperExit1(_ *testing.T) {
	if os.Getenv("GITC_HELPER_EXIT1") == "1" {
		os.Exit(1)
	}
}

// TestRemoteAllowlistFailsClosedOnExecError is the H-26/ERR-1 regression: when a
// git query cannot be run to a verdict (timeout / exec failure), the allowlist
// must BLOCK rather than silently skip the check and let the push through.
func TestRemoteAllowlistFailsClosedOnExecError(t *testing.T) {
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "", context.DeadlineExceeded
	})

	code, blocked := enforceRemoteAllowlist(allowlistPolicy("internal.example"), []string{"push", "origin"}, "git")
	if !blocked || code != 1 {
		t.Fatalf("an exec failure must FAIL CLOSED (block), got code=%d blocked=%v", code, blocked)
	}
}

// TestRemoteAllowlistFallsThroughOnUnknownRemote: a git-level rejection (unknown
// remote, a real *exec.ExitError) is NOT an exec failure — git itself will error,
// so the allowlist lets it through instead of over-blocking.
func TestRemoteAllowlistFallsThroughOnUnknownRemote(t *testing.T) {
	ee := exitError(t)
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "", ee
	})

	_, blocked := enforceRemoteAllowlist(allowlistPolicy("internal.example"), []string{"push", "origin"}, "git")
	if blocked {
		t.Fatal("a git-level unknown-remote rejection should fall through to git, not be blocked")
	}
}

func TestRemoteAllowlistBlocksDisallowedHost(t *testing.T) {
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "https://github.com/evil/x", nil
	})

	code, blocked := enforceRemoteAllowlist(allowlistPolicy("internal.example"), []string{"push", "origin"}, "git")
	if !blocked || code != 1 {
		t.Fatalf("push to a non-allowlisted host must be blocked, got code=%d blocked=%v", code, blocked)
	}
}

func TestRemoteAllowlistAllowsApprovedHost(t *testing.T) {
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "https://internal.example/team/x", nil
	})

	_, blocked := enforceRemoteAllowlist(allowlistPolicy("internal.example"), []string{"push", "origin"}, "git")
	if blocked {
		t.Fatal("push to an allowlisted host must be allowed")
	}
}

func TestIsExecFailure(t *testing.T) {
	if isExecFailure(nil) {
		t.Error("nil is not a failure")
	}

	if !isExecFailure(context.DeadlineExceeded) {
		t.Error("a timeout/context error is an exec failure (fail closed)")
	}

	if isExecFailure(exitError(t)) {
		t.Error("a git-level non-zero exit is NOT an exec failure (git's verdict)")
	}
}
