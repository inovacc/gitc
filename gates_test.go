package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/inovacc/gitc/internal/policy"
)

// plantSecretRepo writes a working tree containing a detectable secret — a
// Stripe live-key-formatted token, which the gitleaks default ruleset matches
// reliably without tripping the "test"/"example" allowlist stopwords.
func plantSecretRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	// Assemble the token from split literals so the SOURCE file never contains a
	// contiguous provider-format secret (GitHub push-protection scans file bytes);
	// at runtime the full token is written to the temp file for gitleaks to find.
	body := "stripe_key = sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc\n"

	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

// TestSecretGateBlocksAndWarns (H-15/COV-1) exercises the secret-gate wiring:
// block on a finding, warn-mode proceed, and no-op on a non-gated command.
func TestSecretGateBlocksAndWarns(t *testing.T) {
	dir := plantSecretRepo(t)
	stubGitQuery(t, func(string, ...string) (string, error) { return dir, nil }) // secretScanDir -> dir

	block := policy.Policy{SecretGate: policy.SecretGate{Enabled: true}}
	if code, blocked := enforceSecretGate(block, []string{"commit", "-m", "x"}, "git"); !blocked || code != 1 {
		t.Errorf("secret gate must block a planted secret, got code=%d blocked=%v", code, blocked)
	}

	warn := policy.Policy{SecretGate: policy.SecretGate{Enabled: true, Mode: "warn"}}
	if _, blocked := enforceSecretGate(warn, []string{"commit"}, "git"); blocked {
		t.Error("warn mode must proceed despite findings")
	}

	if _, blocked := enforceSecretGate(block, []string{"status"}, "git"); blocked {
		t.Error("secret gate must not apply to a non-gated command")
	}
}

// TestResolveDefaultRemoteFollowsPush (H-15/COV-4) covers the @{push} -> named
// remote resolution used for a bare `git push`.
func TestResolveDefaultRemoteFollowsPush(t *testing.T) {
	stubGitQuery(t, func(_ string, args ...string) (string, error) {
		switch args[0] {
		case "rev-parse":
			return "upstream/main", nil
		case "remote":
			if args[2] != "upstream" {
				t.Errorf("default remote should resolve @{push}'s remote 'upstream', asked %q", args[2])
			}

			return "https://internal.example/x", nil
		}

		return "", nil
	})

	url, err := resolveDefaultRemote("git")
	if err != nil || url != "https://internal.example/x" {
		t.Errorf("resolveDefaultRemote = %q err=%v", url, err)
	}
}

// TestResolvePolicyMalformedFailsClosed (H-15) confirms a broken policy file
// surfaces an error so enforceGates fails closed.
func TestResolvePolicyMalformedFailsClosed(t *testing.T) {
	dir := t.TempDir()
	machine := filepath.Join(dir, "policy.json")
	writeFile(t, machine, "{ this is not valid json")

	if _, _, err := resolvePolicy(machine, filepath.Join(dir, "u.json"), filepath.Join(dir, "ENFORCE")); err == nil {
		t.Error("a malformed policy must return an error (fail closed), got nil")
	}
}

// writeFile is a test helper that writes data or fails the test.
func writeFile(t *testing.T, path string, data string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestResolvePolicy covers H-27/SEC-2: machine policy wins over the deprecated
// per-user policy, and a missing policy fails CLOSED when the ENFORCE marker is
// present (so an agent redirecting its user dir cannot disable the gate).
func TestResolvePolicy(t *testing.T) {
	dir := t.TempDir()
	machine := filepath.Join(dir, "machine.json")
	user := filepath.Join(dir, "user.json")
	marker := filepath.Join(dir, "ENFORCE")

	const valid = `{"version":1,"remoteAllowlist":{"enabled":true,"hosts":["internal.example"]}}`

	// Machine policy present -> used.
	writeFile(t, machine, valid)

	pol, path, err := resolvePolicy(machine, user, marker)
	if err != nil || path != machine || !pol.RemoteAllow.Enabled {
		t.Fatalf("machine policy should win: path=%q err=%v enabled=%v", path, err, pol.RemoteAllow.Enabled)
	}

	// Only the deprecated per-user policy present -> used as fallback.
	if err := os.Remove(machine); err != nil {
		t.Fatal(err)
	}

	writeFile(t, user, valid)

	_, path, err = resolvePolicy(machine, user, marker)
	if err != nil || path != user {
		t.Fatalf("user policy fallback should be used: path=%q err=%v", path, err)
	}

	// Neither policy, but the ENFORCE marker is present -> fail CLOSED.
	if err := os.Remove(user); err != nil {
		t.Fatal(err)
	}

	writeFile(t, marker, "1")

	if _, _, err := resolvePolicy(machine, user, marker); err == nil {
		t.Fatal("ENFORCE marker with no policy must fail closed (return an error)")
	}

	// Neither policy nor marker -> no enforcement (backwards compatible).
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	pol, path, err = resolvePolicy(machine, user, marker)
	if err != nil || path != "" || pol.RemoteAllow.Enabled {
		t.Fatalf("no policy + no marker must be no-enforcement: path=%q err=%v", path, err)
	}
}

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

// TestRemoteRewriteOverrideBlocked is the SEC-4/H-29 regression: a config
// override that can rewrite the remote at connect time (insteadOf, pushurl) must
// block a remote-facing command, even if the positional remote resolves to an
// allowed URL.
func TestRemoteRewriteOverrideBlocked(t *testing.T) {
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "https://internal.example/team/x", nil // the clean, allowed URL
	})

	pol := allowlistPolicy("internal.example")

	cases := [][]string{
		{"-c", "url.https://127.0.0.1/.insteadOf=https://internal.example/", "push", "origin", "main"},
		{"-c", "remote.origin.pushurl=https://evil.example/x", "push", "origin"},
		{"--config-env", "url.x.insteadOf=EVIL", "push", "origin"},
		{"--config-env=url.x.pushInsteadOf=EVIL", "push", "origin"},
	}

	for _, args := range cases {
		if code, blocked := enforceRemoteAllowlist(pol, args, "git"); !blocked || code != 1 {
			t.Errorf("rewrite override must block: args=%v code=%d blocked=%v", args, code, blocked)
		}
	}
}

// TestBenignConfigNotBlocked confirms an unrelated -c override does not trip the
// rewrite gate (only remote-rewriting keys do).
func TestBenignConfigNotBlocked(t *testing.T) {
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "https://internal.example/team/x", nil
	})

	pol := allowlistPolicy("internal.example")
	if _, blocked := enforceRemoteAllowlist(pol, []string{"-c", "core.pager=less", "push", "origin"}, "git"); blocked {
		t.Error("a benign -c override must not be blocked")
	}
}

// TestRemoteRewriteViaEnv covers the GIT_CONFIG_KEY_* environment vector.
func TestRemoteRewriteViaEnv(t *testing.T) {
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "https://internal.example/team/x", nil
	})

	t.Setenv("GIT_CONFIG_KEY_0", "url.https://evil/.insteadOf")

	pol := allowlistPolicy("internal.example")
	if code, blocked := enforceRemoteAllowlist(pol, []string{"push", "origin"}, "git"); !blocked || code != 1 {
		t.Errorf("GIT_CONFIG_KEY rewrite must block: code=%d blocked=%v", code, blocked)
	}
}

// TestAliasInjection is the SEC-6/H-30 regression: a command-line alias that
// runs a gated verb or a shell command must be detected, while benign aliases
// and unrelated -c overrides are left alone.
func TestAliasInjection(t *testing.T) {
	t.Parallel()

	block := [][]string{
		{"-c", "alias.p=push", "p", "origin"},         // alias -> gated verb
		{"-c", "alias.x=!git push --force", "x"},      // shell alias
		{"-c", "alias.s=send-pack", "s", "evil:repo"}, // alias -> plumbing exfil verb
	}
	for _, a := range block {
		if _, ok := aliasInjection(a); !ok {
			t.Errorf("should block alias injection: %v", a)
		}
	}

	allow := [][]string{
		{"-c", "alias.co=checkout", "co"},   // benign alias, non-gated verb
		{"push", "origin"},                  // no alias at all
		{"-c", "core.pager=less", "status"}, // unrelated -c override
		{"-c", "alias.p=push", "status"},    // alias defined but NOT the invoked subcommand
	}
	for _, a := range allow {
		if key, ok := aliasInjection(a); ok {
			t.Errorf("should NOT block %v (flagged %q)", a, key)
		}
	}
}

// TestSecretScanDirHonorsGlobals is the SEC-7/H-32 regression: the secret gate
// must scan the repo the command targets (`git -C /repo commit`), resolved via
// git with the command's own globals, not the process CWD.
func TestSecretScanDirHonorsGlobals(t *testing.T) {
	var gotArgs []string

	stubGitQuery(t, func(_ string, args ...string) (string, error) {
		gotArgs = args
		return "/resolved/top", nil
	})

	dir := secretScanDir([]string{"-C", "/repo", "commit", "-m", "x"}, "git")
	if dir != "/resolved/top" {
		t.Errorf("scan dir = %q, want the git-resolved toplevel", dir)
	}

	if len(gotArgs) < 4 || gotArgs[0] != "-C" || gotArgs[1] != "/repo" {
		t.Errorf("the -C global must be forwarded to rev-parse: %v", gotArgs)
	}

	if gotArgs[len(gotArgs)-1] != "--show-toplevel" {
		t.Errorf("expected a rev-parse --show-toplevel query, got %v", gotArgs)
	}
}

// TestSecretScanDirFallsBackToCwd: when git cannot resolve a toplevel, scan the
// current directory (prior behavior).
func TestSecretScanDirFallsBackToCwd(t *testing.T) {
	stubGitQuery(t, func(string, ...string) (string, error) {
		return "", context.DeadlineExceeded
	})

	if dir := secretScanDir([]string{"commit"}, "git"); dir != "." {
		t.Errorf("fallback scan dir = %q, want \".\"", dir)
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
