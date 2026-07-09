package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyMissingIsEmpty(t *testing.T) {
	t.Parallel()

	p, err := LoadPolicy(filepath.Join(t.TempDir(), "policy.json"))
	if err != nil {
		t.Fatalf("missing policy should not error: %v", err)
	}

	if p.SecretGate.Enabled || p.RemoteAllow.Enabled {
		t.Errorf("absent policy must enforce nothing, got %+v", p)
	}
}

func TestLoadPolicyParses(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.json")
	body := `{"version":1,"secretGate":{"enabled":true},"remoteAllowlist":{"enabled":true,"hosts":["github.com/inovacc"]}}`

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	if !p.SecretGate.Enabled || !p.RemoteAllow.Enabled || len(p.RemoteAllow.Hosts) != 1 {
		t.Errorf("policy did not parse: %+v", p)
	}
}

func TestSecretGateApplies(t *testing.T) {
	t.Parallel()

	on := Policy{SecretGate: SecretGate{Enabled: true}}
	if !on.SecretGateApplies([]string{"commit", "-m", "x"}) {
		t.Error("commit should be gated")
	}

	if !on.SecretGateApplies([]string{"-c", "x=y", "push"}) {
		t.Error("push behind a global flag should still be gated")
	}

	if on.SecretGateApplies([]string{"status"}) {
		t.Error("status is not a gated command")
	}

	off := Policy{SecretGate: SecretGate{Enabled: false}}
	if off.SecretGateApplies([]string{"commit"}) {
		t.Error("disabled gate must not apply")
	}
}

func TestRemoteAllowlist(t *testing.T) {
	t.Parallel()

	p := Policy{RemoteAllow: RemoteAllowlist{Enabled: true, Hosts: []string{"github.com/inovacc"}}}

	urls := p.RemoteURLsToCheck([]string{"push", "https://github.com/evil/x.git"})
	if len(urls) != 1 {
		t.Fatalf("expected 1 url to check, got %v", urls)
	}

	if p.RemoteAllowed("https://github.com/evil/x.git") {
		t.Error("github.com/evil should be blocked")
	}

	if !p.RemoteAllowed("https://github.com/inovacc/gitc.git") {
		t.Error("github.com/inovacc should be allowed")
	}

	if !p.RemoteAllowed("git@github.com:inovacc/gitc.git") {
		t.Error("scp-style inovacc remote should be allowed")
	}

	// Disabled allowlist checks nothing and permits everything.
	off := Policy{RemoteAllow: RemoteAllowlist{Enabled: false}}
	if off.RemoteURLsToCheck([]string{"push", "https://x/y"}) != nil || !off.RemoteAllowed("https://anything/x") {
		t.Error("disabled allowlist must be permissive")
	}
}

func TestRemoteURLsToCheckIgnoresNonRemote(t *testing.T) {
	t.Parallel()

	p := Policy{RemoteAllow: RemoteAllowlist{Enabled: true, Hosts: []string{"github.com"}}}

	if got := p.RemoteURLsToCheck([]string{"status"}); got != nil {
		t.Errorf("status has no remote URLs, got %v", got)
	}

	if got := p.RemoteURLsToCheck([]string{"push", "origin", "main"}); got != nil {
		t.Errorf("a named remote is not a URL, got %v", got)
	}
}
