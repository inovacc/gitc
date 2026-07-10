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

func TestRemoteAllowed(t *testing.T) {
	t.Parallel()

	p := Policy{RemoteAllow: RemoteAllowlist{Enabled: true, Hosts: []string{"github.com/inovacc"}}}

	if p.RemoteAllowed("https://github.com/evil/x.git") {
		t.Error("github.com/evil should be blocked")
	}

	if !p.RemoteAllowed("https://github.com/inovacc/gitc.git") {
		t.Error("github.com/inovacc should be allowed")
	}

	if !p.RemoteAllowed("git@github.com:inovacc/gitc.git") {
		t.Error("scp-style inovacc remote should be allowed")
	}

	off := Policy{RemoteAllow: RemoteAllowlist{Enabled: false}}
	if !off.RemoteAllowed("https://anything/x") {
		t.Error("disabled allowlist must permit everything")
	}
}

func TestRemoteRefs(t *testing.T) {
	t.Parallel()

	p := Policy{RemoteAllow: RemoteAllowlist{Enabled: true, Hosts: []string{"github.com"}}}

	// Explicit URL argument.
	if refs, def := p.RemoteRefs([]string{"push", "https://github.com/evil/x.git"}); len(refs) != 1 || def {
		t.Errorf("url push: refs=%v default=%v", refs, def)
	}

	// Named remote → returned as a ref (the caller resolves it to a URL).
	if refs, def := p.RemoteRefs([]string{"push", "origin", "main"}); len(refs) != 1 || refs[0] != "origin" || def {
		t.Errorf("named remote: refs=%v default=%v", refs, def)
	}

	// Bare push → uses the default/implicit remote.
	if refs, def := p.RemoteRefs([]string{"-c", "x=y", "push"}); refs != nil || !def {
		t.Errorf("bare push should use default remote: refs=%v default=%v", refs, def)
	}

	// Non-remote command and disabled allowlist → nothing to check.
	if refs, _ := p.RemoteRefs([]string{"status"}); refs != nil {
		t.Errorf("status is not remote-facing: %v", refs)
	}

	off := Policy{RemoteAllow: RemoteAllowlist{Enabled: false}}
	if refs, def := off.RemoteRefs([]string{"push", "origin"}); refs != nil || def {
		t.Error("disabled allowlist yields no refs")
	}
}

// TestRemoteRefsValueFlagConfusion is the SEC-3/H-28 regression: a value-flag
// before the remote must not shift the detected positional, and any URL-looking
// positional must be vetted — so an exfil remote can't hide behind a flag value.
func TestRemoteRefsValueFlagConfusion(t *testing.T) {
	t.Parallel()

	p := Policy{RemoteAllow: RemoteAllowlist{Enabled: true, Hosts: []string{"github.com"}}}

	contains := func(refs []string, want string) bool {
		for _, r := range refs {
			if r == want {
				return true
			}
		}

		return false
	}

	// `-o opt` consumes "opt"; the real remote URL must still be detected.
	refs, _ := p.RemoteRefs([]string{"push", "-o", "opt", "evil.com:repo", "main"})
	if !contains(refs, "evil.com:repo") {
		t.Errorf("value-flag push: exfil URL not vetted, refs=%v", refs)
	}

	if contains(refs, "opt") {
		t.Errorf("the flag value must not be treated as the remote, refs=%v", refs)
	}

	// The `=` form does not consume the next token; the URL is the positional.
	refs, _ = p.RemoteRefs([]string{"push", "--push-option=x", "evil.com:repo"})
	if !contains(refs, "evil.com:repo") {
		t.Errorf("--flag=value push: exfil URL not vetted, refs=%v", refs)
	}

	// clone: `-b main` value must be skipped so the source URL is the positional.
	refs, _ = p.RemoteRefs([]string{"clone", "-b", "main", "https://evil.example/x", "dir"})
	if !contains(refs, "https://evil.example/x") {
		t.Errorf("clone with value flag: source URL not detected, refs=%v", refs)
	}

	// Plain named push still resolves to the single named remote.
	refs, _ = p.RemoteRefs([]string{"push", "origin", "main"})
	if len(refs) != 1 || refs[0] != "origin" {
		t.Errorf("plain named push regressed: refs=%v", refs)
	}
}

// TestRemoteRefsPlumbingVerbs is the SEC-5/H-31 regression: low-level push
// plumbing (send-pack, http-push) must be vetted by the allowlist too.
func TestRemoteRefsPlumbingVerbs(t *testing.T) {
	t.Parallel()

	p := Policy{RemoteAllow: RemoteAllowlist{Enabled: true, Hosts: []string{"github.com"}}}

	if refs, _ := p.RemoteRefs([]string{"send-pack", "evil.com:repo", "HEAD"}); len(refs) == 0 || refs[0] != "evil.com:repo" {
		t.Errorf("send-pack remote not vetted: %v", refs)
	}

	if refs, _ := p.RemoteRefs([]string{"http-push", "https://evil.example/x", "main"}); len(refs) == 0 || refs[0] != "https://evil.example/x" {
		t.Errorf("http-push URL not vetted: %v", refs)
	}

	// Value flag before the destination must be skipped.
	if refs, _ := p.RemoteRefs([]string{"send-pack", "--receive-pack", "rp", "evil.com:repo", "HEAD"}); len(refs) == 0 || refs[0] != "evil.com:repo" {
		t.Errorf("send-pack value-flag destination not detected: %v", refs)
	}
}

func TestSecretGateMode(t *testing.T) {
	t.Parallel()

	if !(SecretGate{}).Blocks() {
		t.Error("default (empty) mode should block")
	}

	if !(SecretGate{Mode: "block"}).Blocks() {
		t.Error("block mode should block")
	}

	if (SecretGate{Mode: "warn"}).Blocks() {
		t.Error("warn mode should not block")
	}
}
