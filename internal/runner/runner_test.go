package runner

import (
	"bytes"
	"testing"

	"github.com/inovacc/gitc/internal/backend"
)

func TestAuditable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"status"}, true},
		{[]string{"commit", "-m", "x"}, true},
		{[]string{"-c", "x=y", "push"}, true},
		{[]string{"--help"}, false},
		{[]string{"-h"}, false},
		{[]string{"--version"}, false},
		{[]string{"help", "commit"}, false},
		{[]string{"version"}, false},
		{[]string{"clone", "--help", "url"}, false},
	}

	for _, c := range cases {
		if got := auditable(c.args); got != c.want {
			t.Errorf("auditable(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestBaseRecordRedactsCredentials(t *testing.T) {
	t.Parallel()

	r := New(backend.Backend{Kind: backend.KindSystem, Path: "git"}, nil, nil, &bytes.Buffer{})

	rec := r.baseRecord([]string{"clone", "https://user:s3cr3t@github.com/x.git"}, "passthrough", "")

	if len(rec.Argv) != 2 {
		t.Fatalf("argv = %v", rec.Argv)
	}

	if rec.Argv[1] != "https://user:***@github.com/x.git" {
		t.Errorf("credential not redacted in the audit record: %q", rec.Argv[1])
	}

	if rec.Mode != "passthrough" || rec.Backend != string(backend.KindSystem) {
		t.Errorf("record metadata wrong: mode=%q backend=%q", rec.Mode, rec.Backend)
	}
}

func TestCaptureEnv(t *testing.T) {
	t.Setenv("GIT_AUTHOR_NAME", "alice")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/s")
	t.Setenv("UNRELATED_SECRET", "leak")

	env := captureEnv()

	if env["GIT_AUTHOR_NAME"] != "alice" {
		t.Error("GIT_-prefixed var should be captured")
	}

	if env["SSH_AUTH_SOCK"] != "/tmp/s" {
		t.Error("exact-match var should be captured")
	}

	if _, ok := env["UNRELATED_SECRET"]; ok {
		t.Error("unrelated env var must not be captured")
	}
}
