package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, in, want string
	}{
		{"user:pass url keeps user", "https://alice:s3cr3t@github.com/x.git", "https://alice:***@github.com/x.git"},
		{"token-as-user url masked whole", "https://ghp_ABC123def456@github.com/x.git", "https://***@github.com/x.git"},
		{"ssh-style scheme", "ssh://git:key@host:22/repo", "ssh://git:***@host:22/repo"},
		{"no credentials untouched", "https://github.com/inovacc/gitc.git", "https://github.com/inovacc/gitc.git"},
		{"plain subcommand untouched", "status", "status"},
		{"auth header bearer masks token", "Authorization: Bearer abcdef123", "Authorization: Bearer ***"},
		{"auth header basic masks token", "authorization: Basic dXNlcjpwYXNz", "authorization: Basic ***"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			if got := String(c.in); got != c.want {
				t.Errorf("String(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestArgsMasksAndCopies(t *testing.T) {
	t.Parallel()

	in := []string{"clone", "https://x:tok@github.com/r.git"}
	got := Args(in)

	if got[1] != "https://x:***@github.com/r.git" {
		t.Errorf("Args did not mask url cred: %q", got[1])
	}

	if strings.Contains(strings.Join(got, " "), "tok@") {
		t.Errorf("token leaked through Args: %v", got)
	}

	if in[1] != "https://x:tok@github.com/r.git" {
		t.Errorf("Args must not mutate the input slice, got %q", in[1])
	}
}
