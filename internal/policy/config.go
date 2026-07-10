package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/inovacc/gitc/internal/gitargs"
)

// Policy is the machine/org enforcement policy (policy.json). gitc reads it but
// never lets a git flag override it, so an AI agent flowing through the shim
// cannot disable a gate at the command line. An absent policy file means no
// enforcement — enforcement is strictly opt-in by dropping a policy.json.
type Policy struct {
	Version     int             `json:"version"`
	SecretGate  SecretGate      `json:"secretGate"`
	RemoteAllow RemoteAllowlist `json:"remoteAllowlist"`
}

// SecretGate blocks a gated git command when a working-tree secret scan finds
// anything. Commands defaults to commit + push when empty. Mode "warn" reports
// findings but lets the command proceed; the default (empty / "block") refuses.
type SecretGate struct {
	Enabled  bool     `json:"enabled"`
	Commands []string `json:"commands"`
	Mode     string   `json:"mode"`
}

// Blocks reports whether a finding should refuse the command rather than warn.
func (g SecretGate) Blocks() bool {
	return g.Mode != "warn"
}

// RemoteAllowlist blocks push/fetch/clone to a URL whose host (or host/owner)
// is not listed, preventing exfiltration to unapproved hosts.
type RemoteAllowlist struct {
	Enabled bool     `json:"enabled"`
	Hosts   []string `json:"hosts"`
}

// LoadPolicy reads policy.json. A missing file yields a zero (no-enforcement)
// Policy with a nil error.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Policy{}, nil
	}

	if err != nil {
		return Policy{}, err
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}

	return p, nil
}

// SecretGateApplies reports whether args is a gated command (commit/push by
// default) with the secret gate enabled.
func (p Policy) SecretGateApplies(args []string) bool {
	if !p.SecretGate.Enabled {
		return false
	}

	sub := subcommandOf(args)
	if sub == "" {
		return false
	}

	cmds := p.SecretGate.Commands
	if len(cmds) == 0 {
		cmds = []string{"commit", "push"}
	}

	for _, c := range cmds {
		if c == sub {
			return true
		}
	}

	return false
}

// RemoteRefs returns the remote references a remote-facing command targets — URL
// arguments and configured remote NAMES — for the allowlist to vet, plus whether
// the command relies on an implicit/default remote (a bare `git push`), which the
// caller resolves to the branch's configured remote. Empty when the allowlist is
// disabled or the command is not remote-facing.
func (p Policy) RemoteRefs(args []string) (refs []string, usesDefault bool) {
	if !p.RemoteAllow.Enabled {
		return nil, false
	}

	idx := gitargs.SubcommandIndex(args)
	if idx < 0 {
		return nil, false
	}

	sub := args[idx]
	switch sub {
	case "push", "fetch", "pull", "clone", "remote":
	default:
		return nil, false
	}

	pos := positionals(args[idx+1:])

	switch sub {
	case "clone":
		if len(pos) > 0 {
			return pos[:1], false // the clone source URL
		}

		return nil, false
	case "remote":
		var urls []string

		for _, a := range pos {
			if IsRemoteURL(a) {
				urls = append(urls, a) // e.g. `remote add <name> <url>`
			}
		}

		return urls, false
	default: // push / fetch / pull: the first positional is the remote (name or URL)
		if len(pos) == 0 {
			return nil, true
		}

		return pos[:1], false
	}
}

// IsRemoteURL reports whether s is a network git remote URL (scheme:// or
// scp-style git@host:path) rather than a configured remote name or local path.
func IsRemoteURL(s string) bool {
	return looksLikeRemoteURL(s)
}

// positionals returns the non-flag arguments (drops any token starting with
// '-'); enough to locate the remote positional.
func positionals(args []string) []string {
	var out []string

	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}

	return out
}

// RemoteAllowed reports whether a remote URL's host (or host/owner) is permitted.
func (p Policy) RemoteAllowed(remote string) bool {
	if !p.RemoteAllow.Enabled {
		return true
	}

	host := remoteHostOwner(remote)
	for _, allowed := range p.RemoteAllow.Hosts {
		if host == allowed || strings.HasPrefix(host+"/", allowed+"/") {
			return true
		}
	}

	return false
}

// subcommandOf returns the git subcommand token past any leading global flags.
func subcommandOf(args []string) string {
	idx := gitargs.SubcommandIndex(args)
	if idx < 0 {
		return ""
	}

	return args[idx]
}

// looksLikeRemoteURL reports whether s is a network git remote (scheme://... or
// scp-style git@host:path). Local paths are ignored.
func looksLikeRemoteURL(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}

	at := strings.IndexByte(s, '@')
	colon := strings.IndexByte(s, ':')

	return at >= 0 && colon > at // git@host:owner/repo
}

// remoteHostOwner extracts "host/owner" (or just "host") from a git remote URL,
// for matching against allowlist entries.
func remoteHostOwner(remote string) string {
	s := remote

	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		if at := strings.IndexByte(s, '@'); at >= 0 {
			s = s[at+1:] // strip userinfo
		}
	} else if at := strings.IndexByte(s, '@'); at >= 0 {
		// scp-style git@host:owner/repo -> host/owner/repo
		s = s[at+1:]
		s = strings.Replace(s, ":", "/", 1)
	}

	parts := strings.SplitN(s, "/", 3)
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}

	return parts[0]
}
