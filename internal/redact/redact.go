// Package redact masks credentials embedded in git argument vectors before they
// are written to the forensic audit log.
//
// The backend still executes the real, unmodified arguments — only the STORED
// copy is masked — so a password baked into a clone URL or an Authorization
// header does not persist in the audit DB. This is a deliberate, narrow
// exception to gitc's raw-logging default: it strips only unambiguous secrets
// (URL userinfo, Authorization tokens) while preserving everything forensically
// useful (the command, host, path, and remaining flags). Broader redaction of
// the raw record stays out of band by design (see docs/BACKLOG.md).
package redact

import (
	"regexp"
	"strings"
)

const mask = "***"

// urlCred matches a URL scheme followed by userinfo and an '@', e.g.
// "https://user:pass@host" or "https://ghp_token@host".
var urlCred = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)([^/@\s]+)@`)

// authHeader matches an Authorization header value, e.g. "Authorization: Bearer x".
var authHeader = regexp.MustCompile(`(?i)(authorization:\s*[a-z]+\s+)(\S+)`)

// Args returns a copy of args with embedded credentials masked. The input slice
// is not modified.
func Args(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = String(a)
	}

	return out
}

// String masks credentials found anywhere in s.
func String(s string) string {
	s = urlCred.ReplaceAllStringFunc(s, func(m string) string {
		sub := urlCred.FindStringSubmatch(m)
		scheme, userinfo := sub[1], sub[2]

		// user:pass -> keep the username, mask the secret; a single field
		// (typically a token used as the username) is masked whole.
		if i := strings.IndexByte(userinfo, ':'); i >= 0 {
			return scheme + userinfo[:i] + ":" + mask + "@"
		}

		return scheme + mask + "@"
	})

	return authHeader.ReplaceAllString(s, "${1}"+mask)
}
