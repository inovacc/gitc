// Package runner is gitc's execution core. It resolves the git backend once,
// executes passthrough commands or built-in shortcuts, and writes an
// append-only forensic audit record for every git invocation it issues.
//
// Audit writes are best-effort: a logging failure is reported to stderr but
// never blocks or fails the underlying git command (availability over audit
// completeness, per the design).
package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/enrich"
	"github.com/inovacc/gitc/internal/gitargs"
	"github.com/inovacc/gitc/internal/redact"
	"github.com/inovacc/gitc/internal/shortcut"
	"github.com/inovacc/gitc/internal/store"
)

// envCaptureExact and envCapturePrefix define which environment variables are
// recorded. Values are credential-masked (redact.String) before storage, since
// GIT_-prefixed vars — notably GIT_CONFIG_PARAMETERS — can carry an Authorization
// header or a URL with userinfo that must not persist raw in the audit DB.
var (
	envCaptureExact  = []string{"SSH_AUTH_SOCK", "PATH"}
	envCapturePrefix = []string{"GIT_"}
)

// GateFunc decides whether an about-to-run git arg vector is permitted. It
// returns (exitCode, true) to BLOCK the command — git is never run — or
// (_, false) to allow it. It is the single enforcement choke point: every git
// vector the runner executes (passthrough AND each shortcut step) passes through
// it, so a built-in shortcut cannot bypass the machine/org policy.
type GateFunc func(ctx context.Context, args []string) (code int, blocked bool)

// Runner executes git work against a resolved backend and audits it.
type Runner struct {
	backend  backend.Backend
	store    *store.Store // may be nil if the audit DB failed to open
	enricher enrich.Enricher
	warn     io.Writer
	gate     GateFunc // nil means unguarded

	osUser     string
	identity   string
	policyPath string // resolved enforcement policy path, recorded per audit row
}

// New builds a Runner. A nil store disables auditing (with a stderr warning per
// invocation); resolution and exec still proceed so git stays usable.
func New(b backend.Backend, s *store.Store, e enrich.Enricher, warn io.Writer) *Runner {
	if warn == nil {
		warn = os.Stderr
	}

	if e == nil {
		e = enrich.Noop()
	}

	r := &Runner{backend: b, store: s, enricher: e, warn: warn}
	if u, err := user.Current(); err == nil {
		r.osUser = u.Username
		r.identity = u.Name
	}

	return r
}

// Guard installs the enforcement gate run before every git vector — passthrough
// and each shortcut step alike. Without it the runner executes unguarded. This
// is what makes the machine/org policy non-bypassable via built-in shortcuts.
func (r *Runner) Guard(g GateFunc) { r.gate = g }

// SetPolicyPath records the resolved enforcement policy path (empty when no
// policy is in effect) so every audited row shows which policy governed it —
// making a policy relocation forensically visible (SEC-2).
func (r *Runner) SetPolicyPath(p string) { r.policyPath = p }

// Passthrough forwards args verbatim to the backend and audits the call.
// It returns the backend exit code.
func (r *Runner) Passthrough(ctx context.Context, args []string) int {
	return r.execAndAudit(ctx, args, "passthrough", "")
}

// Shortcut runs a built-in shortcut: it logs the shortcut invocation itself,
// then runs each underlying git step (each independently audited as
// passthrough). Execution stops at the first non-zero step.
func (r *Runner) Shortcut(ctx context.Context, sc shortcut.Shortcut, args []string) int {
	if len(args) < sc.MinArgs {
		usage := sc.Usage
		if usage == "" {
			usage = sc.Name
		}

		fmt.Fprintf(r.warn, "gitc: usage: gitc %s\n", usage)

		return 2
	}

	start := time.Now()
	last := 0

	steps := sc.Steps(args)
	for _, step := range steps {
		last = r.execAndAudit(ctx, step, "passthrough", "")
		if last != 0 {
			break
		}
	}

	// Record the shortcut invocation itself for full traceability, distinct
	// from the individual underlying git steps.
	rec := r.baseRecord(append([]string{sc.Name}, args...), "shortcut", sc.Name)
	rec.TS = start
	rec.ExitCode = last
	rec.Duration = time.Since(start)
	r.writeAudit(rec)

	return last
}

// execAndAudit runs one git arg vector and writes one audit row. The enforcement
// gate (if installed) runs first: a blocked vector never reaches git, but the
// refused attempt IS recorded (mode "blocked") so a forensic trail exists.
func (r *Runner) execAndAudit(ctx context.Context, args []string, mode, shortcutName string) int {
	if r.gate != nil {
		if code, blocked := r.gate(ctx, args); blocked {
			r.auditBlocked(args, code)
			return code
		}
	}

	rec := r.baseRecord(args, mode, shortcutName)
	rec.TS = time.Now()

	res, err := r.backend.Run(ctx, args)
	if err != nil {
		fmt.Fprintf(r.warn, "gitc: %v\n", err)
	}

	// Help/usage/version invocations touch no repository state; run them but do
	// not record them, so the audit log stays a log of real git operations.
	if !auditable(args) {
		return res.ExitCode
	}

	rec.ExitCode = res.ExitCode
	rec.Duration = res.Duration

	if blob, eerr := r.enricher.Enrich(ctx, rec.Cwd); eerr != nil {
		// Enrichment is best-effort — a failure never blocks the git command, but
		// silently dropping it hides a misconfigured enricher. Surface it on the
		// warn stream (the exec enricher itself degrades to a nil error).
		fmt.Fprintf(r.warn, "gitc: enrichment skipped: %v\n", eerr)
	} else {
		rec.Enrichment = blob
	}

	r.writeAudit(rec)

	return res.ExitCode
}

// auditBlocked records a policy-refused invocation (mode "blocked") so a
// blocked exfil or secret-gated attempt leaves a tamper-evident trace even
// though git never ran. Argv is credential-masked like any other row; help and
// version are never gated so the auditable filter is a defensive no-op.
func (r *Runner) auditBlocked(args []string, code int) {
	if !auditable(args) {
		return
	}

	rec := r.baseRecord(args, "blocked", "")
	rec.TS = time.Now()
	rec.ExitCode = code

	r.writeAudit(rec)
}

// auditable reports whether an argv represents a real git operation worth
// recording. Bare usage, help (help/-h/--help), and version queries are not.
func auditable(args []string) bool {
	if len(args) == 0 {
		return false
	}

	for _, a := range args {
		if a == "--help" || a == "-h" || a == "--version" {
			return false
		}
	}

	idx := gitargs.SubcommandIndex(args)
	if idx < 0 {
		return false
	}

	switch args[idx] {
	case "help", "version":
		return false
	default:
		return true
	}
}

func (r *Runner) baseRecord(args []string, mode, shortcutName string) store.Record {
	cwd, _ := os.Getwd()

	return store.Record{
		OSUser:   r.osUser,
		Identity: r.identity,
		Cwd:      cwd,
		// Store a credential-masked copy of argv (the backend still runs the
		// real args); a token in a clone URL must not persist in the audit DB.
		Argv:        redact.Args(args),
		EnvSubset:   captureEnv(),
		Backend:     string(r.backend.Kind),
		BackendPath: r.backend.Path,
		Mode:        mode,
		Shortcut:    shortcutName,
		PolicyPath:  r.policyPath,
	}
}

func (r *Runner) writeAudit(rec store.Record) {
	if r.store == nil {
		fmt.Fprintln(r.warn, "gitc: audit log unavailable; invocation not recorded")
		return
	}

	if err := r.store.Insert(rec); err != nil {
		fmt.Fprintf(r.warn, "gitc: audit write failed: %v\n", err)
	}
}

// captureEnv returns the git-relevant environment subset with credential-masked
// values (URL userinfo and Authorization tokens stripped).
func captureEnv() map[string]string {
	out := make(map[string]string)

	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}

		key, val := kv[:eq], kv[eq+1:]
		if matchEnv(key) {
			out[key] = redact.String(val)
		}
	}

	return out
}

func matchEnv(key string) bool {
	for _, exact := range envCaptureExact {
		if key == exact {
			return true
		}
	}

	for _, prefix := range envCapturePrefix {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}

	return false
}
