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

	"github.com/dyammarcano/gitc/internal/backend"
	"github.com/dyammarcano/gitc/internal/enrich"
	"github.com/dyammarcano/gitc/internal/shortcut"
	"github.com/dyammarcano/gitc/internal/store"
)

// envCaptureExact and envCapturePrefix define which environment variables are
// recorded. Values are stored raw and unredacted; only the key set is filtered.
var (
	envCaptureExact  = []string{"SSH_AUTH_SOCK", "PATH"}
	envCapturePrefix = []string{"GIT_"}
)

// Runner executes git work against a resolved backend and audits it.
type Runner struct {
	backend  backend.Backend
	store    *store.Store // may be nil if the audit DB failed to open
	enricher enrich.Enricher
	warn     io.Writer

	osUser   string
	identity string
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

// execAndAudit runs one git arg vector and writes one audit row.
func (r *Runner) execAndAudit(ctx context.Context, args []string, mode, shortcutName string) int {
	rec := r.baseRecord(args, mode, shortcutName)
	rec.TS = time.Now()

	res, err := r.backend.Run(ctx, args)
	rec.ExitCode = res.ExitCode
	rec.Duration = res.Duration
	if err != nil {
		fmt.Fprintf(r.warn, "gitc: %v\n", err)
	}

	if blob, eerr := r.enricher.Enrich(ctx, rec.Cwd); eerr == nil {
		rec.Enrichment = blob
	}

	r.writeAudit(rec)
	return res.ExitCode
}

func (r *Runner) baseRecord(args []string, mode, shortcutName string) store.Record {
	cwd, _ := os.Getwd()
	return store.Record{
		OSUser:      r.osUser,
		Identity:    r.identity,
		Cwd:         cwd,
		Argv:        args,
		EnvSubset:   captureEnv(),
		Backend:     string(r.backend.Kind),
		BackendPath: r.backend.Path,
		Mode:        mode,
		Shortcut:    shortcutName,
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

// captureEnv returns the git-relevant environment subset with raw values.
func captureEnv() map[string]string {
	out := make(map[string]string)
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key, val := kv[:eq], kv[eq+1:]
		if matchEnv(key) {
			out[key] = val
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
