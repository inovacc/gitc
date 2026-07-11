// Command gitc is a git binary: it replaces git on PATH and provides all
// git-related functionality under one tool.
//
// It forwards ordinary git invocations (args, stdin/stdout/stderr, exit code)
// to a git backend while recording an append-only forensic audit trail, and it
// adds its own first-class commands — `git scan` (secret detection),
// `git scrub` (history rewrite), `git audit`, `git where`, `git install`, and
// shortcuts (`git sync`/`undo`/`log-graph`/`quick-commit`). Native names that
// would collide with a real git subcommand are reached via the `git gitc <cmd>`
// namespace instead; everything unrecognized passes through to real git.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/inovacc/gitc/internal/auditcmd"
	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/cmdtree"
	"github.com/inovacc/gitc/internal/doctor"
	"github.com/inovacc/gitc/internal/enrich"
	"github.com/inovacc/gitc/internal/installer"
	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/policy"
	"github.com/inovacc/gitc/internal/provision"
	"github.com/inovacc/gitc/internal/router"
	"github.com/inovacc/gitc/internal/runner"
	"github.com/inovacc/gitc/internal/scancmd"
	"github.com/inovacc/gitc/internal/scrubcmd"
	"github.com/inovacc/gitc/internal/selfupdate"
	"github.com/inovacc/gitc/internal/shortcut"
	"github.com/inovacc/gitc/internal/store"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// When invoked under the name sh/bash (via an installed shim), act as a
	// launcher for the managed backend's shell instead of the git proxy.
	if name := shellName(os.Args[0]); name != "" {
		os.Exit(runShell(name, os.Args[1:]))
	}

	// A signal-cancelled context so Ctrl-C (and SIGTERM, e.g. a supervisor/init
	// stopping a background updater on non-Windows) aborts in-flight work —
	// notably the network downloads in `git update` / `git fetch-git` — instead
	// of being ignored mid-transfer. SIGTERM is inert on Windows.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(run(ctx, os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	cleanShimBackups()

	shortcuts := shortcut.All()
	dec := router.Classify(args, shortcuts)

	// Audit store is best-effort: if it can't open, git still runs (the runner
	// warns per invocation). Meta commands may need it read-only.
	st, err := store.Open(provision.AuditDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: audit log unavailable: %v\n", err)

		st = nil
	}

	defer func() {
		if st != nil {
			_ = st.Close()
		}
	}()

	if dec.Kind == router.Meta {
		return runMeta(ctx, dec.Args, st)
	}

	// On ordinary git usage, surface any pending update notice and lazily kick
	// off a throttled background update check — never blocking this command.
	if os.Getenv("GITC_BACKGROUND") == "" {
		printAndClearNotice()
		maybeSpawnBackgroundUpdate()
	}

	// Passthrough and shortcuts require a resolved backend. Fail fast before
	// any exec if none is available.
	self, _ := os.Executable()

	b, err := provision.ResolveOrProvision(ctx, self, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	r := runner.New(b, st, enrich.NewExec(b.Path), os.Stderr)

	// Enforce the machine/org policy (secret gate, remote allowlist) at the single
	// choke point the runner funnels every git vector through — so built-in
	// shortcuts (which expand to push/commit steps) are gated exactly like
	// passthrough and cannot bypass enforcement. A blocked command never reaches
	// git. The backend path lets the allowlist resolve named/default remotes.
	r.Guard(func(_ context.Context, args []string) (int, bool) {
		return enforceGates(args, b.Path)
	})

	// Record which enforcement policy governed this process on every audit row
	// (SEC-2), so a policy relocation is forensically visible. Resolved once —
	// the machine-dir path is stable for the process.
	if _, policyPath, _ := loadEnforcementPolicy(); policyPath != "" {
		r.SetPolicyPath(policyPath)
	}

	switch dec.Kind {
	case router.RunShortcut:
		return r.Shortcut(ctx, dec.Shortcut, dec.Args)
	default:
		args := dec.Args
		// New repos default to `main`, not `master`, unless the user chose a
		// branch. Only inject when the backend git supports the flag.
		if idx, ok := policy.InitNeedsBranch(args); ok && b.SupportsInitialBranch(ctx) {
			args = policy.InjectInitialBranch(args, idx, "main")
		}

		return r.Passthrough(ctx, args)
	}
}

// runMeta handles gitc's own commands. They are reachable first-class as
// `git <cmd>` (for names that don't collide with real git) and always via the
// explicit `git gitc <cmd>` namespace. Bare `git gitc` prints gitc self-info.
func runMeta(ctx context.Context, args []string, st *store.Store) int { //nolint:funlen // command dispatch switch
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}

	// `git <cmd> --help` shows that command's usage (from the cmdtree catalog)
	// rather than falling through to run it.
	if cmd != "" && cmd != "help" && hasHelpFlag(args[1:]) {
		return cmdtree.Run([]string{"-c", cmd})
	}

	switch cmd {
	case "", "help":
		printSelfInfo()
		printMetaHelp()

		return 0
	case "version":
		fmt.Printf("gitc %s\n", version)
		return 0
	case "where":
		self, _ := os.Executable()

		b, err := backend.Resolve(provision.ManagedGitPath(), self)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
			return 1
		}

		fmt.Printf("backend: %s (%s)\n", b.Path, b.Kind)
		fmt.Printf("audit:   %s\n", provision.AuditDBPath())

		return 0
	case "audit":
		return auditcmd.Run(args[1:], st)
	case "install":
		apply := false

		for _, a := range args[1:] {
			if a == "--apply" {
				apply = true
			}
		}

		res, err := installer.Install(apply)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
			return 1
		}

		fmt.Printf("shim git: %s\n", res.ShimGit)

		if res.BackendPath != "" {
			fmt.Printf("delegates to: %s\n", res.BackendPath)
		} else {
			fmt.Println("git backend: none yet — provisioned on the first git command (Windows) or via `git fetch-git`")
		}

		if res.PathApplied {
			fmt.Println("PATH updated for the current user; restart your shell to activate.")
		} else {
			fmt.Println(res.Instruction)
		}

		return 0
	case "uninstall":
		msg, err := installer.Uninstall()
		if err != nil {
			fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
			return 1
		}

		fmt.Println(msg)

		return 0
	case "scrub":
		return scrubcmd.Run(ctx, args[1:])
	case "scan":
		return scancmd.Run(args[1:])
	case "fetch-git":
		return provision.FetchGit(ctx, args[1:])
	case "update":
		return runUpdate(ctx, args[1:])
	case "doctor":
		return doctor.Run(doctor.Config{
			Version:        version,
			ManagedGitPath: provision.ManagedGitPath(),
			AuditDBPath:    provision.AuditDBPath(),
		}, args[1:])
	case "cmdtree":
		return cmdtree.Run(args[1:])
	case "sh", "bash":
		// `git gitc sh` / `git gitc bash` — launch the managed backend's shell.
		// The installed sh.exe/bash.exe shims reach this same logic by name.
		return runShell(cmd, args[1:])
	case "backend-update":
		return runBackendUpdate(ctx)
	default:
		fmt.Fprintf(os.Stderr, "gitc: unknown command %q\n", cmd)
		printMetaHelp()

		return 2
	}
}

// runUpdate implements `git update`: check the gitc GitHub releases for a newer
// version (--check) or download and replace this binary in place (--apply). With
// no flag it checks and, if an update exists, tells the user to pass --apply.
func runUpdate(ctx context.Context, args []string) int {
	var check, apply bool

	for _, a := range args {
		switch a {
		case "--check":
			check = true
		case "--apply":
			apply = true
		default:
			fmt.Fprintf(os.Stderr, "git update: unknown flag %q\n", a)
			return 2
		}
	}

	info, err := selfupdate.Check(ctx, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git update: %v\n", err)
		return 1
	}

	fmt.Printf("current: %s\nlatest:  %s\n", info.Current, info.Latest)

	if !info.HasUpdate {
		fmt.Println("gitc is up to date.")
		return 0
	}

	fmt.Printf("a newer release is available: %s\n", info.Latest)

	if check || !apply {
		fmt.Println("run `git update --apply` to install it.")
		return 0
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "git update: locate self: %v\n", err)
		return 1
	}

	fmt.Printf("downloading %s...\n", info.Asset.Name)

	if err := selfupdate.Apply(ctx, info.Asset, self); err != nil {
		fmt.Fprintf(os.Stderr, "git update: %v\n", err)
		return 1
	}

	fmt.Printf("updated to %s: %s\n", info.Latest, self)

	return 0
}

// hasHelpFlag reports whether args request help for a meta command.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}

	return false
}

// printSelfInfo shows gitc's identity: version, resolved git backend, audit DB.
func printSelfInfo() {
	fmt.Printf("gitc %s — git wrapper with forensic audit, secret scan, history scrub\n", version)

	self, _ := os.Executable()
	if b, err := backend.Resolve(provision.ManagedGitPath(), self); err == nil {
		fmt.Printf("git backend: %s (%s)\n", b.Path, b.Kind)
	}

	fmt.Printf("audit log:   %s\n", provision.AuditDBPath())
}

// printMetaHelp lists gitc's native commands.
func printMetaHelp() {
	fmt.Fprintln(os.Stderr, "\ngitc commands (each also as `git gitc <cmd>`):")
	fmt.Fprintln(os.Stderr, "  git scan [path]         detect secrets (exit 1 if any found)")
	fmt.Fprintln(os.Stderr, "  git scrub [opts]        rewrite history: purge paths / redact text (--force to apply)")
	fmt.Fprintln(os.Stderr, "  git audit [N] [--wide]  show the last N audited invocations (compact; --wide=full)")
	fmt.Fprintln(os.Stderr, "  git where               show resolved git backend and audit DB path")
	fmt.Fprintln(os.Stderr, "  git doctor              health-check install, backend, PATH shim, audit DB")
	fmt.Fprintln(os.Stderr, "  git update [--check|--apply]     self-update gitc from GitHub releases")
	fmt.Fprintln(os.Stderr, "  git fetch-git [--latest|--list|--busybox]  download a git backend")
	fmt.Fprintln(os.Stderr, "                          (--busybox bundles a shell for git hooks)")
	fmt.Fprintln(os.Stderr, "  git install [--apply]   install the PATH shim (--apply prepends PATH)")
	fmt.Fprintln(os.Stderr, "  git uninstall           remove the PATH shim")
	fmt.Fprintln(os.Stderr, "  git cmdtree [-b|--json] show the full command tree")
	fmt.Fprintln(os.Stderr, "  git gitc sh|bash [args] launch the managed backend's shell (also the sh/bash shims)")
	fmt.Fprintln(os.Stderr, "  git sync|undo|log-graph|quick-commit    built-in shortcuts")
	fmt.Fprintln(os.Stderr, "  git gitc version        print gitc's own version")
}

// cleanShimBackups best-effort removes stale `*.old` binaries left behind by a
// self-update swap: a running .exe cannot delete itself, so the swap renames the
// old binary aside as <name>.old and it is cleared on a later startup (when it
// is no longer the running process). Both the shim dir (the launcher shims) and
// the bin dir (the canonical gitc.exe that `git update` replaces) are swept.
func cleanShimBackups() {
	for _, dir := range []string{paths.ShimDir(), paths.BinDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".old") {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
}
