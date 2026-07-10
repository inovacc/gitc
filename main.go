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
	"strconv"
	"strings"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/cmdtree"
	"github.com/inovacc/gitc/internal/doctor"
	"github.com/inovacc/gitc/internal/enrich"
	"github.com/inovacc/gitc/internal/filterrepo"
	"github.com/inovacc/gitc/internal/installer"
	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/policy"
	"github.com/inovacc/gitc/internal/provision"
	"github.com/inovacc/gitc/internal/router"
	"github.com/inovacc/gitc/internal/runner"
	"github.com/inovacc/gitc/internal/scan"
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

	// A signal-cancelled context so Ctrl-C aborts in-flight work (notably the
	// network downloads in `git update` / `git fetch-git`) instead of being
	// ignored mid-transfer.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
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
		return runAudit(args[1:], st)
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
		return runScrub(ctx, args[1:])
	case "scan":
		return runScan(args[1:])
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

// runAudit renders the audit log: a compact one-line summary by default, or the
// full record with --wide/-w. An optional numeric argument limits the row count.
func runAudit(args []string, st *store.Store) int {
	if st == nil {
		fmt.Fprintln(os.Stderr, "gitc: audit log unavailable")
		return 1
	}

	n := 0
	wide := false
	verify := false
	plain := false

	for _, a := range args {
		switch a {
		case "--wide", "-w":
			wide = true
		case "--verify":
			verify = true
		case "--plain":
			plain = true
		default:
			if v, err := strconv.Atoi(a); err == nil {
				n = v
			}
		}
	}

	if verify {
		return runAuditVerify(st)
	}

	// On a terminal, browse interactively; a pipe/redirect, --plain, or --wide
	// gets the scriptable text render. The TUI loads the most recent rows
	// (default 500) so a big log stays responsive.
	if !wide && !plain && stdoutIsTTY() {
		return runAuditTUI(st, auditLimit(n, 500))
	}

	if err := st.Tail(auditLimit(n, 20), wide, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	return 0
}

// auditLimit returns n when the user gave a positive count, else the default.
func auditLimit(n, def int) int {
	if n > 0 {
		return n
	}

	return def
}

// stdoutIsTTY reports whether stdout is an interactive terminal (not a pipe or
// file), using only the standard library so no isatty dependency is pulled in.
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// runAuditVerify checks the tamper-evident hash chain and reports whether the
// audit log is intact.
func runAuditVerify(st *store.Store) int {
	res, err := st.Verify()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	if res.Intact {
		fmt.Printf("audit chain intact: %d row(s) verified", res.Checked)

		if res.Legacy > 0 {
			fmt.Printf(", %d legacy (pre-hash) row(s)", res.Legacy)
		}

		fmt.Println()

		return 0
	}

	fmt.Fprintf(os.Stderr,
		"audit chain BROKEN at row id %d (%d verified before the break): a row was deleted or edited\n",
		res.BrokenID, res.Checked)

	return 1
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

// scrubFlags holds the parsed `git scrub` options.
type scrubFlags struct {
	paths       []string
	invertPaths bool
	replaceText string
	force       bool
	dryRun      bool
	prune       string
}

// runScrub implements `git scrub` (a.k.a. `git gitc scrub`): a guarded front end
// to the filterrepo history rewriter. It is named scrub, not clean, so it never
// shadows real `git clean`. Without --force it prints the plan and refuses to
// mutate; --dry-run exercises the export+transform pipeline but discards the
// import so the repository is left untouched.
func runScrub(ctx context.Context, args []string) int {
	fl, err := parseScrubFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scrub: %v\n", err)
		return 2
	}

	prune, err := parsePruneMode(fl.prune)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scrub: %v\n", err)
		return 2
	}

	spec := filterrepo.NewPathSpec()
	for _, p := range fl.paths {
		if aerr := spec.AddMatch([]byte(p)); aerr != nil {
			fmt.Fprintf(os.Stderr, "git scrub: %v\n", aerr)
			return 2
		}
	}

	spec.Invert = fl.invertPaths

	var rules *filterrepo.ReplaceRules
	if fl.replaceText != "" {
		rules, err = filterrepo.ParseReplaceText(fl.replaceText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "git scrub: reading --replace-text: %v\n", err)
			return 1
		}
	}

	// Resolve the real git backend so the rewrite never re-enters the gitc shim.
	self, _ := os.Executable()

	b, berr := backend.Resolve(provision.ManagedGitPath(), self)
	if berr != nil {
		fmt.Fprintf(os.Stderr, "git scrub: %v\n", berr)
		return 1
	}

	printScrubPlan(fl)

	if !fl.force && !fl.dryRun {
		fmt.Fprintln(os.Stderr, "\nThis rewrites history irreversibly. Nothing has been changed.")
		fmt.Fprintln(os.Stderr, "Re-run with --dry-run to preview, or --force to apply.")

		return 0
	}

	opts := filterrepo.Options{
		RepoDir:     ".",
		GitBin:      b.Path,
		Paths:       spec,
		ReplaceText: rules,
		Prune:       prune,
		// A dry run must not be blocked by the fresh-clone guard, since it never
		// mutates; --force is still required for a real rewrite.
		Force:  fl.force || fl.dryRun,
		DryRun: fl.dryRun,
	}

	if err := filterrepo.Run(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "git scrub: %v\n", err)
		return 1
	}

	if fl.dryRun {
		fmt.Println("dry run complete; repository unchanged.")
	} else {
		fmt.Println("history rewrite complete; repository repacked.")
	}

	return 0
}

// parseScrubFlags parses the clean subcommand's flags without using the flag
// package so --path can repeat, matching the manual style used elsewhere.
func parseScrubFlags(args []string) (scrubFlags, error) {
	fl := scrubFlags{prune: "auto"}

	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", a)
			}

			i++

			return args[i], nil
		}

		switch a {
		case "--path":
			v, err := next()
			if err != nil {
				return fl, err
			}

			fl.paths = append(fl.paths, v)
		case "--invert-paths":
			fl.invertPaths = true
		case "--replace-text":
			v, err := next()
			if err != nil {
				return fl, err
			}

			fl.replaceText = v
		case "--prune":
			v, err := next()
			if err != nil {
				return fl, err
			}

			fl.prune = v
		case "--force":
			fl.force = true
		case "--dry-run":
			fl.dryRun = true
		default:
			return fl, fmt.Errorf("unknown flag %q", a)
		}
	}

	return fl, nil
}

// parsePruneMode maps the --prune flag to a filterrepo.PruneMode.
func parsePruneMode(s string) (filterrepo.PruneMode, error) {
	switch s {
	case "", "auto":
		return filterrepo.PruneAuto, nil
	case "always":
		return filterrepo.PruneAlways, nil
	case "never":
		return filterrepo.PruneNever, nil
	default:
		return filterrepo.PruneAuto, fmt.Errorf("invalid --prune value %q (want auto|always|never)", s)
	}
}

// printScrubPlan describes what the rewrite would do, to stderr, so the operator
// sees the plan whether or not it is applied.
func printScrubPlan(fl scrubFlags) {
	fmt.Fprintln(os.Stderr, "gitc scrub plan:")

	if len(fl.paths) > 0 {
		verb := "keep only"
		if fl.invertPaths {
			verb = "remove"
		}

		fmt.Fprintf(os.Stderr, "  paths: %s %v\n", verb, fl.paths)
	}

	if fl.replaceText != "" {
		fmt.Fprintf(os.Stderr, "  replace-text: apply rules from %s\n", fl.replaceText)
	}

	if len(fl.paths) == 0 && fl.replaceText == "" {
		fmt.Fprintln(os.Stderr, "  (no --path or --replace-text given: history would be re-exported unchanged)")
	}

	fmt.Fprintf(os.Stderr, "  prune empty commits: %s\n", fl.prune)

	mode := "APPLY (rewrites history, then repacks)"
	if fl.dryRun {
		mode = "dry run (no changes)"
	} else if !fl.force {
		mode = "preview only (pass --force to apply)"
	}

	fmt.Fprintf(os.Stderr, "  mode: %s\n", mode)
}

// runScan implements `git scan [path]`: a detection-only secret scan of
// the working tree using the gitleaks embedded ruleset. It never mutates the
// repository. It prints one redacted line per finding and a summary, exiting 1
// if any secrets are found (so it is usable as a CI gate) and 0 when clean.
func runScan(args []string) int {
	path := "."
	strict := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--audit":
			return runScanAudit()
		case a == "--strict":
			strict = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(os.Stderr, "git scan: unknown flag %q\n", a)
			return 2
		default:
			path = a
		}
	}

	sc, err := scan.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan: %v\n", err)
		return 1
	}

	res, err := sc.ScanDir(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan: %v\n", err)
		return 1
	}

	for _, f := range res.Findings {
		loc := f.File
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
		}

		fmt.Printf("%s\t%s\t%s\n", f.RuleID, loc, scan.Mask(f.Secret))
	}

	reportSkipped(res.Skipped)

	switch {
	case len(res.Findings) > 0:
		fmt.Printf("scan: %d potential secret(s) found in %s\n", len(res.Findings), path)
		return 1
	case strict && len(res.Skipped) > 0:
		fmt.Printf("scan: no secrets found, but %d file(s) could not be read (--strict) in %s\n", len(res.Skipped), path)
		return 1
	default:
		fmt.Printf("scan clean: no secrets found in %s (%d file(s) skipped)\n", path, len(res.Skipped))
		return 0
	}
}

// reportSkipped warns (to stderr) about files the scan could not read, so a
// clean result is never mistaken for a complete one. The list is capped to keep
// output readable.
func reportSkipped(skipped []scan.Skip) {
	if len(skipped) == 0 {
		return
	}

	const maxList = 10

	fmt.Fprintf(os.Stderr, "git scan: %d file(s) could not be read:\n", len(skipped))

	for i, sk := range skipped {
		if i == maxList {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(skipped)-maxList)
			break
		}

		fmt.Fprintf(os.Stderr, "  %s: %s\n", sk.Path, sk.Reason)
	}
}

// runScanAudit implements `git scan --audit`: it scans the captured argv and
// env of every audit-log row for secrets that slipped past write-time redaction,
// printing the row id per finding. Exit 1 if any are found (CI-usable).
func runScanAudit() int {
	st, err := store.Open(provision.AuditDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan --audit: %v\n", err)
		return 1
	}

	defer func() { _ = st.Close() }()

	rows, err := st.RawRows()
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan --audit: %v\n", err)
		return 1
	}

	sc, err := scan.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan --audit: %v\n", err)
		return 1
	}

	found := 0

	for _, row := range rows {
		for _, f := range sc.ScanString(row.Argv + "\n" + row.Env) {
			found++

			fmt.Printf("row %d\t%s\t%s\n", row.ID, f.RuleID, scan.Mask(f.Secret))
		}
	}

	if found == 0 {
		fmt.Printf("scan --audit clean: no secrets in %d audited row(s)\n", len(rows))
		return 0
	}

	fmt.Printf("scan --audit: %d potential secret(s) across %d audited row(s)\n", found, len(rows))

	return 1
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
