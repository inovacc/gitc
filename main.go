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
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/enrich"
	"github.com/inovacc/gitc/internal/filterrepo"
	"github.com/inovacc/gitc/internal/gitwin"
	"github.com/inovacc/gitc/internal/installer"
	"github.com/inovacc/gitc/internal/paths"
	"github.com/inovacc/gitc/internal/policy"
	"github.com/inovacc/gitc/internal/router"
	"github.com/inovacc/gitc/internal/runner"
	"github.com/inovacc/gitc/internal/scan"
	"github.com/inovacc/gitc/internal/selfupdate"
	"github.com/inovacc/gitc/internal/settings"
	"github.com/inovacc/gitc/internal/shortcut"
	"github.com/inovacc/gitc/internal/store"
	"github.com/inovacc/gitc/internal/uuidv7"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// A signal-cancelled context so Ctrl-C aborts in-flight work (notably the
	// network downloads in `git update` / `git fetch-git`) instead of being
	// ignored mid-transfer.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	os.Exit(run(ctx, os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	shortcuts := shortcut.All()
	dec := router.Classify(args, shortcuts)

	// Audit store is best-effort: if it can't open, git still runs (the runner
	// warns per invocation). Meta commands may need it read-only.
	st, err := store.Open(auditDBPath())
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

	b, err := resolveOrProvision(ctx, self)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	r := runner.New(b, st, enrich.NewExec(b.Path), os.Stderr)

	switch dec.Kind {
	case router.RunShortcut:
		return r.Shortcut(ctx, dec.Shortcut, dec.Args)
	default:
		args := dec.Args
		// Enforce the machine/org policy (secret gate, remote allowlist) before
		// the command runs. A blocked command never reaches git.
		if code, blocked := enforceGates(args); blocked {
			return code
		}
		// New repos default to `main`, not `master`, unless the user chose a
		// branch. Only inject when the backend git supports the flag.
		if idx, ok := policy.InitNeedsBranch(args); ok && b.SupportsInitialBranch(ctx) {
			args = policy.InjectInitialBranch(args, idx, "main")
		}

		return r.Passthrough(ctx, args)
	}
}

// resolveOrProvision resolves the git backend, and on a git-less machine where
// the pinned MinGit is available (Windows) it self-provisions on first run —
// downloading and sha256-verifying the pinned git, activating it, then retrying.
// Other platforms and background children surface ErrNoBackend unchanged (they
// rely on a system git or an explicit `git fetch-git`).
func resolveOrProvision(ctx context.Context, self string) (backend.Backend, error) {
	b, err := backend.Resolve(managedGitPath(), self)
	if err == nil {
		return b, nil
	}

	if !errors.Is(err, backend.ErrNoBackend) || !pinnedAvailable() || os.Getenv("GITC_BACKGROUND") != "" {
		return b, err
	}

	fmt.Fprintf(os.Stderr, "gitc: no git backend found; provisioning pinned git %s (first run)...\n",
		gitwin.Pinned().Version)

	gitExe, perr := installPinnedGit(ctx)
	if perr != nil {
		return backend.Backend{}, fmt.Errorf("%w (auto-provision failed: %v)", err, perr)
	}

	activateBackend(gitExe)

	return backend.Resolve(managedGitPath(), self)
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
		return runCmdtree([]string{"-c", cmd})
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

		b, err := backend.Resolve(managedGitPath(), self)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
			return 1
		}

		fmt.Printf("backend: %s (%s)\n", b.Path, b.Kind)
		fmt.Printf("audit:   %s\n", auditDBPath())

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
		fmt.Printf("delegates to: %s\n", res.BackendPath)

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
		return runFetchGit(ctx, args[1:])
	case "update":
		return runUpdate(ctx, args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "cmdtree":
		return runCmdtree(args[1:])
	case "backend-update":
		return runBackendUpdate(ctx)
	default:
		fmt.Fprintf(os.Stderr, "gitc: unknown command %q\n", cmd)
		printMetaHelp()

		return 2
	}
}

// runFetchGit downloads a git backend (git-for-windows MinGit) into a fresh
// app/<uuid>/ install and activates it via settings.json. By default it uses the
// in-code hash-pinned manifest (gitwin.Pinned); --latest queries the
// git-for-windows releases API for the newest version (no pinned hash); --list
// shows recent releases.
func runFetchGit(ctx context.Context, args []string) int {
	var list, latest, acceptUnverified bool

	for _, a := range args {
		switch a {
		case "--list":
			list = true
		case "--latest":
			latest = true
		case "--i-accept-unverified":
			acceptUnverified = true
		default:
			fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: unknown flag %q\n", a)
			return 2
		}
	}

	switch {
	case list:
		return fetchGitList(ctx)
	case latest:
		return fetchGitLatest(ctx, acceptUnverified)
	default:
		return fetchGitPinned(ctx)
	}
}

// fetchGitList prints the recent git-for-windows release tags.
func fetchGitList(ctx context.Context) int {
	rels, err := gitwin.List(ctx, 10)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	for _, r := range rels {
		fmt.Println(r.Tag)
	}

	return 0
}

// fetchGitLatest downloads the newest git-for-windows release. It is UNPINNED
// (no sha256 to verify against), so it refuses unless the operator opted in with
// --i-accept-unverified.
func fetchGitLatest(ctx context.Context, acceptUnverified bool) int {
	if !acceptUnverified {
		fmt.Fprintln(os.Stderr, "gitc fetch-git --latest downloads an UNPINNED git with no sha256 verification.")
		fmt.Fprintln(os.Stderr, "Prefer `git fetch-git` (in-code hash-pinned + verified).")
		fmt.Fprintln(os.Stderr, "To override and accept an unverified binary, re-run with --i-accept-unverified.")

		return 1
	}

	rel, err := gitwin.Latest(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	base, err := newInstallBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "warning: installing UNVERIFIED git-for-windows %s (%s)\n", rel.Tag, runtime.GOARCH)

	gitExe, err := gitwin.Ensure(ctx, rel, runtime.GOARCH, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	activateBackend(gitExe)
	fmt.Printf("installed (UNVERIFIED, --i-accept-unverified) and activated: %s\n", gitExe)

	return 0
}

// pinnedAvailable reports whether the in-code pinned manifest has a git build
// for this platform (git-for-windows MinGit is Windows-only).
func pinnedAvailable() bool {
	_, ok := gitwin.Pinned().For(runtime.GOOS, runtime.GOARCH)
	return ok
}

// installPinnedGit downloads and sha256-verifies the in-code pinned MinGit into
// a fresh app/<uuid>/ install and returns the git.exe path (not yet activated).
func installPinnedGit(ctx context.Context) (string, error) {
	m := gitwin.Pinned()

	asset, ok := m.For(runtime.GOOS, runtime.GOARCH)
	if !ok {
		return "", fmt.Errorf("no pinned git for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	base, err := newInstallBase()
	if err != nil {
		return "", err
	}

	return m.EnsurePinned(ctx, asset, base)
}

// fetchGitPinned downloads the in-code hash-pinned MinGit (gitwin.Pinned),
// verifies its sha256, installs it under app/<uuid>/, and activates it.
func fetchGitPinned(ctx context.Context) int {
	m := gitwin.Pinned()

	asset, ok := m.For(runtime.GOOS, runtime.GOARCH)
	if !ok {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: no pinned git for %s/%s; try --latest\n",
			runtime.GOOS, runtime.GOARCH)

		return 1
	}

	fmt.Printf("fetching pinned git %s (%s)...\n", m.Version, asset.Name)

	base, err := newInstallBase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	gitExe, err := m.EnsurePinned(ctx, asset, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	activateBackend(gitExe)
	fmt.Printf("installed, sha256-verified and activated: %s\n", gitExe)

	return 0
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

	n := 20
	wide := false
	verify := false

	for _, a := range args {
		switch a {
		case "--wide", "-w":
			wide = true
		case "--verify":
			verify = true
		default:
			if v, err := strconv.Atoi(a); err == nil {
				n = v
			}
		}
	}

	if verify {
		return runAuditVerify(st)
	}

	if err := st.Tail(n, wide, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
		return 1
	}

	return 0
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
	if b, err := backend.Resolve(managedGitPath(), self); err == nil {
		fmt.Printf("git backend: %s (%s)\n", b.Path, b.Kind)
	}

	fmt.Printf("audit log:   %s\n", auditDBPath())
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
	fmt.Fprintln(os.Stderr, "  git fetch-git [--latest|--list]  download a git backend (pinned MinGit by default)")
	fmt.Fprintln(os.Stderr, "  git install [--apply]   install the PATH shim (--apply prepends PATH)")
	fmt.Fprintln(os.Stderr, "  git uninstall           remove the PATH shim")
	fmt.Fprintln(os.Stderr, "  git cmdtree [-b|--json] show the full command tree")
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

	b, berr := backend.Resolve(managedGitPath(), self)
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

		fmt.Printf("%s\t%s\t%s\n", f.RuleID, loc, maskSecret(f.Secret))
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
	st, err := store.Open(auditDBPath())
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

			fmt.Printf("row %d\t%s\t%s\n", row.ID, f.RuleID, maskSecret(f.Secret))
		}
	}

	if found == 0 {
		fmt.Printf("scan --audit clean: no secrets in %d audited row(s)\n", len(rows))
		return 0
	}

	fmt.Printf("scan --audit: %d potential secret(s) across %d audited row(s)\n", found, len(rows))

	return 1
}

// maskSecret returns a redacted snippet of a detected secret so the operator
// can recognize it without the terminal (or CI logs) capturing the plaintext.
func maskSecret(secret string) string {
	if secret == "" {
		return "<redacted>"
	}

	const keep = 4
	if len(secret) <= keep {
		return strings.Repeat("*", len(secret))
	}

	return secret[:keep] + strings.Repeat("*", 6)
}

func auditDBPath() string {
	if v := os.Getenv("GITC_AUDIT_DB"); v != "" {
		return v
	}

	return paths.AuditDBPath()
}

func managedGitPath() string {
	if v := os.Getenv("GITC_GIT_BACKEND"); v != "" {
		return v
	}

	return resolveManagedGit()
}

// resolveManagedGit returns the active managed git.exe recorded in settings.json.
// On first run (or when settings has no active backend) it lazily adopts a legacy
// git\<tag> install by recording it in settings in place — no bulk move of a
// possibly in-use install. Returns "" when no managed git is available.
func resolveManagedGit() string {
	sp := paths.SettingsPath()

	s, err := settings.LoadOrInit(sp)
	if err != nil {
		// Settings unavailable: fall back to the legacy newest-on-disk scan so
		// git still resolves.
		return paths.ManagedGitPath()
	}

	if s.Backend.Active != "" {
		gitExe := filepath.Join(paths.DataDir(), filepath.FromSlash(s.Backend.Active), "cmd", "git.exe")
		if _, statErr := os.Stat(gitExe); statErr == nil {
			return gitExe
		}
	}

	// First run / stale pointer: adopt the legacy install if one exists.
	legacy := paths.ManagedGitPath()
	if legacy == "" {
		return ""
	}

	if rel, relErr := installRel(legacy); relErr == nil {
		s.Backend.Active = rel
		_ = settings.Save(sp, s) // best-effort; resolution already succeeded
	}

	return legacy
}

// installRel returns a git.exe's install root (its <version> dir) relative to
// DataDir, slash-separated as stored in settings.json.
func installRel(gitExe string) (string, error) {
	versionDir := filepath.Dir(filepath.Dir(gitExe)) // .../<version>/cmd/git.exe -> .../<version>

	rel, err := filepath.Rel(paths.DataDir(), versionDir)
	if err != nil {
		return "", err
	}

	return filepath.ToSlash(rel), nil
}

// newInstallBase reserves a fresh UUIDv7-namespaced directory (app/<uuid>) for a
// new managed-git install, so a download never touches the in-use install.
func newInstallBase() (string, error) {
	id, err := uuidv7.New()
	if err != nil {
		return "", fmt.Errorf("generate install id: %w", err)
	}

	return filepath.Join(paths.AppDir(), id), nil
}

// activateBackend records gitExe's install as the active backend in settings.json
// (demoting the prior active to previous) and stamps the backend check time, so
// the next invocation resolves the new install.
func activateBackend(gitExe string) {
	rel, err := installRel(gitExe)
	if err != nil {
		return
	}

	sp := paths.SettingsPath()

	s, err := settings.LoadOrInit(sp)
	if err != nil {
		return
	}

	if s.Backend.Active != rel {
		s.Backend.Previous = s.Backend.Active
		s.Backend.Active = rel
	}

	_ = settings.Save(sp, s)
}
