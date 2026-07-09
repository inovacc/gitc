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
	_ "embed"
	"fmt"
	"os"
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
	"github.com/inovacc/gitc/internal/shortcut"
	"github.com/inovacc/gitc/internal/store"
)

// gitReleaseJSON is the pinned git-for-windows MinGit manifest (URLs + sha256
// per platform), embedded so `gitc gitc fetch-git` can download and verify a
// known-good git without a network query for the version list.
//
//go:embed git_release.json
var gitReleaseJSON []byte

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ctx := context.Background()
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
		return runMeta(dec.Args, st)
	}

	// Passthrough and shortcuts require a resolved backend. Fail fast before
	// any exec if none is available.
	self, _ := os.Executable()

	b, err := backend.Resolve(managedGitPath(), self)
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
func runMeta(args []string, st *store.Store) int { //nolint:funlen // command dispatch switch
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
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
		if st == nil {
			fmt.Fprintln(os.Stderr, "gitc: audit log unavailable")
			return 1
		}

		n := 20

		if len(args) > 1 {
			if v, err := strconv.Atoi(args[1]); err == nil {
				n = v
			}
		}

		if err := st.Tail(n, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "gitc: %v\n", err)
			return 1
		}

		return 0
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
		return runScrub(args[1:])
	case "scan":
		return runScan(args[1:])
	case "fetch-git":
		return runFetchGit(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "gitc: unknown command %q\n", cmd)
		printMetaHelp()

		return 2
	}
}

// runFetchGit downloads a git backend (git-for-windows MinGit) and unpacks it
// into the git cache. By default it uses the embedded, hash-pinned manifest
// (git_release.json); --latest queries the git-for-windows releases API for the
// newest version (no pinned hash); --list shows recent releases.
func runFetchGit(args []string) int {
	var list, latest bool

	for _, a := range args {
		switch a {
		case "--list":
			list = true
		case "--latest":
			latest = true
		default:
			fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: unknown flag %q\n", a)
			return 2
		}
	}

	ctx := context.Background()
	base := paths.GitCacheDir()

	if list {
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

	if latest {
		rel, err := gitwin.Latest(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
			return 1
		}

		fmt.Printf("fetching git-for-windows %s (%s)...\n", rel.Tag, runtime.GOARCH)

		gitExe, err := gitwin.Ensure(ctx, rel, runtime.GOARCH, base)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
			return 1
		}

		fmt.Printf("installed (unverified): %s\n", gitExe)

		return 0
	}

	// Default: the embedded, hash-pinned manifest.
	m, err := gitwin.ParseManifest(gitReleaseJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	asset, ok := m.For(runtime.GOOS, runtime.GOARCH)
	if !ok {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: no pinned git for %s/%s in git_release.json; try --latest\n",
			runtime.GOOS, runtime.GOARCH)

		return 1
	}

	fmt.Printf("fetching pinned git %s (%s)...\n", m.Version, asset.Name)

	gitExe, err := m.EnsurePinned(ctx, asset, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc fetch-git: %v\n", err)
		return 1
	}

	fmt.Printf("installed and sha256-verified: %s\n", gitExe)

	return 0
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
	fmt.Fprintln(os.Stderr, "  git audit [N]           show the last N audited invocations")
	fmt.Fprintln(os.Stderr, "  git where               show resolved git backend and audit DB path")
	fmt.Fprintln(os.Stderr, "  git fetch-git [--latest|--list]  download a git backend (pinned MinGit by default)")
	fmt.Fprintln(os.Stderr, "  git install [--apply]   install the PATH shim (--apply prepends PATH)")
	fmt.Fprintln(os.Stderr, "  git uninstall           remove the PATH shim")
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
func runScrub(args []string) int {
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

	if err := filterrepo.Run(context.Background(), opts); err != nil {
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

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--audit":
			// Scanning captured audit-log argv/env is a planned follow-up
			// (see docs/BACKLOG.md). Working-tree scanning is the priority.
			fmt.Fprintln(os.Stderr, "git scan: --audit is not implemented yet; scanning the working tree")
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

	findings, err := sc.ScanDir(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git scan: %v\n", err)
		return 1
	}

	for _, f := range findings {
		loc := f.File
		if f.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
		}

		fmt.Printf("%s\t%s\t%s\n", f.RuleID, loc, maskSecret(f.Secret))
	}

	if len(findings) == 0 {
		fmt.Printf("scan clean: no secrets found in %s\n", path)
		return 0
	}

	fmt.Printf("scan: %d potential secret(s) found in %s\n", len(findings), path)

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

	return paths.ManagedGitPath()
}
