// Command gitc is a transparent forensic proxy in front of the real git binary.
//
// It forwards every invocation (args, stdin/stdout/stderr, exit code) to a git
// backend while recording an append-only audit trail of what ran, when, where,
// by whom, and with what result. A small set of built-in shortcuts and a
// `gitc gitc ...` meta namespace round out the tool; both are audited like any
// passthrough command.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/dyammarcano/gitc/internal/backend"
	"github.com/dyammarcano/gitc/internal/enrich"
	"github.com/dyammarcano/gitc/internal/filterrepo"
	"github.com/dyammarcano/gitc/internal/installer"
	"github.com/dyammarcano/gitc/internal/paths"
	"github.com/dyammarcano/gitc/internal/policy"
	"github.com/dyammarcano/gitc/internal/router"
	"github.com/dyammarcano/gitc/internal/runner"
	"github.com/dyammarcano/gitc/internal/shortcut"
	"github.com/dyammarcano/gitc/internal/store"
)

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
	b, err := backend.Resolve(vendoredGitPath(), self)
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

// runMeta handles `gitc gitc <cmd>` tool-specific subcommands.
func runMeta(args []string, st *store.Store) int {
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "version":
		fmt.Printf("gitc %s\n", version)
		return 0
	case "where":
		self, _ := os.Executable()
		b, err := backend.Resolve(vendoredGitPath(), self)
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
	case "clean":
		return runClean(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "gitc meta commands:")
		fmt.Fprintln(os.Stderr, "  gitc gitc version          print gitc version")
		fmt.Fprintln(os.Stderr, "  gitc gitc where            show resolved git backend and audit DB path")
		fmt.Fprintln(os.Stderr, "  gitc gitc audit [N]        show the last N audited invocations (default 20)")
		fmt.Fprintln(os.Stderr, "  gitc gitc install [--apply]  install the PATH shim (--apply prepends PATH)")
		fmt.Fprintln(os.Stderr, "  gitc gitc uninstall        remove the PATH shim")
		fmt.Fprintln(os.Stderr, "  gitc gitc clean [opts]     rewrite history (purge paths / redact text); --force to apply")
		if cmd == "" || cmd == "help" {
			return 0
		}
		return 2
	}
}

// cleanFlags holds the parsed `gitc gitc clean` options.
type cleanFlags struct {
	paths       []string
	invertPaths bool
	replaceText string
	force       bool
	dryRun      bool
	prune       string
}

// runClean implements `gitc gitc clean`: a guarded, audited front end to the
// filterrepo history rewriter. Without --force it prints the plan and refuses to
// mutate; --dry-run exercises the export+transform pipeline but discards the
// import so the repository is left untouched.
func runClean(args []string) int {
	fl, err := parseCleanFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc clean: %v\n", err)
		return 2
	}

	prune, err := parsePruneMode(fl.prune)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc clean: %v\n", err)
		return 2
	}

	spec := filterrepo.NewPathSpec()
	for _, p := range fl.paths {
		if aerr := spec.AddMatch([]byte(p)); aerr != nil {
			fmt.Fprintf(os.Stderr, "gitc gitc clean: %v\n", aerr)
			return 2
		}
	}
	spec.Invert = fl.invertPaths

	var rules *filterrepo.ReplaceRules
	if fl.replaceText != "" {
		rules, err = filterrepo.ParseReplaceText(fl.replaceText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gitc gitc clean: reading --replace-text: %v\n", err)
			return 1
		}
	}

	// Resolve the real git backend so the rewrite never re-enters the gitc shim.
	self, _ := os.Executable()
	b, berr := backend.Resolve(vendoredGitPath(), self)
	if berr != nil {
		fmt.Fprintf(os.Stderr, "gitc gitc clean: %v\n", berr)
		return 1
	}

	printCleanPlan(fl)

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
		fmt.Fprintf(os.Stderr, "gitc gitc clean: %v\n", err)
		return 1
	}

	if fl.dryRun {
		fmt.Println("dry run complete; repository unchanged.")
	} else {
		fmt.Println("history rewrite complete; repository repacked.")
	}
	return 0
}

// parseCleanFlags parses the clean subcommand's flags without using the flag
// package so --path can repeat, matching the manual style used elsewhere.
func parseCleanFlags(args []string) (cleanFlags, error) {
	fl := cleanFlags{prune: "auto"}
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

// printCleanPlan describes what the rewrite would do, to stderr, so the operator
// sees the plan whether or not it is applied.
func printCleanPlan(fl cleanFlags) {
	fmt.Fprintln(os.Stderr, "gitc clean plan:")
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

func auditDBPath() string {
	if v := os.Getenv("GITC_AUDIT_DB"); v != "" {
		return v
	}
	return paths.AuditDBPath()
}

func vendoredGitPath() string {
	if v := os.Getenv("GITC_GIT_BACKEND"); v != "" {
		return v
	}
	return paths.VendoredGitPath()
}
