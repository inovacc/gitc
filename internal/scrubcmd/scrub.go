// Package scrubcmd implements `git scrub`: a guarded front end to the filterrepo
// history rewriter (purge paths / redact text across all history). Keeping it out
// of package main leaves the command layer as thin dispatch.
package scrubcmd

import (
	"context"
	"fmt"
	"os"

	"github.com/inovacc/gitc/internal/backend"
	"github.com/inovacc/gitc/internal/filterrepo"
	"github.com/inovacc/gitc/internal/provision"
)

// scrubFlags holds the parsed `git scrub` options.
type scrubFlags struct {
	paths       []string
	invertPaths bool
	replaceText string
	force       bool
	dryRun      bool
	prune       string
}

// Run implements `git scrub` (a.k.a. `git gitc scrub`): a guarded front end to
// the filterrepo history rewriter. It is named scrub, not clean, so it never
// shadows real `git clean`. Without --force it prints the plan and refuses to
// mutate; --dry-run exercises the export+transform pipeline but discards the
// import so the repository is left untouched.
func Run(ctx context.Context, args []string) int {
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

// parseScrubFlags parses the scrub subcommand's flags without using the flag
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
