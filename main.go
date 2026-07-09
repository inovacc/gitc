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
	"github.com/dyammarcano/gitc/internal/installer"
	"github.com/dyammarcano/gitc/internal/paths"
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
		return r.Passthrough(ctx, dec.Args)
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
	default:
		fmt.Fprintln(os.Stderr, "gitc meta commands:")
		fmt.Fprintln(os.Stderr, "  gitc gitc version          print gitc version")
		fmt.Fprintln(os.Stderr, "  gitc gitc where            show resolved git backend and audit DB path")
		fmt.Fprintln(os.Stderr, "  gitc gitc audit [N]        show the last N audited invocations (default 20)")
		fmt.Fprintln(os.Stderr, "  gitc gitc install [--apply]  install the PATH shim (--apply prepends PATH)")
		fmt.Fprintln(os.Stderr, "  gitc gitc uninstall        remove the PATH shim")
		if cmd == "" || cmd == "help" {
			return 0
		}
		return 2
	}
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
