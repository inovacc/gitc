package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inovacc/gitc/internal/shortcut"
)

// ASCII tree characters for consistent width across all terminals. Adapted from
// scout's cobra-driven cmdtree; gitc has no cobra tree, so the catalog is built
// from gitc's real command surface (router.firstClassMeta + the gitc token
// namespace + shortcuts + passthrough) rather than walked from a *cobra.Command.
const (
	treeMiddle = "+-- "
	treeLast   = "\\-- "
	treeIndent = "|   "
	treeSpace  = "    "
	maxDescLen = 44
	commentCol = 52
)

// cmdFlag is a single flag on a gitc command.
type cmdFlag struct {
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand,omitempty"`
	Type        string `json:"type"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description"`
}

// cmdNode is one node of gitc's command catalog.
type cmdNode struct {
	Name        string    `json:"name"`
	Usage       string    `json:"usage"`
	Short       string    `json:"short"`
	Long        string    `json:"long,omitempty"`
	Flags       []cmdFlag `json:"flags,omitempty"`
	Subcommands []cmdNode `json:"commands,omitempty"`
}

// gitcTree returns gitc's full command catalog rooted at `git`.
func gitcTree() cmdNode { //nolint:funlen // static command catalog
	scanFlags := []cmdFlag{
		{Name: "audit", Type: "bool", Description: "scan captured audit-log argv/env (planned)"},
		{Name: "strict", Type: "bool", Description: "exit non-zero if any file could not be read"},
	}
	scrubFlags := []cmdFlag{
		{Name: "path", Type: "string", Description: "path glob to purge (repeatable)"},
		{Name: "invert-paths", Type: "bool", Description: "remove matched paths instead of keeping only them"},
		{Name: "replace-text", Type: "string", Description: "file of redaction rules to apply to blobs"},
		{Name: "prune", Type: "string", Default: "auto", Description: "prune empty commits: auto|always|never"},
		{Name: "dry-run", Type: "bool", Description: "run export+transform but discard the import"},
		{Name: "force", Type: "bool", Description: "apply the rewrite (irreversible)"},
	}
	fetchFlags := []cmdFlag{
		{Name: "latest", Type: "bool", Description: "query git-for-windows for the newest release (unpinned)"},
		{Name: "list", Type: "bool", Description: "list recent git-for-windows releases"},
		{Name: "i-accept-unverified", Type: "bool", Description: "allow --latest despite no sha256 verification"},
	}
	updateFlags := []cmdFlag{
		{Name: "check", Type: "bool", Description: "report whether a newer gitc release exists"},
		{Name: "apply", Type: "bool", Description: "download and replace this binary with the latest"},
	}
	installFlags := []cmdFlag{
		{Name: "apply", Type: "bool", Description: "prepend the shim dir to the user PATH"},
	}

	native := []cmdNode{
		{Name: "scan", Usage: "git scan [path]", Short: "Detect secrets (exit 1 if any found)", Flags: scanFlags},
		{Name: "scrub", Usage: "git scrub [flags]", Short: "Rewrite history: purge paths / redact text", Flags: scrubFlags},
		{
			Name: "audit", Usage: "git audit [N] [--wide]",
			Short: "Show the last N audited invocations (compact; --wide for full)",
			Flags: []cmdFlag{
				{Name: "wide", Shorthand: "w", Type: "bool", Description: "full record instead of the compact summary"},
			},
		},
		{Name: "where", Usage: "git where", Short: "Show resolved git backend and audit DB path"},
		{Name: "doctor", Usage: "git doctor", Short: "Health-check the install, backend, PATH shim, audit DB"},
		{
			Name: "update", Usage: "git update [--check|--apply]",
			Short: "Self-update gitc from GitHub releases", Flags: updateFlags,
		},
		{
			Name: "fetch-git", Usage: "git fetch-git [--latest|--list]",
			Short: "Download a git backend (pinned MinGit)", Flags: fetchFlags,
		},
		{Name: "install", Usage: "git install [--apply]", Short: "Install the PATH shim", Flags: installFlags},
		{Name: "uninstall", Usage: "git uninstall", Short: "Remove the PATH shim"},
		{Name: "cmdtree", Usage: "git cmdtree [-b|-c NAME|--json]", Short: "Display this command tree"},
	}

	var shortcuts []cmdNode

	for _, sc := range shortcut.All() {
		use := "git " + sc.Name
		if sc.Usage != "" {
			use = "git " + sc.Usage
		}

		shortcuts = append(shortcuts, cmdNode{Name: sc.Name, Usage: use, Short: sc.Short})
	}

	return cmdNode{
		Name:  "git",
		Usage: "git <command> [args]",
		Short: "gitc: a git binary with forensic audit, secret scan, history scrub",
		Subcommands: []cmdNode{
			{
				Name: "gitc", Usage: "git gitc <cmd>", Short: "Force gitc's own namespace (also `git <cmd>` directly)",
				Subcommands: append(native, cmdNode{
					Name: "version", Usage: "git gitc version", Short: "Print gitc's own version",
				}),
			},
			{Name: "<shortcuts>", Usage: "git <shortcut>", Short: "Built-in convenience commands", Subcommands: shortcuts},
			{Name: "<git>", Usage: "git <anything else>", Short: "Passthrough to the real git engine (audited)"},
		},
	}
}

// cmdtreeOpts holds parsed `git cmdtree` flags.
type cmdtreeOpts struct {
	brief   bool
	command string
	asJSON  bool
}

// runCmdtree renders gitc's command catalog as a tree (verbose by default).
func runCmdtree(args []string) int {
	opts, err := parseCmdtreeFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git cmdtree: %v\n", err)
		return 2
	}

	root := gitcTree()

	if opts.command != "" {
		node := findNode(&root, opts.command)
		if node == nil {
			fmt.Fprintf(os.Stderr, "git cmdtree: command not found: %s\n", opts.command)
			return 1
		}

		if opts.asJSON {
			return encodeJSON(*node)
		}

		printSingleNode(os.Stdout, *node)

		return 0
	}

	if opts.asJSON {
		return encodeJSON(root)
	}

	var out bytes.Buffer

	out.WriteString(root.Name + "\n")

	if opts.brief {
		printNodes(&out, root.Subcommands, "")
	} else {
		printVerboseNodes(&out, root.Subcommands, "")
	}

	fmt.Print(out.String())

	return 0
}

// parseCmdtreeFlags parses cmdtree's flags in gitc's manual style.
func parseCmdtreeFlags(args []string) (cmdtreeOpts, error) {
	var opts cmdtreeOpts

	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "-b", "--brief":
			opts.brief = true
		case "-v", "--verbose":
			opts.brief = false
		case "--json":
			opts.asJSON = true
		case "-c", "--command":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("%s requires a value", a)
			}

			i++
			opts.command = args[i]
		default:
			return opts, fmt.Errorf("unknown flag %q", a)
		}
	}

	return opts, nil
}

// printNodes renders the compact tree (name + short description).
func printNodes(w io.Writer, nodes []cmdNode, prefix string) {
	for i, n := range nodes {
		isLast := i == len(nodes)-1

		connector := treeMiddle
		if isLast {
			connector = treeLast
		}

		desc := n.Short
		if len(desc) > maxDescLen {
			desc = desc[:maxDescLen-3] + "..."
		}

		cmdPart := prefix + connector + n.Name
		padding := max(commentCol-len(cmdPart), 2)

		_, _ = fmt.Fprintf(w, "%s%s# %s\n", cmdPart, strings.Repeat(" ", padding), desc)

		if len(n.Subcommands) > 0 {
			next := prefix + treeIndent
			if isLast {
				next = prefix + treeSpace
			}

			printNodes(w, n.Subcommands, next)
		}
	}
}

// printVerboseNodes renders the full tree (usage, description, flags).
func printVerboseNodes(w io.Writer, nodes []cmdNode, prefix string) {
	for i, n := range nodes {
		isLast := i == len(nodes)-1

		connector := treeMiddle
		if isLast {
			connector = treeLast
		}

		_, _ = fmt.Fprintf(w, "%s%s%s\n", prefix, connector, n.Name)

		detail := prefix + treeIndent
		if isLast {
			detail = prefix + treeSpace
		}

		if n.Usage != "" {
			_, _ = fmt.Fprintf(w, "%sUsage: %s\n", detail, n.Usage)
		}

		if n.Short != "" {
			_, _ = fmt.Fprintf(w, "%sDescription: %s\n", detail, n.Short)
		}

		if len(n.Flags) > 0 {
			_, _ = fmt.Fprintf(w, "%sFlags:\n", detail)
			for _, f := range n.Flags {
				printFlag(w, detail+"  ", f)
			}
		}

		_, _ = fmt.Fprintf(w, "%s\n", detail)

		if len(n.Subcommands) > 0 {
			printVerboseNodes(w, n.Subcommands, detail)
		}
	}
}

// printSingleNode renders one command's full detail.
func printSingleNode(w io.Writer, n cmdNode) {
	_, _ = fmt.Fprintf(w, "# %s\n\n", n.Name)
	_, _ = fmt.Fprintf(w, "Usage: %s\n\n", n.Usage)

	if n.Short != "" {
		_, _ = fmt.Fprintf(w, "Description: %s\n\n", n.Short)
	}

	if len(n.Flags) > 0 {
		_, _ = io.WriteString(w, "Flags:\n")
		for _, f := range n.Flags {
			printFlag(w, "  ", f)
		}

		_, _ = io.WriteString(w, "\n")
	}

	if len(n.Subcommands) > 0 {
		_, _ = io.WriteString(w, "Subcommands:\n")
		for _, sub := range n.Subcommands {
			_, _ = fmt.Fprintf(w, "  %s - %s\n", sub.Name, sub.Short)
		}
	}
}

// printFlag renders one flag with aligned description.
func printFlag(w io.Writer, prefix string, f cmdFlag) {
	var flagStr string
	if f.Shorthand != "" {
		flagStr = fmt.Sprintf("-%s, --%s", f.Shorthand, f.Name)
	} else {
		flagStr = "    --" + f.Name
	}

	if f.Type != "bool" && f.Type != "" {
		flagStr += " " + f.Type
	}

	padding := max(28-len(flagStr), 2)
	_, _ = fmt.Fprintf(w, "%s%s%s%s\n", prefix, flagStr, strings.Repeat(" ", padding), f.Description)
}

// findNode locates a node by name anywhere in the catalog.
func findNode(root *cmdNode, name string) *cmdNode {
	if root.Name == name {
		return root
	}

	for i := range root.Subcommands {
		if found := findNode(&root.Subcommands[i], name); found != nil {
			return found
		}
	}

	return nil
}

// encodeJSON writes a node as indented JSON to stdout.
func encodeJSON(n cmdNode) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if err := enc.Encode(n); err != nil {
		fmt.Fprintf(os.Stderr, "git cmdtree: json encode: %v\n", err)
		return 1
	}

	return 0
}
