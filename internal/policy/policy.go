// Package policy applies gitc's opinionated defaults to passthrough git
// commands. Currently: new repositories default their initial branch to `main`
// instead of `master`.
//
// Transforms are conservative — they never override an explicit user choice and
// only touch the specific command they target, preserving transparent
// passthrough for everything else.
package policy

import "strings"

// gitValueGlobals are git global options that consume a following argument, so
// the subcommand scanner must skip their value too (e.g. `git -C dir init`).
var gitValueGlobals = map[string]bool{
	"-C":             true,
	"-c":             true,
	"--git-dir":      true,
	"--work-tree":    true,
	"--namespace":    true,
	"--super-prefix": true,
	"--config-env":   true,
}

// subcommandIndex returns the index of the git subcommand token in args,
// skipping leading global options and their values. It returns -1 if no
// subcommand is present.
func subcommandIndex(args []string) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return i + 1
			}
			return -1
		}
		if strings.HasPrefix(a, "-") {
			if gitValueGlobals[a] {
				i++ // also skip this flag's value
			}
			continue
		}
		return i
	}
	return -1
}

// InitNeedsBranch reports whether args is a `git init` invocation with no
// explicit initial-branch choice, and returns the index of the `init` token.
// When ok is false, args should be passed through unchanged.
func InitNeedsBranch(args []string) (initIdx int, ok bool) {
	idx := subcommandIndex(args)
	if idx < 0 || args[idx] != "init" {
		return 0, false
	}
	for _, a := range args[idx+1:] {
		if a == "-b" || a == "--initial-branch" || strings.HasPrefix(a, "--initial-branch=") {
			return 0, false
		}
	}
	return idx, true
}

// InjectInitialBranch returns a copy of args with `--initial-branch=<branch>`
// inserted immediately after the init token at initIdx.
func InjectInitialBranch(args []string, initIdx int, branch string) []string {
	flag := "--initial-branch=" + branch
	out := make([]string, 0, len(args)+1)
	out = append(out, args[:initIdx+1]...)
	out = append(out, flag)
	out = append(out, args[initIdx+1:]...)
	return out
}
