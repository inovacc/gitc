// Package policy applies gitc's opinionated defaults to passthrough git
// commands. Currently: new repositories default their initial branch to `main`
// instead of `master`.
//
// Transforms are conservative — they never override an explicit user choice and
// only touch the specific command they target, preserving transparent
// passthrough for everything else.
package policy

import (
	"strings"

	"github.com/inovacc/gitc/internal/gitargs"
)

// InitNeedsBranch reports whether args is a `git init` invocation with no
// explicit initial-branch choice, and returns the index of the `init` token.
// When ok is false, args should be passed through unchanged.
func InitNeedsBranch(args []string) (initIdx int, ok bool) {
	idx := gitargs.SubcommandIndex(args)
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
