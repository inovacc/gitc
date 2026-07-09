// Package gitargs parses the leading portion of a git argument vector. It
// locates the git subcommand token by skipping git's global options (and the
// values of the globals that consume a following argument, e.g. `-C dir`).
//
// The router (to classify an invocation) and the policy layer (to inject
// defaults like the initial branch) both depend on this so they agree on
// exactly which token is "the git subcommand" — without it, `git -c x=y scan`
// is misread as a passthrough of the `-c` flag and gitc's own commands never
// fire.
package gitargs

import "strings"

// valueGlobals are git global options that consume the following argument, so
// the subcommand scanner must skip their value too (e.g. `git -C dir init`).
var valueGlobals = map[string]bool{
	"-C":             true,
	"-c":             true,
	"--git-dir":      true,
	"--work-tree":    true,
	"--namespace":    true,
	"--super-prefix": true,
	"--config-env":   true,
}

// SubcommandIndex returns the index of the git subcommand token in args,
// skipping leading global options and their values. It returns -1 if no
// subcommand is present (empty args, or only global flags).
func SubcommandIndex(args []string) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return i + 1
			}

			return -1
		}

		if strings.HasPrefix(a, "-") {
			if valueGlobals[a] {
				i++ // also skip this flag's value
			}

			continue
		}

		return i
	}

	return -1
}
