// Package router classifies a gitc invocation into a passthrough git command,
// a built-in shortcut, or a gitc-native command.
//
// gitc IS the git binary: it provides its own commands first-class (e.g.
// `git scan`, `git audit`, `git scrub`) and forwards everything else to the git
// engine. Only gitc-native names are intercepted; names that collide with real
// git subcommands are deliberately NOT taken first-class (real `git version`
// and `git clean` pass through — gitc's equivalents are `git gitc version` and
// `git scrub`). The explicit `git gitc <cmd>` namespace forces gitc's own
// resolution and remains for back-compat.
package router

import (
	"github.com/inovacc/gitc/internal/gitargs"
	"github.com/inovacc/gitc/internal/shortcut"
)

// Kind is the classified invocation type.
type Kind int

const (
	// Passthrough forwards Args verbatim to the git backend.
	Passthrough Kind = iota
	// RunShortcut runs Shortcut with Args (arguments after the shortcut name).
	RunShortcut
	// Meta runs a gitc-native command; Args[0] is the command name.
	Meta
)

// GitcToken forces gitc's own namespace. `git gitc <cmd>` resolves <cmd> against
// gitc's commands — including names that otherwise pass through to git (e.g.
// version). Bare `git gitc` shows gitc self-info.
const GitcToken = "gitc"

// firstClassMeta are gitc-native commands exposed directly as `git <cmd>`.
// Names that collide with real git subcommands (version, clean) are omitted so
// real git keeps them; gitc's equivalents are reachable via the gitc token
// (version) or a non-colliding name (scrub, not clean).
var firstClassMeta = map[string]bool{
	"scan":      true,
	"audit":     true,
	"scrub":     true,
	"install":   true,
	"uninstall": true,
	"where":     true,
	"fetch-git": true,
	"update":    true,
	"doctor":    true,
	"cmdtree":   true,
}

// Decision is the result of classification.
type Decision struct {
	Kind     Kind
	Shortcut shortcut.Shortcut // valid only when Kind == RunShortcut
	Args     []string
}

// Classify routes args (the arguments after the program name). It resolves the
// subcommand past any leading git global flags (via gitargs), so gitc-native
// commands and shortcuts still fire when prefixed, e.g. `git -c x=y scan`.
//
// gitc-native commands and shortcuts are gitc concepts, not git subcommands:
// when routed as Meta/RunShortcut the leading git globals are dropped (they do
// not apply to gitc's own commands). Anything not gitc-native passes through
// verbatim — full args, globals intact — so real git behavior is untouched.
func Classify(args []string, shortcuts []shortcut.Shortcut) Decision {
	if len(args) == 0 {
		return Decision{Kind: Passthrough}
	}

	idx := gitargs.SubcommandIndex(args)
	if idx < 0 {
		// Only global flags, no subcommand: pass through verbatim.
		return Decision{Kind: Passthrough, Args: args}
	}

	sub := args[idx]

	// `git gitc ...` forces gitc's namespace (explicit escape + back-compat).
	// Args after the token (Args[0] = the gitc command, empty ⇒ self-info).
	if sub == GitcToken {
		return Decision{Kind: Meta, Args: args[idx+1:]}
	}
	// First-class gitc-native commands: `git scan`, `git audit`, ...
	if firstClassMeta[sub] {
		return Decision{Kind: Meta, Args: args[idx:]}
	}
	// Built-in shortcuts.
	for _, sc := range shortcuts {
		if sub == sc.Name {
			return Decision{Kind: RunShortcut, Shortcut: sc, Args: args[idx+1:]}
		}
	}
	// Everything else is real git.
	return Decision{Kind: Passthrough, Args: args}
}
