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

import "github.com/inovacc/gitc/internal/shortcut"

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

// Classify routes args (the arguments after the program name).
func Classify(args []string, shortcuts []shortcut.Shortcut) Decision {
	if len(args) == 0 {
		return Decision{Kind: Passthrough}
	}

	first := args[0]

	// `git gitc ...` forces gitc's namespace (explicit escape + back-compat).
	// Args after the token (Args[0] = the gitc command, empty ⇒ self-info).
	if first == GitcToken {
		return Decision{Kind: Meta, Args: args[1:]}
	}
	// First-class gitc-native commands: `git scan`, `git audit`, ...
	if firstClassMeta[first] {
		return Decision{Kind: Meta, Args: args}
	}
	// Built-in shortcuts.
	for _, sc := range shortcuts {
		if first == sc.Name {
			return Decision{Kind: RunShortcut, Shortcut: sc, Args: args[1:]}
		}
	}
	// Everything else is real git.
	return Decision{Kind: Passthrough, Args: args}
}
