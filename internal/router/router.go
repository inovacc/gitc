// Package router classifies a gitc invocation into a passthrough git command,
// a built-in shortcut, or a gitc meta command.
//
// Transparency rule: only the reserved shortcut names and the single reserved
// namespace token "gitc" are intercepted. Everything else — including real git
// subcommands like status, commit, version, and help — passes straight through
// to the git backend. gitc's own tooling lives under the `gitc gitc ...`
// namespace so it can never shadow a real git subcommand.
package router

import "github.com/dyammarcano/gitc/internal/shortcut"

// Kind is the classified invocation type.
type Kind int

const (
	// Passthrough forwards Args verbatim to the git backend.
	Passthrough Kind = iota
	// RunShortcut runs Shortcut with Args (arguments after the shortcut name).
	RunShortcut
	// Meta runs a gitc meta command; Args holds the tokens after "gitc".
	Meta
)

// MetaToken is the reserved namespace for gitc's own subcommands.
const MetaToken = "gitc"

// Decision is the result of classification.
type Decision struct {
	Kind     Kind
	Shortcut shortcut.Shortcut // valid only when Kind == RunShortcut
	Args     []string
}

// Classify routes args (the arguments after the program name).
func Classify(args []string, shortcuts []shortcut.Shortcut) Decision {
	if len(args) == 0 {
		return Decision{Kind: Passthrough, Args: nil}
	}
	first := args[0]

	if first == MetaToken {
		return Decision{Kind: Meta, Args: args[1:]}
	}
	for _, sc := range shortcuts {
		if first == sc.Name {
			return Decision{Kind: RunShortcut, Shortcut: sc, Args: args[1:]}
		}
	}
	return Decision{Kind: Passthrough, Args: args}
}
