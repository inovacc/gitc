// Package shortcut defines gitc's built-in convenience commands. Each shortcut
// is a thin composition of real git argument vectors — it never reimplements
// git logic — so every underlying git call it issues is executed through the
// same audited backend as passthrough commands.
package shortcut

// Shortcut is a named sequence of git argument vectors run in order. Steps stop
// at the first non-zero exit (see runner in the cmd package).
type Shortcut struct {
	Name  string
	Short string
	// Steps returns the ordered git arg vectors for the given user args.
	Steps func(args []string) [][]string
	// MinArgs is the minimum number of positional args required.
	MinArgs int
	// Usage documents required args, shown on misuse.
	Usage string
}

// All returns the starter shortcut set. It is intentionally small and
// extensible later via user config.
func All() []Shortcut {
	return []Shortcut{
		{
			Name:  "sync",
			Short: "Fetch, rebase onto the upstream tracking branch, then push",
			Steps: func([]string) [][]string {
				return [][]string{
					{"fetch", "--prune"},
					{"rebase"},
					{"push"},
				}
			},
		},
		{
			Name:  "undo",
			Short: "Soft-reset the last commit, keeping its changes staged",
			Steps: func([]string) [][]string {
				return [][]string{
					{"reset", "--soft", "HEAD~1"},
				}
			},
		},
		{
			Name:  "log-graph",
			Short: "Show a decorated commit graph across all refs",
			Steps: func(args []string) [][]string {
				base := []string{"log", "--graph", "--oneline", "--decorate", "--all"}
				return [][]string{append(base, args...)}
			},
		},
		{
			Name:    "quick-commit",
			Short:   "Stage all changes and commit with a message",
			MinArgs: 1,
			Usage:   "quick-commit <message>",
			Steps: func(args []string) [][]string {
				msg := ""
				if len(args) > 0 {
					msg = args[0]
				}

				return [][]string{
					{"add", "-A"},
					{"commit", "-m", msg},
				}
			},
		},
	}
}
