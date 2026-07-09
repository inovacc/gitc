package router

import (
	"testing"

	"github.com/inovacc/gitc/internal/shortcut"
)

func TestClassify(t *testing.T) {
	shortcuts := shortcut.All()

	tests := []struct {
		name     string
		args     []string
		wantKind Kind
		wantSC   string   // expected shortcut name when RunShortcut
		wantArgs []string // expected residual args
	}{
		{"empty is passthrough", nil, Passthrough, "", nil},
		{"status passes through", []string{"status"}, Passthrough, "", []string{"status"}},
		{"real git subcommand version passes through", []string{"version"}, Passthrough, "", []string{"version"}},
		{"help passes through", []string{"help"}, Passthrough, "", []string{"help"}},
		{"commit with flags passes through", []string{"commit", "-m", "x"}, Passthrough, "", []string{"commit", "-m", "x"}},
		{"sync shortcut", []string{"sync"}, RunShortcut, "sync", []string{}},
		{"undo shortcut", []string{"undo"}, RunShortcut, "undo", []string{}},
		{"log-graph shortcut with extra args", []string{"log-graph", "-n", "5"}, RunShortcut, "log-graph", []string{"-n", "5"}},
		{"quick-commit passes message", []string{"quick-commit", "msg"}, RunShortcut, "quick-commit", []string{"msg"}},
		{"meta namespace", []string{"gitc", "audit", "5"}, Meta, "", []string{"audit", "5"}},
		// First-class gitc-native commands.
		{"scan is first-class meta", []string{"scan"}, Meta, "", []string{"scan"}},
		{"scan with path", []string{"scan", "src"}, Meta, "", []string{"scan", "src"}},
		{"scrub is first-class meta", []string{"scrub", "--path", "x"}, Meta, "", []string{"scrub", "--path", "x"}},
		{"audit is first-class meta", []string{"audit", "5"}, Meta, "", []string{"audit", "5"}},
		{"where/install/uninstall first-class", []string{"where"}, Meta, "", []string{"where"}},
		// Collisions with real git pass through, not intercepted.
		{"real git clean passes through", []string{"clean", "-fd"}, Passthrough, "", []string{"clean", "-fd"}},
		{"real git version passes through", []string{"version"}, Passthrough, "", []string{"version"}},
		// gitc token forces the namespace (back-compat) incl. colliding names.
		{"gitc token unwraps scan", []string{"gitc", "scan"}, Meta, "", []string{"scan"}},
		{"gitc token reaches version", []string{"gitc", "version"}, Meta, "", []string{"version"}},
		{"bare gitc is self-info", []string{"gitc"}, Meta, "", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.args, shortcuts)
			if got.Kind != tt.wantKind {
				t.Fatalf("Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if got.Kind == RunShortcut && got.Shortcut.Name != tt.wantSC {
				t.Fatalf("Shortcut = %q, want %q", got.Shortcut.Name, tt.wantSC)
			}
			if !equalArgs(got.Args, tt.wantArgs) {
				t.Fatalf("Args = %#v, want %#v", got.Args, tt.wantArgs)
			}
		})
	}
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
