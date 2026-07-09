package router

import (
	"testing"

	"github.com/dyammarcano/gitc/internal/shortcut"
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
